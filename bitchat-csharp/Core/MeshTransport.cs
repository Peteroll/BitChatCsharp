namespace Bitchat.Core;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Bitchat.Protocol;
using Bitchat.Protocol.Models;
using Bitchat.Utils;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Bitchat.Noise;
using Bitchat.Services;
using NSec.Cryptography;
using Bitchat.Nostr;
using Bitchat.NostrInterop;

public interface IMeshTransport
{
    void Send(byte[] data);
    event Action<byte[]>? OnReceive;
}

public sealed class InMemoryMeshTransport : IMeshTransport
{
    private readonly ConcurrentQueue<byte[]> _queue = new();
    public event Action<byte[]>? OnReceive;

    public void Send(byte[] data)
    {
        // 即時回環，模擬 mesh 廣播
        _queue.Enqueue(data);
        if (_queue.TryDequeue(out var d))
            OnReceive?.Invoke(d);
    }
}

public sealed class SimpleRouter : IRouter
{
    private readonly IMeshTransport _transport;
    private readonly HashSet<string> _seen = new();
    private readonly FragmentAssembler _fragments = new();
    private readonly NoiseManager _noise = new();
    private readonly DeliveryTracker _delivery;
    private readonly RateLimiter _forwardLimiter = new(20);
    private readonly KeychainManager _keys = new();
    private readonly (PublicKey pub, Key priv) _signing;
    private readonly IdentityRegistry _ids = new();
    private readonly NostrRelayManager _nostr = new();
    private readonly Nostr.NostrKeyManager _nostrKeys = new();

    public SimpleRouter(IMeshTransport transport)
    {
        _transport = transport;
        _transport.OnReceive += HandleIncoming;
        _delivery = new DeliveryTracker(_transport.Send);
        _signing = _keys.GetOrCreateEd25519("default-signing");

        // Wire Nostr relays (defaults can be adjusted by user later)
        try
        {
            _nostr.OnEvent += HandleNostrEvent;
            _nostr.OnLog += s => Console.WriteLine(s);
            _nostr.AddRelay("wss://relay.damus.io");
            _nostr.AddRelay("wss://nos.lol");
            _ = _nostr.StartAsync();
        }
        catch { }
    }

    public void Broadcast(string senderPeerHex, string content)
    {
        var bm = new Bitchat.Protocol.Models.BitchatMessage(
            id: Guid.NewGuid().ToString("N"),
            sender: senderPeerHex,
            content: content,
            timestamp: DateTime.UtcNow,
            isRelay: false,
            originalSender: null,
            isPrivate: false,
            recipientNickname: null,
            senderPeerId: senderPeerHex,
            mentions: null
        );
        var payload = Bitchat.Protocol.Models.BitchatMessage.ToBinaryPayload(bm);
        var pkt = CreatePacket(MessageType.Message, 5, senderPeerHex, payload);
        SignAndSend(pkt);
    }

    public void PrivateMessage(string senderPeerHex, string targetPeerHex, string content)
    {
        var bm = new Bitchat.Protocol.Models.BitchatMessage(
            id: Guid.NewGuid().ToString("N"),
            sender: senderPeerHex,
            content: content,
            timestamp: DateTime.UtcNow,
            isRelay: false,
            originalSender: null,
            isPrivate: true,
            recipientNickname: null,
            senderPeerId: senderPeerHex,
            mentions: null
        );
        var payload = Bitchat.Protocol.Models.BitchatMessage.ToBinaryPayload(bm);
        var pkt = CreatePacket(MessageType.Message, 5, senderPeerHex, payload, recipient: HexTo8(targetPeerHex));
        SignAndSend(pkt);
    }

    public void PrivateMessageNoise(string senderPeerHex, string targetPeerHex, string content)
    {
        // Build BitchatMessage binary payload (isPrivate=true)
        var bm = new Bitchat.Protocol.Models.BitchatMessage(
            id: Guid.NewGuid().ToString("N"),
            sender: senderPeerHex,
            content: content,
            timestamp: DateTime.UtcNow,
            isRelay: false,
            originalSender: null,
            isPrivate: true,
            recipientNickname: null,
            senderPeerId: senderPeerHex,
            mentions: null
        );
        var pt = Bitchat.Protocol.Models.BitchatMessage.ToBinaryPayload(bm);

        // Ensure session; kick handshake if needed
        var session = _noise.GetOrCreate(targetPeerHex);
        if (!session.IsEstablished)
        {
            var initPayload = session.GetInitPayload();
            var init = CreatePacket(MessageType.NoiseHandshakeInit, 5, senderPeerHex, initPayload, recipient: HexTo8(targetPeerHex));
            SendPacket(init);
        }

        var ct = session.Encrypt(pt, out var nonce, out var tag);
        if (ct == null)
        {
            Console.WriteLine("[Noise] Session not established; PM dropped");
            return;
        }
        var payload = new List<byte>(nonce.Length + 16 + ct.Length);
        payload.AddRange(nonce);
        payload.AddRange(tag);
        payload.AddRange(ct);
        var pkt = CreatePacket(MessageType.NoiseEncrypted, 5, senderPeerHex, payload.ToArray(), recipient: HexTo8(targetPeerHex));
        SendPacket(pkt);
    }

    public void SendNoiseEncrypted(string senderPeerHex, string targetPeerHex, string content)
    {
    // Delegate to the unified BitchatMessage-over-Noise path
    PrivateMessageNoise(senderPeerHex, targetPeerHex, content);
    }

    public void AnnounceIdentity(string myPeerHex, string nickname)
    {
        // Use local signing pub as signing key, and derive a long-term X25519 pub for identity
        var x = _keys.GetOrCreateX25519("default-x25519");
        var nia = new Bitchat.Protocol.Models.NoiseIdentityAnnouncement(
            peerId: myPeerHex,
            publicKey: x.pub.Export(KeyBlobFormat.RawPublicKey),
            signingPublicKey: _signing.pub.Export(KeyBlobFormat.RawPublicKey),
            nickname: nickname,
            timestamp: DateTime.UtcNow,
            previousPeerId: null,
            signature: Array.Empty<byte>()
        );
        // sign over announcement fields excluding signature itself
        var signable = BuildNiaSignable(nia);
        var sig = SignatureAlgorithm.Ed25519.Sign(_signing.priv, signable);
        var niaSigned = new Bitchat.Protocol.Models.NoiseIdentityAnnouncement(
            nia.PeerId, nia.PublicKey, nia.SigningPublicKey, nia.Nickname, nia.Timestamp, nia.PreviousPeerId, sig);
        var pkt = CreatePacket(MessageType.NoiseIdentityAnnounce, 3, myPeerHex, niaSigned.ToBinary());
        SignAndSend(pkt);
    }

    public void HandleIncoming(byte[] raw)
    {
        if (!BinaryProtocol.TryDecode(raw, out var pkt))
        {
            Console.WriteLine("[Router] Decode failed");
            return;
        }

        HandleDecoded(pkt);
    }

    private void HandleDecoded(BitchatPacket pkt)
    {
        // Fragment handling
        if (pkt.Type == MessageType.FragmentStart || pkt.Type == MessageType.FragmentContinue || pkt.Type == MessageType.FragmentEnd)
        {
            if (_fragments.TryHandleFragment(pkt, out var reassembled))
            {
                if (reassembled != null)
                {
                    // Process the reassembled full packet
                    HandleDecoded(reassembled);
                }
            }
            return;
        }

        var pid = PacketId.Compute(pkt);
        if (!_seen.Add(pid))
        {
            // duplicate, ignore
            return;
        }

        // Handle acks early: clear DeliveryTracker entries
        if (pkt.Type == MessageType.ProtocolAck)
        {
            if (Protocol.Models.ProtocolAck.TryFromBinary(pkt.Payload, out var ack))
            {
                _delivery.Ack(ack.OriginalPacketId);
            }
            return;
        }

        // Handle nacks early: stop retries and log
        if (pkt.Type == MessageType.ProtocolNack)
        {
            if (Protocol.Models.ProtocolNack.TryFromBinary(pkt.Payload, out var nack))
            {
                _delivery.Ack(nack.OriginalPacketId); // stop retrying
                Console.WriteLine($"[NACK] code={nack.Code} reason='{nack.Reason}' for={nack.OriginalPacketId}");
            }
            return;
        }

        // Handle Noise messages
        if (pkt.Type == MessageType.NoiseHandshakeInit || pkt.Type == MessageType.NoiseHandshakeResp)
        {
            var peerId = Convert.ToHexString(pkt.SenderId);
            var session = _noise.GetOrCreate(peerId);
            var resp = session.ProcessHandshake(pkt.Payload);
            if (resp != null)
            {
                var replyType = pkt.Type == MessageType.NoiseHandshakeInit ? MessageType.NoiseHandshakeResp : MessageType.NoiseHandshakeInit;
                var reply = CreatePacket(replyType, pkt.Ttl, peerId, resp, recipient: pkt.SenderId);
                SignAndSend(reply);
            }
            return;
        }

        if (pkt.Type == MessageType.NoiseEncrypted)
        {
            var peerId = Convert.ToHexString(pkt.SenderId);
            INoiseSession? sess = null;
            if (_noise.TryGet(peerId, out var s1)) sess = s1;
            else if (pkt.RecipientId != null)
            {
                var rid = Convert.ToHexString(pkt.RecipientId);
                if (_noise.TryGet(rid, out var s2)) sess = s2;
            }
            if (sess != null)
            {
                if (pkt.Payload.Length < 12 + 16) return; // 12 nonce + 16 tag + rest
                var nonce = pkt.Payload.AsSpan(0, 12).ToArray();
                var tag = pkt.Payload.AsSpan(12, 16).ToArray();
                var ct = pkt.Payload.AsSpan(28).ToArray();
                var pt = sess.Decrypt(nonce, tag, ct);
                if (pt != null)
                {
                    // If payload is a BitchatMessage binary, decode it; otherwise best-effort UTF8
                    if (Bitchat.Protocol.Models.BitchatMessage.TryFromBinaryPayload(pt, out var bmDec))
                    {
                        Console.WriteLine($"[Noise Dec] from={peerId} <@{bmDec.Sender}> {bmDec.Content}");
                    }
                    else
                    {
                        string dec;
                        try { dec = System.Text.Encoding.UTF8.GetString(pt); } catch { dec = Convert.ToHexString(pt); }
                        Console.WriteLine($"[Noise Dec] from={peerId} msg='{dec}'");
                    }
                }
                else
                {
                    // decryption failed
                    SendNack(pid, pkt, Protocol.Models.ProtocolNack.ErrorCode.DecryptionFailed, "noise decryption failed");
                }
            }
            else
            {
                // no session found
                SendNack(pid, pkt, Protocol.Models.ProtocolNack.ErrorCode.SessionExpired, "no noise session");
            }
            return;
        }

        if (pkt.Type == MessageType.NoiseIdentityAnnounce)
        {
            if (Bitchat.Protocol.Models.NoiseIdentityAnnouncement.TryFromBinary(pkt.Payload, out var nia))
            {
                var signable = BuildNiaSignable(nia, includeSignature: false);
                // validate signature using included signing public key
                try
                {
                    var senderPub = PublicKey.Import(SignatureAlgorithm.Ed25519, nia.SigningPublicKey, KeyBlobFormat.RawPublicKey);
                    var ok = SignatureAlgorithm.Ed25519.Verify(senderPub, signable, nia.Signature);
                    Console.WriteLine(ok ? "[NIA] signature OK" : "[NIA] signature FAIL");
                    if (ok)
                    {
                        // register mapping: PeerId -> signing pub；也可一併存 X25519 pub 供 Noise 使用
                        _ids.AddOrUpdateEd25519(nia.PeerId, nia.SigningPublicKey);

                        // Publish to Nostr for wider discovery
                        try
                        {
                            var ev = NostrProtocolMapper.ToNostr(nia);
                            ev.PubKey = _nostrKeys.GetXOnlyPubHex();
                            // compute id over unsigned serialization
                            ev.Id = NostrEvent.ComputeId(ev);
                            // sign over SHA256(serialized unsigned)
                            var ser = NostrEvent.SerializeUnsigned(ev);
                            var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(ser));
                            ev.Sig = Convert.ToHexString(_nostrKeys.SignBip340(hash)).ToLowerInvariant();
                            _ = _nostr.PublishAsync(ev);
                        }
                        catch { }
                    }
                }
                catch { Console.WriteLine("[NIA] invalid public key"); }
            }
            return;
        }

        // Show payload: prefer decoding Swift BitchatMessage binary, fallback to best-effort UTF-8
        string msg;
        string? fromName = null;
        if (pkt.Type == MessageType.Message && Bitchat.Protocol.Models.BitchatMessage.TryFromBinaryPayload(pkt.Payload, out var bmPlain))
        {
            fromName = bmPlain.Sender;
            msg = bmPlain.Content;
        }
        else
        {
            try { msg = System.Text.Encoding.UTF8.GetString(pkt.Payload); }
            catch { msg = Convert.ToHexString(pkt.Payload); }
        }
        // Verify signature if present
        if (pkt.Signature != null)
        {
            if (BinaryProtocol.TryGetSignatureSegments(raw: BinaryProtocol.Encode(pkt), out var signable, out var signature))
            {
                // Try identity registry first; fallback to local pub (demo)
                var senderHex = Convert.ToHexString(pkt.SenderId);
                bool ok;
                if (_ids.TryGetEd25519(senderHex, out var senderPub)) ok = KeychainManager.VerifyEd25519(senderPub, signable, signature);
                else ok = KeychainManager.VerifyEd25519(_signing.pub, signable, signature);
                Console.WriteLine(ok ? "[Sig] OK" : "[Sig] FAIL");
                if (!ok)
                {
                    SendNack(pid, pkt, Protocol.Models.ProtocolNack.ErrorCode.MalformedPacket, "signature verify failed");
                }
            }
        }
        if (!string.IsNullOrEmpty(fromName))
            Console.WriteLine($"[Recv] type={pkt.Type} from={Convert.ToHexString(pkt.SenderId)} ttl={pkt.Ttl} <@{fromName}> {msg}");
        else
            Console.WriteLine($"[Recv] type={pkt.Type} from={Convert.ToHexString(pkt.SenderId)} ttl={pkt.Ttl} msg='{msg}'");

        // Send ProtocolAck for non-control messages
        if (pkt.Type != MessageType.ProtocolNack)
        {
            var ack = new ProtocolAck(
                originalPacketId: pid,
                senderId: Convert.ToHexString(pkt.SenderId),
                receiverId: Convert.ToHexString(pkt.SenderId),
                packetType: (byte)pkt.Type,
                hop: 0
            );
            var ackPkt = CreatePacket(MessageType.ProtocolAck, 1, Convert.ToHexString(pkt.SenderId), ack.ToBinary(), recipient: pkt.SenderId);
            SendPacket(ackPkt);
        }

        // TTL-based forwarding with basic rate limiting (mesh multi-hop)
        if (pkt.Ttl > 1 && _forwardLimiter.TryAcquire())
        {
            var fwd = new BitchatPacket(
                Version: pkt.Version,
                Type: pkt.Type,
                SenderId: pkt.SenderId,
                RecipientId: pkt.RecipientId,
                Timestamp: pkt.Timestamp,
                Payload: pkt.Payload,
                Signature: pkt.Signature,
                Ttl: (byte)(pkt.Ttl - 1)
            );
            _transport.Send(BinaryProtocol.Encode(fwd));
        }
        else if (pkt.Ttl > 1)
        {
            // throttled: optional nack to notify sender
            SendNack(pid, pkt, Protocol.Models.ProtocolNack.ErrorCode.ResourceExhausted, "forward rate-limited");
        }
    }

    private void HandleNostrEvent(NostrEvent ev)
    {
        // Auto-register identity when seeing our mapped kind
        if (NostrProtocolMapper.TryFromNostr(ev, out var nia))
        {
            // Basic verification: use embedded Ed25519 key
            try
            {
                var signable = BuildNiaSignable(nia, includeSignature: false);
                var senderPub = PublicKey.Import(SignatureAlgorithm.Ed25519, nia.SigningPublicKey, KeyBlobFormat.RawPublicKey);
                if (SignatureAlgorithm.Ed25519.Verify(senderPub, signable, nia.Signature))
                {
                    _ids.AddOrUpdateEd25519(nia.PeerId, nia.SigningPublicKey);
                    Console.WriteLine($"[Nostr] Registered identity for {nia.PeerId} from relay");
                }
            }
            catch { }
        }
    }

    private void SendPacket(BitchatPacket pkt)
    {
        var data = BinaryProtocol.Encode(pkt);
        // Avoid fragmenting fragment packets
        if (data.Length > 512 && pkt.Type != MessageType.FragmentStart && pkt.Type != MessageType.FragmentContinue && pkt.Type != MessageType.FragmentEnd)
        {
            SendFragmented(pkt, data);
        }
        else
        {
            _transport.Send(data);
        }

        // Track for delivery if it's not a control/fragment packet
        if (ShouldTrack(pkt))
        {
            _delivery.Track(pkt, data);
        }
    }

    private void SignAndSend(BitchatPacket pkt)
    {
        // signer uses Ed25519 over the signable bytes
        byte[] Signer(ReadOnlySpan<byte> data) => SignatureAlgorithm.Ed25519.Sign(_signing.priv, data);
        var data = BinaryProtocol.EncodeWithSigner(pkt, Signer);
        if (data.Length > 512 && pkt.Type != MessageType.FragmentStart && pkt.Type != MessageType.FragmentContinue && pkt.Type != MessageType.FragmentEnd)
        {
            // Need to re-decode to original packet structure for fragmentation path
            if (BinaryProtocol.TryDecode(data, out var signedPkt)) SendFragmented(signedPkt, data);
            else _transport.Send(data);
        }
        else
        {
            _transport.Send(data);
        }

        if (ShouldTrack(pkt)) _delivery.Track(pkt, data);
    }

    private void SendFragmented(BitchatPacket original, byte[] fullData)
    {
        // Generate 8-byte fragment ID
        var fragmentId = new byte[8];
        RandomNumberGenerator.Fill(fragmentId);

        const int maxFragmentSize = 469; // 512 MTU - overhead
        int total = (fullData.Length + maxFragmentSize - 1) / maxFragmentSize;

        // 20ms between fragments
        const int delayMs = 20;

        for (int index = 0; index < total; index++)
        {
            int start = index * maxFragmentSize;
            int len = Math.Min(maxFragmentSize, fullData.Length - start);
            var slice = new ReadOnlySpan<byte>(fullData, start, len);

            var payload = new byte[8 + 2 + 2 + 1 + len];
            int o = 0;
            Buffer.BlockCopy(fragmentId, 0, payload, o, 8); o += 8;
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(o, 2), (ushort)index); o += 2;
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(o, 2), (ushort)total); o += 2;
            payload[o++] = (byte)original.Type;
            slice.CopyTo(payload.AsSpan(o));

            var fragType = index == 0 ? MessageType.FragmentStart : (index == total - 1 ? MessageType.FragmentEnd : MessageType.FragmentContinue);

            var fragPkt = new BitchatPacket(
                Version: original.Version,
                Type: fragType,
                SenderId: original.SenderId,
                RecipientId: original.RecipientId,
                Timestamp: original.Timestamp,
                Payload: payload,
                Signature: null,
                Ttl: original.Ttl
            );

            var sendBytes = BinaryProtocol.Encode(fragPkt);

            var delay = index * delayMs;
            _ = Task.Run(async () => { await Task.Delay(delay); _transport.Send(sendBytes); });
        }
    }

    private static BitchatPacket CreatePacket(MessageType type, byte ttl, string senderHex, ReadOnlySpan<byte> payload, byte[]? recipient = null)
    {
        return new BitchatPacket(
            Version: 1,
            Type: type,
            SenderId: HexTo8(senderHex),
            RecipientId: recipient,
            Timestamp: (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            Payload: payload.ToArray(),
            Signature: null,
            Ttl: ttl
        );
    }

    private static byte[] HexTo8(string hex)
    {
        var clean = hex.AsSpan();
        var outBytes = new byte[8];
        int idx = 0;
        for (int i = 0; i + 1 < clean.Length && idx < 8; i += 2)
        {
            if (byte.TryParse(clean.Slice(i, 2), System.Globalization.NumberStyles.HexNumber, null, out var b))
                outBytes[idx++] = b;
            else break;
        }
        return outBytes;
    }

    private static bool ShouldTrack(BitchatPacket pkt)
    {
        // track normal app messages and encrypted payloads, skip acks/nacks/fragments
        if (pkt.Type == MessageType.ProtocolAck || pkt.Type == MessageType.ProtocolNack) return false;
        if (pkt.Type == MessageType.FragmentStart || pkt.Type == MessageType.FragmentContinue || pkt.Type == MessageType.FragmentEnd) return false;
        return true;
    }

    private static byte[] BuildNiaSignable(Bitchat.Protocol.Models.NoiseIdentityAnnouncement nia, bool includeSignature = true)
    {
        // 以 ToBinary 輸出為基礎，但不含簽章欄位；為了穩定，這裡重建：flags(含prev) + peerId(8) + pubKey(len+data) + signPub(len+data) + nickname(len+data) + ts + [prevPeerId]
        var buf = new List<byte>();
        byte flags = 0; if (nia.PreviousPeerId != null) flags |= 0x01; buf.Add(flags);
        buf.AddRange(nia.PeerId.Length >= 16 ? Convert.FromHexString(nia.PeerId[..16]) : Convert.FromHexString(nia.PeerId));
        void W(List<byte> b, byte[] d) { var l = (ushort)d.Length; Span<byte> ls = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(ls, l); b.AddRange(ls.ToArray()); b.AddRange(d); }
        W(buf, nia.PublicKey); W(buf, nia.SigningPublicKey);
        var nick = System.Text.Encoding.UTF8.GetBytes(nia.Nickname);
        { var l = (ushort)nick.Length; Span<byte> ls = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(ls, l); buf.AddRange(ls.ToArray()); buf.AddRange(nick); }
        { var ms = (ulong)new DateTimeOffset(nia.Timestamp).ToUnixTimeMilliseconds(); Span<byte> t = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(t, ms); buf.AddRange(t.ToArray()); }
        if (nia.PreviousPeerId != null) buf.AddRange(Convert.FromHexString(nia.PreviousPeerId));
        // 不附簽章欄位
        return buf.ToArray();
    }

    private void SendNack(string originalPacketId, BitchatPacket src, Protocol.Models.ProtocolNack.ErrorCode code, string reason)
    {
        var nack = new ProtocolNack(
            originalPacketId: originalPacketId,
            senderId: Convert.ToHexString(src.SenderId),
            receiverId: Convert.ToHexString(src.SenderId),
            packetType: (byte)src.Type,
            reason: reason,
            code: code
        );
        var nackPkt = CreatePacket(MessageType.ProtocolNack, 1, Convert.ToHexString(src.SenderId), nack.ToBinary(), recipient: src.SenderId);
        SendPacket(nackPkt);
    }

    // Helpers to interact from Program: export local signing pub, register a peer's pub key
    public byte[] ExportLocalSigningPublicKeyRaw32() => _signing.pub.Export(KeyBlobFormat.RawPublicKey);
    public bool RegisterPeerSigningKey(string peerHex8, byte[] raw32) => _ids.AddOrUpdateEd25519(peerHex8, raw32);

    // Nostr relay management and identity listing for CLI
    public IReadOnlyList<string> ListRelays() => _nostr.GetRelays();
    public void AddRelay(string url) { _nostr.AddRelay(url); }
    public bool RemoveRelay(string url) => _nostr.RemoveRelay(url);
    public IReadOnlyDictionary<string, string> ListIdentities() => _ids.ListEd25519();
    public string GetNostrPubKeyHex() => _nostrKeys.GetXOnlyPubHex();
}

internal sealed class FragmentAssembler
{
    private readonly Dictionary<string, Dictionary<int, byte[]>> _incoming = new(); // fragmentId -> index -> data
    private readonly Dictionary<string, (byte originalType, int total, DateTime ts)> _meta = new();

    private const int MaxConcurrentSessions = 20;
    private static readonly TimeSpan FragmentTimeout = TimeSpan.FromSeconds(30);
    private const int MaxBytes = 10 * 1024 * 1024;

    public bool TryHandleFragment(BitchatPacket packet, out BitchatPacket? reassembled)
    {
        reassembled = null;
        var p = packet.Payload;
        if (p == null || p.Length < 13) return false;

        // Parse header: 8(id)+2(index)+2(total)+1(originalType)
        var fragmentId = Convert.ToHexString(p.AsSpan(0, 8));
        int index = BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(8, 2));
        int total = BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(10, 2));
        byte originalType = p[12];
        var fragmentData = p.Length > 13 ? p.AsSpan(13).ToArray() : Array.Empty<byte>();

        if (!_incoming.ContainsKey(fragmentId))
        {
            CleanupOld();
            if (_incoming.Count >= MaxConcurrentSessions)
            {
                // still too many, drop
                return true; // handled but no reassembly
            }
            _incoming[fragmentId] = new Dictionary<int, byte[]>();
            _meta[fragmentId] = (originalType, total, DateTime.UtcNow);
        }

        _incoming[fragmentId][index] = fragmentData;

        if (_incoming[fragmentId].Count == total)
        {
            // Reassemble in order
            var buffers = new List<byte>(total * fragmentData.Length);
            for (int i = 0; i < total; i++)
            {
                if (!_incoming[fragmentId].TryGetValue(i, out var frag))
                {
                    return true; // missing, wait for more
                }
                buffers.AddRange(frag);
            }

            var all = buffers.ToArray();
            _incoming.Remove(fragmentId);
            _meta.Remove(fragmentId);

            if (BinaryProtocol.TryDecode(all, out var fullPkt))
            {
                reassembled = fullPkt;
            }
            return true;
        }

        CleanupOld();
        return true; // handled fragment
    }

    private void CleanupOld()
    {
        var cutoff = DateTime.UtcNow - FragmentTimeout;
        var toRemove = new List<string>();
        foreach (var kv in _meta)
        {
            if (kv.Value.ts < cutoff) toRemove.Add(kv.Key);
        }
        foreach (var id in toRemove)
        {
            _incoming.Remove(id);
            _meta.Remove(id);
        }

        // memory cap
        int totalBytes = 0;
        foreach (var fr in _incoming.Values)
        {
            foreach (var d in fr.Values) totalBytes += d.Length;
        }
        if (totalBytes > MaxBytes)
        {
            // remove oldest sessions
            foreach (var id in new List<string>(_meta.Keys))
            {
                _incoming.Remove(id);
                _meta.Remove(id);
                totalBytes = 0;
                foreach (var fr in _incoming.Values)
                    foreach (var d in fr.Values) totalBytes += d.Length;
                if (totalBytes <= MaxBytes) break;
            }
        }
    }
}
