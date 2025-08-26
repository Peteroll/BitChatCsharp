using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Bitchat.Protocol;
using Bitchat.Core;
using Bitchat.Noise;

namespace Bitchat.Tests;

public static class SelfTests
{
    public static bool RunAll()
    {
        try
        {
            TestRoundTripBasic();
            TestRoundTripWithRecipient();
            TestRoundTripWithSignature();
            TestCompressionPath();
            TestFragmentationReassembly();
            TestNoiseHandshakeAndEncrypt();
            TestSignatureRoundTrip();
            Console.WriteLine("[SelfTest] All tests passed");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SelfTest] Failed: {ex.Message}");
            return false;
        }
    }

    private static void TestNoiseHandshakeAndEncrypt()
    {
        var a = new Noise.NoiseSession("peerA");
        var b = new Noise.NoiseSession("peerB");

        // A initiates
        var init = a.GetInitPayload();
        var resp = b.ProcessHandshake(init);
        if (resp == null) throw new("b handshake failed");
        var fin = a.ProcessHandshake(resp);
        if (!a.IsEstablished || !b.IsEstablished) throw new("noise not established");

        // Encrypt A->B
        var msg = System.Text.Encoding.UTF8.GetBytes("hello-noise");
        var ct = a.Encrypt(msg, out var nonce, out var tag);
        if (ct == null) throw new("encrypt failed");
        var pt = b.Decrypt(nonce, tag, ct);
        if (pt == null || !pt.AsSpan().SequenceEqual(msg)) throw new("decrypt mismatch");
    }

    private static BitchatPacket CreatePacket(MessageType type, byte[] sender, byte[]? recipient, byte[] payload, byte[]? signature = null)
    {
        return new BitchatPacket(
            Version: 1,
            Type: type,
            SenderId: sender,
            RecipientId: recipient,
            Timestamp: (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            Payload: payload,
            Signature: signature,
            Ttl: 5
        );
    }

    private static void TestRoundTripBasic()
    {
        var sender = Rand8();
        var payload = RandomBytes(64);
        var pkt = CreatePacket(MessageType.Message, sender, null, payload);
        var bytes = BinaryProtocol.Encode(pkt);
        if (!BinaryProtocol.TryDecode(bytes, out var dec)) throw new("decode failed");
        if (dec.Version != 1 || dec.Type != MessageType.Message) throw new("header mismatch");
        if (!dec.SenderId.AsSpan().SequenceEqual(sender)) throw new("sender mismatch");
        if (dec.RecipientId != null) throw new("recipient unexpected");
        if (!dec.Payload.AsSpan().SequenceEqual(payload)) throw new("payload mismatch");
        if (dec.Signature != null) throw new("signature unexpected");
    }

    private static void TestRoundTripWithRecipient()
    {
        var sender = Rand8();
        var recipient = Rand8();
        var payload = RandomBytes(32);
        var pkt = CreatePacket(MessageType.Message, sender, recipient, payload);
        var bytes = BinaryProtocol.Encode(pkt);
        if (!BinaryProtocol.TryDecode(bytes, out var dec)) throw new("decode failed");
        if (!dec.RecipientId!.AsSpan().SequenceEqual(recipient)) throw new("recipient mismatch");
    }

    private static void TestRoundTripWithSignature()
    {
        var sender = Rand8();
        var payload = RandomBytes(48);
        // try shorter
        var sigShort = RandomBytes(32);
        var pkt1 = CreatePacket(MessageType.Message, sender, null, payload, sigShort);
        var bytes1 = BinaryProtocol.Encode(pkt1);
        if (!BinaryProtocol.TryDecode(bytes1, out var dec1)) throw new("decode failed");
        if (dec1.Signature == null || dec1.Signature.Length != BinaryProtocol.SignatureSize) throw new("sig size mismatch");
        for (int i = 0; i < sigShort.Length; i++) if (dec1.Signature[i] != sigShort[i]) throw new("sig short content mismatch");
        for (int i = sigShort.Length; i < dec1.Signature.Length; i++) if (dec1.Signature[i] != 0) throw new("sig padding mismatch");

        // try longer (80)
        var sigLong = RandomBytes(80);
        var pkt2 = CreatePacket(MessageType.Message, sender, null, payload, sigLong);
        var bytes2 = BinaryProtocol.Encode(pkt2);
        if (!BinaryProtocol.TryDecode(bytes2, out var dec2)) throw new("decode failed");
        for (int i = 0; i < BinaryProtocol.SignatureSize; i++) if (dec2.Signature![i] != sigLong[i]) throw new("sig truncate mismatch");
    }

    private static void TestCompressionPath()
    {
        var sender = Rand8();
        var payload = RandomBytes(2048); // big enough to compress
        var pkt = CreatePacket(MessageType.Message, sender, null, payload);
        var bytes = BinaryProtocol.Encode(pkt);
        // check compressed flag in header
        var unpadded = MessagePadding.Unpad(bytes);
        byte flags = unpadded[1 + 1 + 1 + 8];
        bool isCompressed = (flags & BinaryProtocol.Flags.IsCompressed) != 0;
        // compression may fail to help; accept both, but decode must round-trip
        if (!BinaryProtocol.TryDecode(bytes, out var dec)) throw new("decode failed");
        if (!dec.Payload.AsSpan().SequenceEqual(payload)) throw new("payload mismatch after compression");
    }

    private static void TestFragmentationReassembly()
    {
        var sender = Rand8();
        var payload = RandomBytes(4096);
        var original = CreatePacket(MessageType.Message, sender, null, payload);
        var full = BinaryProtocol.Encode(original);

        var assembler = new FragmentAssembler();
        var fragId = Rand8();
        const int maxFragmentSize = 469;
        int total = (full.Length + maxFragmentSize - 1) / maxFragmentSize;
        for (int index = 0; index < total; index++)
        {
            int start = index * maxFragmentSize;
            int len = Math.Min(maxFragmentSize, full.Length - start);
            var slice = full.AsSpan(start, len);
            var fragPayload = new byte[8 + 2 + 2 + 1 + len];
            int o = 0;
            Buffer.BlockCopy(fragId, 0, fragPayload, o, 8); o += 8;
            BinaryPrimitives.WriteUInt16BigEndian(fragPayload.AsSpan(o, 2), (ushort)index); o += 2;
            BinaryPrimitives.WriteUInt16BigEndian(fragPayload.AsSpan(o, 2), (ushort)total); o += 2;
            fragPayload[o++] = (byte)MessageType.Message;
            slice.CopyTo(fragPayload.AsSpan(o));

            var fragType = index == 0 ? MessageType.FragmentStart : (index == total - 1 ? MessageType.FragmentEnd : MessageType.FragmentContinue);
            var fragPkt = CreatePacket(fragType, sender, null, fragPayload);
            var enc = BinaryProtocol.Encode(fragPkt);
            if (!BinaryProtocol.TryDecode(enc, out var decodedFrag)) throw new("fragment decode failed");
            if (assembler.TryHandleFragment(decodedFrag, out var reassembled) && reassembled != null)
            {
                // Only last should produce reassembled
                if (index != total - 1) throw new("reassembled too early");
                if (!reassembled.Payload.AsSpan().SequenceEqual(original.Payload)) throw new("reassembled payload mismatch");
            }
        }
    }

    private static void TestSignatureRoundTrip()
    {
        var sender = Rand8();
        var payload = RandomBytes(128);
        var pkt = CreatePacket(MessageType.Message, sender, null, payload);

        // create signing key
        var alg = NSec.Cryptography.SignatureAlgorithm.Ed25519;
        using var key = new NSec.Cryptography.Key(alg, new NSec.Cryptography.KeyCreationParameters { ExportPolicy = NSec.Cryptography.KeyExportPolicies.AllowPlaintextExport });
        byte[] Signer(ReadOnlySpan<byte> data) => alg.Sign(key, data);
        var enc = BinaryProtocol.EncodeWithSigner(pkt, Signer);
        if (!BinaryProtocol.TryGetSignatureSegments(enc, out var signable, out var sig)) throw new("sig segments not found");
        if (!alg.Verify(key.PublicKey, signable, sig)) throw new("signature verify failed");
    }

    private static byte[] Rand8() { var b = new byte[8]; RandomNumberGenerator.Fill(b); return b; }
    private static byte[] RandomBytes(int n) { var b = new byte[n]; RandomNumberGenerator.Fill(b); return b; }
}
