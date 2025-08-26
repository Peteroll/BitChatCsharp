using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Bitchat.Protocol;

public static class BinaryProtocol
{
    // Header layout: Version(1) + Type(1) + TTL(1) + Timestamp(8) + Flags(1) + PayloadLen(2) = 14 bytes
    public const int HeaderSize = 14;
    public const int SenderIdSize = 8;
    public const int RecipientIdSize = 8;
    public const int SignatureSize = 64;

    public static class Flags
    {
        public const byte HasRecipient = 0x01;
        public const byte HasSignature = 0x02;
        public const byte IsCompressed = 0x04;
    }

    public static byte[] Encode(BitchatPacket packet)
    {
        // Prepare payload with optional compression
        var payload = packet.Payload.AsSpan();
        bool isCompressed = false;
        ushort? originalSize = null;
        if (CompressionUtil.ShouldCompress(payload))
        {
            var compressed = CompressionUtil.Compress(payload);
            if (compressed != null)
            {
                payload = compressed;
                originalSize = (ushort)packet.Payload.Length;
                isCompressed = true;
            }
        }

        int payloadDataSize = payload.Length + (isCompressed ? 2 : 0);
        var buf = new byte[HeaderSize];
        int o = 0;
        buf[o++] = packet.Version;
        buf[o++] = (byte)packet.Type;
        buf[o++] = packet.Ttl;
        BinaryPrimitives.WriteUInt64BigEndian(buf.AsSpan(o, 8), packet.Timestamp);
        o += 8;
        byte flags = 0;
        if (packet.RecipientId != null) flags |= Flags.HasRecipient;
        if (packet.Signature != null) flags |= Flags.HasSignature;
        if (isCompressed) flags |= Flags.IsCompressed;
        buf[o++] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(o, 2), (ushort)payloadDataSize);
        o += 2;

        var bytes = new List<byte>(HeaderSize + SenderIdSize + ((packet.RecipientId != null) ? RecipientIdSize : 0) + payloadDataSize + (((packet.Signature != null) ? SignatureSize : 0)));
        bytes.AddRange(buf);

        // Sender ID exactly 8 bytes (pad with zeros if shorter)
        WriteFixed(bytes, packet.SenderId, SenderIdSize);

        if ((flags & Flags.HasRecipient) != 0)
            WriteFixed(bytes, packet.RecipientId!, RecipientIdSize);

        if (isCompressed && originalSize.HasValue)
        {
            Span<byte> os = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(os, originalSize.Value);
            bytes.AddRange(os.ToArray());
        }
        bytes.AddRange(payload.ToArray());

        if ((flags & Flags.HasSignature) != 0)
        {
            // write up to 64 bytes
            var sig = packet.Signature!;
            if (sig.Length >= SignatureSize)
            {
                bytes.AddRange(sig.AsSpan(0, SignatureSize).ToArray());
            }
            else
            {
                // pad to 64 bytes to match fixed-size decoder expectation
                bytes.AddRange(sig);
                bytes.AddRange(new byte[SignatureSize - sig.Length]);
            }
        }

        // Apply padding to optimal block size
        var padded = MessagePadding.Pad(bytes.ToArray(), MessagePadding.OptimalBlockSize(bytes.Count));
        return padded;
    }

    // Encode with signature: signer receives the exact bytes to sign (unpadded, up to end of payload),
    // with HasSignature flag already set in header. Then we append 64-byte signature and pad.
    public static byte[] EncodeWithSigner(BitchatPacket packet, SignerDelegate signer)
    {
        // Prepare payload with optional compression (same as Encode)
        var payload = packet.Payload.AsSpan();
        bool isCompressed = false;
        ushort? originalSize = null;
        if (CompressionUtil.ShouldCompress(payload))
        {
            var compressed = CompressionUtil.Compress(payload);
            if (compressed != null)
            {
                payload = compressed;
                originalSize = (ushort)packet.Payload.Length;
                isCompressed = true;
            }
        }

        int payloadDataSize = payload.Length + (isCompressed ? 2 : 0);
        var buf = new byte[HeaderSize];
        int o = 0;
        buf[o++] = packet.Version;
        buf[o++] = (byte)packet.Type;
        buf[o++] = packet.Ttl;
        BinaryPrimitives.WriteUInt64BigEndian(buf.AsSpan(o, 8), packet.Timestamp);
        o += 8;
        byte flags = 0;
        if (packet.RecipientId != null) flags |= Flags.HasRecipient;
        flags |= Flags.HasSignature; // ensure signature flag present
        if (isCompressed) flags |= Flags.IsCompressed;
        buf[o++] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(o, 2), (ushort)payloadDataSize);
        o += 2;

        var preSig = new List<byte>(HeaderSize + SenderIdSize + ((packet.RecipientId != null) ? RecipientIdSize : 0) + payloadDataSize);
        preSig.AddRange(buf);
        WriteFixed(preSig, packet.SenderId, SenderIdSize);
        if ((flags & Flags.HasRecipient) != 0)
            WriteFixed(preSig, packet.RecipientId!, RecipientIdSize);
        if (isCompressed && originalSize.HasValue)
        {
            Span<byte> os = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(os, originalSize.Value);
            preSig.AddRange(os.ToArray());
        }
        preSig.AddRange(payload.ToArray());

        // sign over preSig
        var sig = signer(preSig.ToArray());
        if (sig.Length != SignatureSize)
        {
            // normalize to 64-byte fixed size
            if (sig.Length > SignatureSize) sig = sig.AsSpan(0, SignatureSize).ToArray();
            else
            {
                var tmp = new byte[SignatureSize];
                sig.CopyTo(tmp, 0);
                sig = tmp;
            }
        }

        // final bytes = preSig + signature, then padding
        var combined = new byte[preSig.Count + SignatureSize];
        preSig.CopyTo(combined, 0);
        Buffer.BlockCopy(sig, 0, combined, preSig.Count, SignatureSize);
        var padded = MessagePadding.Pad(combined, MessagePadding.OptimalBlockSize(combined.Length));
        return padded;
    }

    // From a raw encoded (and padded) message, extract the unpadded signable segment and signature.
    public static bool TryGetSignatureSegments(ReadOnlySpan<byte> raw, out ReadOnlySpan<byte> signable, out ReadOnlySpan<byte> signature)
    {
        signable = default; signature = default;
        var unpadded = MessagePadding.Unpad(raw.ToArray());
        if (unpadded.Length < HeaderSize + SenderIdSize) return false;
        int o = 0;
        // read header
        o += 1; // version
        o += 1; // type
        o += 1; // ttl
        o += 8; // ts
        byte flags = unpadded[o++];
        ushort payloadLen = BinaryPrimitives.ReadUInt16BigEndian(unpadded.AsSpan(o, 2));
        o += 2;
        if ((flags & Flags.HasSignature) == 0) return false;
        // compute total signable length
        int signableLen = HeaderSize + SenderIdSize + (((flags & Flags.HasRecipient) != 0) ? RecipientIdSize : 0) + payloadLen;
        if (unpadded.Length != signableLen + SignatureSize) return false;
        signable = unpadded.AsSpan(0, signableLen);
        signature = unpadded.AsSpan(signableLen, SignatureSize);
        return true;
    }

    public static bool TryDecode(ReadOnlySpan<byte> input, out BitchatPacket packet)
    {
        packet = default!;
        var unpadded = MessagePadding.Unpad(input.ToArray());
        if (unpadded.Length < HeaderSize + SenderIdSize) return false;
        int o = 0;
        byte version = unpadded[o++];
        if (!ProtocolVersion.IsSupported(version)) return false;
        byte type = unpadded[o++];
        byte ttl = unpadded[o++];
        ulong ts = BinaryPrimitives.ReadUInt64BigEndian(unpadded.AsSpan(o, 8));
        o += 8;
        byte flags = unpadded[o++];
        ushort payloadLen = BinaryPrimitives.ReadUInt16BigEndian(unpadded.AsSpan(o, 2));
        o += 2;

        int expected = HeaderSize + SenderIdSize + (((flags & Flags.HasRecipient) != 0) ? RecipientIdSize : 0) + payloadLen + (((flags & Flags.HasSignature) != 0) ? SignatureSize : 0);
        if (unpadded.Length != expected) return false;

        byte[] sender = unpadded.AsSpan(o, SenderIdSize).ToArray();
        o += SenderIdSize;

        byte[]? recipient = null;
        if ((flags & Flags.HasRecipient) != 0)
        {
            recipient = unpadded.AsSpan(o, RecipientIdSize).ToArray();
            o += RecipientIdSize;
        }

        byte[] payload;
        if ((flags & Flags.IsCompressed) != 0)
        {
            if (payloadLen < 2) return false;
            ushort origSize = BinaryPrimitives.ReadUInt16BigEndian(unpadded.AsSpan(o, 2));
            o += 2;
            var compressed = unpadded.AsSpan(o, payloadLen - 2).ToArray();
            o += payloadLen - 2;
            var dec = CompressionUtil.Decompress(compressed, origSize);
            if (dec == null) return false;
            if (dec.Length != origSize) return false;
            payload = dec;
        }
        else
        {
            payload = unpadded.AsSpan(o, payloadLen).ToArray();
            o += payloadLen;
        }

        byte[]? signature = null;
        if ((flags & Flags.HasSignature) != 0)
        {
            signature = unpadded.AsSpan(o, SignatureSize).ToArray();
            // o += SignatureSize; // not needed further
        }

        packet = new BitchatPacket(
            Version: version,
            Type: (MessageType)type,
            SenderId: sender,
            RecipientId: recipient,
            Timestamp: ts,
            Payload: payload,
            Signature: signature,
            Ttl: ttl
        );
        return true;
    }

    private static void WriteFixed(List<byte> bytes, byte[] data, int size)
    {
        if (data.Length >= size)
            bytes.AddRange(data.AsSpan(0, size).ToArray());
        else
        {
            bytes.AddRange(data);
            bytes.AddRange(new byte[size - data.Length]);
        }
    }
}

// Custom delegate avoids using ReadOnlySpan<T> in generic type args (Func<,>)
public delegate byte[] SignerDelegate(ReadOnlySpan<byte> data);
