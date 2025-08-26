using System;
using System.Buffers.Binary;
using System.Text;

namespace Bitchat.Protocol;

internal static class BinaryEncoding
{
    public static void WriteUInt8(this List<byte> buffer, byte value) => buffer.Add(value);
    public static void WriteUInt16(this List<byte> buffer, ushort value)
    {
        Span<byte> tmp = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(tmp, value);
        buffer.AddRange(tmp.ToArray());
    }
    public static void WriteUInt32(this List<byte> buffer, uint value)
    {
        Span<byte> tmp = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(tmp, value);
        buffer.AddRange(tmp.ToArray());
    }
    public static void WriteUInt64(this List<byte> buffer, ulong value)
    {
        Span<byte> tmp = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(tmp, value);
        buffer.AddRange(tmp.ToArray());
    }
    public static void WriteVarBytes(this List<byte> buffer, ReadOnlySpan<byte> data)
    {
        buffer.WriteUInt16((ushort)data.Length);
        buffer.AddRange(data.ToArray());
    }
    public static void WriteString(this List<byte> buffer, string s)
    {
        var bytes = Encoding.UTF8.GetBytes(s);
        buffer.WriteVarBytes(bytes);
    }

    public static bool TryReadUInt8(this ReadOnlySpan<byte> span, ref int offset, out byte value)
    {
        if (offset + 1 > span.Length) { value = 0; return false; }
        value = span[offset];
        offset += 1; return true;
    }
    public static bool TryReadUInt16(this ReadOnlySpan<byte> span, ref int offset, out ushort value)
    {
        if (offset + 2 > span.Length) { value = 0; return false; }
        value = BinaryPrimitives.ReadUInt16BigEndian(span[offset..]);
        offset += 2; return true;
    }
    public static bool TryReadUInt64(this ReadOnlySpan<byte> span, ref int offset, out ulong value)
    {
        if (offset + 8 > span.Length) { value = 0; return false; }
        value = BinaryPrimitives.ReadUInt64BigEndian(span[offset..]);
        offset += 8; return true;
    }
    public static bool TryReadVarBytes(this ReadOnlySpan<byte> span, ref int offset, out byte[] data)
    {
        data = Array.Empty<byte>();
        if (!span.TryReadUInt16(ref offset, out var len)) return false;
        if (offset + len > span.Length) return false;
        data = span.Slice(offset, len).ToArray();
        offset += len; return true;
    }
    public static bool TryReadString(this ReadOnlySpan<byte> span, ref int offset, out string value)
    {
        value = string.Empty;
        if (!span.TryReadVarBytes(ref offset, out var data)) return false;
        value = Encoding.UTF8.GetString(data);
        return true;
    }
}

public record BitchatPacket(
    byte Version,
    MessageType Type,
    byte[] SenderId,
    byte[]? RecipientId,
    ulong Timestamp,
    byte[] Payload,
    byte[]? Signature,
    byte Ttl
)
{
    public static BitchatPacket Create(MessageType type, byte ttl, string senderHex, ReadOnlySpan<byte> payload)
    {
        return new BitchatPacket(
            Version: 1,
            Type: type,
            SenderId: HexTo8(senderHex),
            RecipientId: null,
            Timestamp: (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            Payload: payload.ToArray(),
            Signature: null,
            Ttl: ttl
        );
    }

    public byte[] Encode()
    {
        var buf = new List<byte>(64 + Payload.Length);
        buf.WriteUInt8(Version);
        buf.WriteUInt8((byte)Type);
        buf.WriteVarBytes(SenderId);
        buf.WriteUInt8((byte)(RecipientId == null ? 0 : 1));
        if (RecipientId != null) buf.WriteVarBytes(RecipientId);
        buf.WriteUInt64(Timestamp);
        buf.WriteVarBytes(Payload);
        buf.WriteUInt8((byte)(Signature == null ? 0 : 1));
        if (Signature != null) buf.WriteVarBytes(Signature);
        buf.WriteUInt8(Ttl);
        return buf.ToArray();
    }

    public static bool TryDecode(ReadOnlySpan<byte> data, out BitchatPacket packet)
    {
        packet = default!;
        int o = 0;
        if (!data.TryReadUInt8(ref o, out var ver)) return false;
        if (!data.TryReadUInt8(ref o, out var type)) return false;
        if (!data.TryReadVarBytes(ref o, out var sender)) return false;
        if (!data.TryReadUInt8(ref o, out var hasRecipient)) return false;
        byte[]? recipient = null;
        if (hasRecipient == 1)
        {
            if (!data.TryReadVarBytes(ref o, out recipient)) return false;
        }
        if (!data.TryReadUInt64(ref o, out var ts)) return false;
        if (!data.TryReadVarBytes(ref o, out var payload)) return false;
        if (!data.TryReadUInt8(ref o, out var hasSig)) return false;
        byte[]? sig = null;
        if (hasSig == 1)
        {
            if (!data.TryReadVarBytes(ref o, out sig)) return false;
        }
        if (!data.TryReadUInt8(ref o, out var ttl)) return false;
        packet = new BitchatPacket(ver, (MessageType)type, sender, recipient, ts, payload, sig, ttl);
        return true;
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
}
