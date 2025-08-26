using System;
using System.Buffers.Binary;
using System.Text;

namespace Bitchat.Protocol.Models;

public sealed class DeliveryAck
{
    public string OriginalMessageId { get; }
    public string AckId { get; }
    public string RecipientId { get; }
    public string RecipientNickname { get; }
    public DateTime Timestamp { get; }
    public byte HopCount { get; }

    public DeliveryAck(string originalMessageId, string recipientId, string recipientNickname, byte hopCount)
    {
        OriginalMessageId = originalMessageId;
        AckId = Guid.NewGuid().ToString();
        RecipientId = recipientId;
        RecipientNickname = recipientNickname;
        Timestamp = DateTime.UtcNow;
        HopCount = hopCount;
    }

    private DeliveryAck(string originalMessageId, string ackId, string recipientId, string recipientNickname, DateTime timestamp, byte hopCount)
    {
        OriginalMessageId = originalMessageId;
        AckId = ackId;
        RecipientId = recipientId;
        RecipientNickname = recipientNickname;
        Timestamp = timestamp;
        HopCount = hopCount;
    }

    public byte[] ToBinary()
    {
        var buf = new List<byte>();
        WriteUuid(buf, OriginalMessageId);
        WriteUuid(buf, AckId);
        buf.AddRange(HexUtil.HexToFixed8(RecipientId));
        buf.Add(HopCount);
        WriteDate(buf, Timestamp);
        WriteString(buf, RecipientNickname);
        return buf.ToArray();
    }

    public static bool TryFromBinary(ReadOnlySpan<byte> data, out DeliveryAck ack)
    {
        ack = default!;
        int o = 0;
        if (!ReadUuid(data, ref o, out var original) ||
            !ReadUuid(data, ref o, out var ackId)) return false;
        if (!TryReadFixed(data, ref o, 8, out var recipientBytes)) return false;
        if (o >= data.Length) return false; var hop = data[o++];
        if (!ReadDate(data, ref o, out var ts)) return false;
        if (!ReadString(data, ref o, out var nick)) return false;
        ack = new DeliveryAck(original, ackId, Convert.ToHexString(recipientBytes), nick, ts, hop);
        return true;
    }

    private static void WriteUuid(List<byte> buf, string id)
    {
        var g = Guid.TryParse(id, out var guid) ? guid : Guid.NewGuid();
        buf.AddRange(g.ToByteArray());
    }
    private static bool ReadUuid(ReadOnlySpan<byte> s, ref int o, out string id)
    {
        id = string.Empty;
        if (o + 16 > s.Length) return false;
        var g = new Guid(s.Slice(o, 16));
        o += 16; id = g.ToString(); return true;
    }
    private static void WriteDate(List<byte> buf, DateTime dt)
    {
        var unixMs = (ulong)new DateTimeOffset(dt).ToUnixTimeMilliseconds();
        Span<byte> b = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(b, unixMs);
        buf.AddRange(b.ToArray());
    }
    private static bool ReadDate(ReadOnlySpan<byte> s, ref int o, out DateTime dt)
    {
        dt = default;
        if (o + 8 > s.Length) return false;
        var ms = BinaryPrimitives.ReadUInt64BigEndian(s.Slice(o, 8));
        o += 8;
        dt = DateTimeOffset.FromUnixTimeMilliseconds((long)ms).UtcDateTime;
        return true;
    }
    private static void WriteString(List<byte> buf, string str)
    {
        var b = Encoding.UTF8.GetBytes(str);
        buf.Add((byte)Math.Min(255, b.Length));
        buf.AddRange(b.AsSpan(0, Math.Min(255, b.Length)).ToArray());
    }
    private static bool ReadString(ReadOnlySpan<byte> s, ref int o, out string value)
    {
        value = string.Empty;
        if (o >= s.Length) return false;
        int len = s[o++];
        if (o + len > s.Length) return false;
        value = Encoding.UTF8.GetString(s.Slice(o, len));
        o += len;
        return true;
    }
    private static bool TryReadFixed(ReadOnlySpan<byte> s, ref int o, int len, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (o + len > s.Length) return false;
        bytes = s.Slice(o, len).ToArray();
        o += len; return true;
    }
}
