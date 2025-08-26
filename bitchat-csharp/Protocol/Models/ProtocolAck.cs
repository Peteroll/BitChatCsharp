using System;
using System.Buffers.Binary;

namespace Bitchat.Protocol.Models;

public sealed class ProtocolAck
{
    public string OriginalPacketId { get; }
    public string AckId { get; }
    public string SenderId { get; }
    public string ReceiverId { get; }
    public byte PacketType { get; }
    public DateTime Timestamp { get; }
    public byte HopCount { get; }

    public ProtocolAck(string originalPacketId, string senderId, string receiverId, byte packetType, byte hop)
    { OriginalPacketId = originalPacketId; AckId = Guid.NewGuid().ToString(); SenderId = senderId; ReceiverId = receiverId; PacketType = packetType; Timestamp = DateTime.UtcNow; HopCount = hop; }

    private ProtocolAck(string originalPacketId, string ackId, string senderId, string receiverId, byte packetType, DateTime ts, byte hop)
    { OriginalPacketId = originalPacketId; AckId = ackId; SenderId = senderId; ReceiverId = receiverId; PacketType = packetType; Timestamp = ts; HopCount = hop; }

    public byte[] ToBinary()
    {
        var buf = new List<byte>();
        WriteUuid(buf, OriginalPacketId); WriteUuid(buf, AckId);
        buf.AddRange(Bitchat.Protocol.HexUtil.HexToFixed8(SenderId));
        buf.AddRange(Bitchat.Protocol.HexUtil.HexToFixed8(ReceiverId));
        buf.Add(PacketType);
        buf.Add(HopCount);
        WriteDate(buf, Timestamp);
        return buf.ToArray();
    }

    public static bool TryFromBinary(ReadOnlySpan<byte> s, out ProtocolAck ack)
    {
        ack = default!; int o = 0;
        if (!ReadUuid(s, ref o, out var op) || !ReadUuid(s, ref o, out var aid)) return false;
        if (o + 8 + 8 > s.Length) return false; var sender = s.Slice(o, 8).ToArray(); o += 8; var recv = s.Slice(o, 8).ToArray(); o += 8;
        if (o + 1 + 1 > s.Length) return false; var ptype = s[o++]; var hop = s[o++];
        if (!ReadDate(s, ref o, out var ts)) return false;
        ack = new ProtocolAck(op, aid, Convert.ToHexString(sender), Convert.ToHexString(recv), ptype, ts, hop); return true;
    }

    // helpers
    private static void WriteUuid(List<byte> buf, string id) { var g = Guid.TryParse(id, out var guid) ? guid : Guid.NewGuid(); buf.AddRange(g.ToByteArray()); }
    private static bool ReadUuid(ReadOnlySpan<byte> s, ref int o, out string id) { id = string.Empty; if (o + 16 > s.Length) return false; var g = new Guid(s.Slice(o, 16)); o += 16; id = g.ToString(); return true; }
    private static void WriteDate(List<byte> buf, DateTime dt) { var ms = (ulong)new DateTimeOffset(dt).ToUnixTimeMilliseconds(); Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, ms); buf.AddRange(b.ToArray()); }
    private static bool ReadDate(ReadOnlySpan<byte> s, ref int o, out DateTime dt) { dt = default; if (o + 8 > s.Length) return false; var ms = BinaryPrimitives.ReadUInt64BigEndian(s.Slice(o, 8)); o += 8; dt = DateTimeOffset.FromUnixTimeMilliseconds((long)ms).UtcDateTime; return true; }
}
