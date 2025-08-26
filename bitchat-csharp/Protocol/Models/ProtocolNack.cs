using System;
using System.Buffers.Binary;
using System.Text;

namespace Bitchat.Protocol.Models;

public sealed class ProtocolNack
{
    public enum ErrorCode : byte { Unknown = 0, ChecksumFailed = 1, DecryptionFailed = 2, MalformedPacket = 3, UnsupportedVersion = 4, ResourceExhausted = 5, RoutingFailed = 6, SessionExpired = 7 }

    public string OriginalPacketId { get; }
    public string NackId { get; }
    public string SenderId { get; }
    public string ReceiverId { get; }
    public byte PacketType { get; }
    public DateTime Timestamp { get; }
    public string Reason { get; }
    public ErrorCode Code { get; }

    public ProtocolNack(string originalPacketId, string senderId, string receiverId, byte packetType, string reason, ErrorCode code = ErrorCode.Unknown)
    { OriginalPacketId = originalPacketId; NackId = Guid.NewGuid().ToString(); SenderId = senderId; ReceiverId = receiverId; PacketType = packetType; Timestamp = DateTime.UtcNow; Reason = reason; Code = code; }

    private ProtocolNack(string originalPacketId, string nackId, string senderId, string receiverId, byte packetType, DateTime ts, string reason, ErrorCode code)
    { OriginalPacketId = originalPacketId; NackId = nackId; SenderId = senderId; ReceiverId = receiverId; PacketType = packetType; Timestamp = ts; Reason = reason; Code = code; }

    public byte[] ToBinary()
    {
        var buf = new List<byte>();
        WriteUuid(buf, OriginalPacketId); WriteUuid(buf, NackId);
        buf.AddRange(Bitchat.Protocol.HexUtil.HexToFixed8(SenderId));
        buf.AddRange(Bitchat.Protocol.HexUtil.HexToFixed8(ReceiverId));
        buf.Add(PacketType);
        buf.Add((byte)Code);
        WriteDate(buf, Timestamp);
        WriteString(buf, Reason);
        return buf.ToArray();
    }

    public static bool TryFromBinary(ReadOnlySpan<byte> s, out ProtocolNack nack)
    {
        nack = default!; int o = 0;
        if (!ReadUuid(s, ref o, out var op) || !ReadUuid(s, ref o, out var nid)) return false;
        if (o + 8 + 8 + 1 + 1 + 8 > s.Length) return false;
        var sender = s.Slice(o, 8).ToArray(); o += 8; var recv = s.Slice(o, 8).ToArray(); o += 8;
        var ptype = s[o++]; var code = (ErrorCode)s[o++];
        if (!ReadDate(s, ref o, out var ts)) return false;
        if (!ReadString(s, ref o, out var reason)) return false;
        nack = new ProtocolNack(op, nid, Convert.ToHexString(sender), Convert.ToHexString(recv), ptype, ts, reason, code); return true;
    }

    // helpers
    private static void WriteUuid(List<byte> buf, string id) { var g = Guid.TryParse(id, out var guid) ? guid : Guid.NewGuid(); buf.AddRange(g.ToByteArray()); }
    private static bool ReadUuid(ReadOnlySpan<byte> s, ref int o, out string id) { id = string.Empty; if (o + 16 > s.Length) return false; var g = new Guid(s.Slice(o, 16)); o += 16; id = g.ToString(); return true; }
    private static void WriteDate(List<byte> buf, DateTime dt) { var ms = (ulong)new DateTimeOffset(dt).ToUnixTimeMilliseconds(); Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, ms); buf.AddRange(b.ToArray()); }
    private static bool ReadDate(ReadOnlySpan<byte> s, ref int o, out DateTime dt) { dt = default; if (o + 8 > s.Length) return false; var ms = BinaryPrimitives.ReadUInt64BigEndian(s.Slice(o, 8)); o += 8; dt = DateTimeOffset.FromUnixTimeMilliseconds((long)ms).UtcDateTime; return true; }
    private static void WriteString(List<byte> buf, string str) { var b = Encoding.UTF8.GetBytes(str); buf.Add((byte)Math.Min(255, b.Length)); buf.AddRange(b.AsSpan(0, Math.Min(255, b.Length)).ToArray()); }
    private static bool ReadString(ReadOnlySpan<byte> s, ref int o, out string v) { v = string.Empty; if (o >= s.Length) return false; int len = s[o++]; if (o + len > s.Length) return false; v = Encoding.UTF8.GetString(s.Slice(o, len)); o += len; return true; }
}
