using System;
using System.Buffers.Binary;
using System.Text;

namespace Bitchat.Protocol.Models;

public sealed class HandshakeRequest
{
    public string RequestId { get; }
    public string RequesterId { get; }
    public string RequesterNickname { get; }
    public string TargetId { get; }
    public byte PendingMessageCount { get; }
    public DateTime Timestamp { get; }

    public HandshakeRequest(string requesterId, string requesterNickname, string targetId, byte pending)
    { RequestId = Guid.NewGuid().ToString(); RequesterId = requesterId; RequesterNickname = requesterNickname; TargetId = targetId; PendingMessageCount = pending; Timestamp = DateTime.UtcNow; }

    private HandshakeRequest(string requestId, string requesterId, string requesterNickname, string targetId, byte pending, DateTime ts)
    { RequestId = requestId; RequesterId = requesterId; RequesterNickname = requesterNickname; TargetId = targetId; PendingMessageCount = pending; Timestamp = ts; }

    public byte[] ToBinary()
    {
        var buf = new List<byte>();
        WriteUuid(buf, RequestId);
        buf.AddRange(Bitchat.Protocol.HexUtil.HexToFixed8(RequesterId));
        buf.AddRange(Bitchat.Protocol.HexUtil.HexToFixed8(TargetId));
        buf.Add(PendingMessageCount);
        WriteDate(buf, Timestamp);
        WriteString(buf, RequesterNickname);
        return buf.ToArray();
    }

    public static bool TryFromBinary(ReadOnlySpan<byte> s, out HandshakeRequest hr)
    {
        hr = default!; int o = 0;
        if (!ReadUuid(s, ref o, out var rid)) return false;
        if (o + 8 + 8 + 1 > s.Length) return false;
        var req = s.Slice(o, 8).ToArray(); o += 8; var tgt = s.Slice(o, 8).ToArray(); o += 8;
        var cnt = s[o++];
        if (!ReadDate(s, ref o, out var ts)) return false;
        if (!ReadString(s, ref o, out var nick)) return false;
        hr = new HandshakeRequest(rid, Convert.ToHexString(req), nick, Convert.ToHexString(tgt), cnt, ts); return true;
    }

    // helpers
    private static void WriteUuid(List<byte> buf, string id) { var g = Guid.TryParse(id, out var guid) ? guid : Guid.NewGuid(); buf.AddRange(g.ToByteArray()); }
    private static bool ReadUuid(ReadOnlySpan<byte> s, ref int o, out string id) { id = string.Empty; if (o + 16 > s.Length) return false; var g = new Guid(s.Slice(o, 16)); o += 16; id = g.ToString(); return true; }
    private static void WriteDate(List<byte> buf, DateTime dt) { var ms = (ulong)new DateTimeOffset(dt).ToUnixTimeMilliseconds(); Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, ms); buf.AddRange(b.ToArray()); }
    private static bool ReadDate(ReadOnlySpan<byte> s, ref int o, out DateTime dt) { dt = default; if (o + 8 > s.Length) return false; var ms = BinaryPrimitives.ReadUInt64BigEndian(s.Slice(o, 8)); o += 8; dt = DateTimeOffset.FromUnixTimeMilliseconds((long)ms).UtcDateTime; return true; }
    private static void WriteString(List<byte> buf, string str) { var b = Encoding.UTF8.GetBytes(str); buf.Add((byte)Math.Min(255, b.Length)); buf.AddRange(b.AsSpan(0, Math.Min(255, b.Length)).ToArray()); }
    private static bool ReadString(ReadOnlySpan<byte> s, ref int o, out string v) { v = string.Empty; if (o >= s.Length) return false; int len = s[o++]; if (o + len > s.Length) return false; v = Encoding.UTF8.GetString(s.Slice(o, len)); o += len; return true; }
}
