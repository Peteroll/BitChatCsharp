using System;
using System.Buffers.Binary;
using System.Text;

namespace Bitchat.Protocol.Models;

public sealed class BitchatMessage
{
    public string Id { get; }
    public string Sender { get; }
    public string Content { get; }
    public DateTime Timestamp { get; }
    public bool IsRelay { get; }
    public string? OriginalSender { get; }
    public bool IsPrivate { get; }
    public string? RecipientNickname { get; }
    public string? SenderPeerId { get; }
    public string[]? Mentions { get; }

    public BitchatMessage(string id, string sender, string content, DateTime timestamp, bool isRelay, string? originalSender, bool isPrivate, string? recipientNickname, string? senderPeerId, string[]? mentions)
    { Id = id; Sender = sender; Content = content; Timestamp = timestamp; IsRelay = isRelay; OriginalSender = originalSender; IsPrivate = isPrivate; RecipientNickname = recipientNickname; SenderPeerId = senderPeerId; Mentions = mentions; }

    public static byte[] ToBinaryPayload(BitchatMessage m)
    {
        var buf = new List<byte>();
        byte flags = 0; if (m.IsRelay) flags |= 0x01; if (m.IsPrivate) flags |= 0x02; if (m.OriginalSender != null) flags |= 0x04; if (m.RecipientNickname != null) flags |= 0x08; if (m.SenderPeerId != null) flags |= 0x10; if (m.Mentions is { Length: > 0 }) flags |= 0x20;
        buf.Add(flags);
        var ms = (ulong)new DateTimeOffset(m.Timestamp).ToUnixTimeMilliseconds();
        Span<byte> t = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(t, ms); buf.AddRange(t.ToArray());
        WriteU8String(buf, m.Id);
        WriteU8String(buf, m.Sender);
        WriteU16String(buf, m.Content);
        if (m.OriginalSender != null) WriteU8String(buf, m.OriginalSender);
        if (m.RecipientNickname != null) WriteU8String(buf, m.RecipientNickname);
        if (m.SenderPeerId != null) WriteU8String(buf, m.SenderPeerId);
        if (m.Mentions is { Length: > 0 })
        {
            buf.Add((byte)Math.Min(255, m.Mentions.Length));
            foreach (var mention in m.Mentions.AsSpan(0, Math.Min(255, m.Mentions.Length)).ToArray())
                WriteU8String(buf, mention);
        }
        return buf.ToArray();
    }

    public static bool TryFromBinaryPayload(ReadOnlySpan<byte> s, out BitchatMessage m)
    {
        m = default!; if (s.Length < 13) return false; int o = 0;
        byte flags = s[o++]; bool isRelay = (flags & 0x01) != 0, isPrivate = (flags & 0x02) != 0, hasOrig = (flags & 0x04) != 0, hasRecip = (flags & 0x08) != 0, hasPeer = (flags & 0x10) != 0, hasMentions = (flags & 0x20) != 0;
        if (o + 8 > s.Length) return false; ulong ts = BinaryPrimitives.ReadUInt64BigEndian(s.Slice(o, 8)); o += 8; var dt = DateTimeOffset.FromUnixTimeMilliseconds((long)ts).UtcDateTime;
        if (!ReadU8String(s, ref o, out var id)) return false;
        if (!ReadU8String(s, ref o, out var sender)) return false;
        if (!ReadU16String(s, ref o, out var content)) return false;
        string? orig = null, recip = null, peer = null; string[]? mentions = null;
        if (hasOrig) { if (!ReadU8String(s, ref o, out orig)) return false; }
        if (hasRecip) { if (!ReadU8String(s, ref o, out recip)) return false; }
        if (hasPeer) { if (!ReadU8String(s, ref o, out peer)) return false; }
        if (hasMentions)
        {
            if (o >= s.Length) return false; int count = s[o++];
            mentions = new string[count];
            for (int i = 0; i < count; i++) { if (!ReadU8String(s, ref o, out var mn)) return false; mentions[i] = mn; }
        }
        m = new BitchatMessage(id, sender, content, dt, isRelay, orig, isPrivate, recip, peer, mentions);
        return true;
    }

    private static void WriteU8String(List<byte> buf, string s)
    { var b = Encoding.UTF8.GetBytes(s); buf.Add((byte)Math.Min(255, b.Length)); buf.AddRange(b.AsSpan(0, Math.Min(255, b.Length)).ToArray()); }
    private static void WriteU16String(List<byte> buf, string s)
    { var b = Encoding.UTF8.GetBytes(s); Span<byte> l = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(l, (ushort)Math.Min(65535, b.Length)); buf.AddRange(l.ToArray()); buf.AddRange(b.AsSpan(0, Math.Min(65535, b.Length)).ToArray()); }
    private static bool ReadU8String(ReadOnlySpan<byte> s, ref int o, out string v)
    { v = string.Empty; if (o >= s.Length) return false; int len = s[o++]; if (o + len > s.Length) return false; v = Encoding.UTF8.GetString(s.Slice(o, len)); o += len; return true; }
    private static bool ReadU16String(ReadOnlySpan<byte> s, ref int o, out string v)
    { v = string.Empty; if (o + 2 > s.Length) return false; ushort len = BinaryPrimitives.ReadUInt16BigEndian(s.Slice(o, 2)); o += 2; if (o + len > s.Length) return false; v = Encoding.UTF8.GetString(s.Slice(o, len)); o += len; return true; }
}
