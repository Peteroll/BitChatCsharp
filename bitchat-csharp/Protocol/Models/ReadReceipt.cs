using System;
using System.Buffers.Binary;
using System.Text;

namespace Bitchat.Protocol.Models;

public sealed class ReadReceipt
{
    public string OriginalMessageId { get; }
    public string ReceiptId { get; }
    public string ReaderId { get; }
    public string ReaderNickname { get; }
    public DateTime Timestamp { get; }

    public ReadReceipt(string originalMessageId, string readerId, string readerNickname)
    {
        OriginalMessageId = originalMessageId;
        ReceiptId = Guid.NewGuid().ToString();
        ReaderId = readerId;
        ReaderNickname = readerNickname;
        Timestamp = DateTime.UtcNow;
    }
    private ReadReceipt(string originalMessageId, string receiptId, string readerId, string readerNickname, DateTime ts)
    {
        OriginalMessageId = originalMessageId;
        ReceiptId = receiptId;
        ReaderId = readerId;
        ReaderNickname = readerNickname;
        Timestamp = ts;
    }

    public byte[] ToBinary()
    {
        var buf = new List<byte>();
        WriteUuid(buf, OriginalMessageId);
        WriteUuid(buf, ReceiptId);
        buf.AddRange(HexUtil.HexToFixed8(ReaderId));
        WriteDate(buf, Timestamp);
        WriteString(buf, ReaderNickname);
        return buf.ToArray();
    }

    public static bool TryFromBinary(ReadOnlySpan<byte> data, out ReadReceipt rr)
    {
        rr = default!;
        int o = 0;
        if (!ReadUuid(data, ref o, out var mid) || !ReadUuid(data, ref o, out var rid)) return false;
        if (!TryReadFixed(data, ref o, 8, out var reader)) return false;
        if (!ReadDate(data, ref o, out var ts)) return false;
        if (!ReadString(data, ref o, out var nick)) return false;
        rr = new ReadReceipt(mid, rid, Convert.ToHexString(reader), nick, ts);
        return true;
    }

    // shared helpers
    private static void WriteUuid(List<byte> buf, string id)
    { var g = Guid.TryParse(id, out var guid) ? guid : Guid.NewGuid(); buf.AddRange(g.ToByteArray()); }
    private static bool ReadUuid(ReadOnlySpan<byte> s, ref int o, out string id)
    { id = string.Empty; if (o + 16 > s.Length) return false; var g = new Guid(s.Slice(o, 16)); o += 16; id = g.ToString(); return true; }
    private static void WriteDate(List<byte> buf, DateTime dt)
    { var ms = (ulong)new DateTimeOffset(dt).ToUnixTimeMilliseconds(); Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, ms); buf.AddRange(b.ToArray()); }
    private static bool ReadDate(ReadOnlySpan<byte> s, ref int o, out DateTime dt)
    { dt = default; if (o + 8 > s.Length) return false; var ms = BinaryPrimitives.ReadUInt64BigEndian(s.Slice(o, 8)); o += 8; dt = DateTimeOffset.FromUnixTimeMilliseconds((long)ms).UtcDateTime; return true; }
    private static void WriteString(List<byte> buf, string str)
    { var b = Encoding.UTF8.GetBytes(str); buf.Add((byte)Math.Min(255, b.Length)); buf.AddRange(b.AsSpan(0, Math.Min(255, b.Length)).ToArray()); }
    private static bool ReadString(ReadOnlySpan<byte> s, ref int o, out string v)
    { v = string.Empty; if (o >= s.Length) return false; int len = s[o++]; if (o + len > s.Length) return false; v = Encoding.UTF8.GetString(s.Slice(o, len)); o += len; return true; }
    private static bool TryReadFixed(ReadOnlySpan<byte> s, ref int o, int len, out byte[] bytes)
    { bytes = Array.Empty<byte>(); if (o + len > s.Length) return false; bytes = s.Slice(o, len).ToArray(); o += len; return true; }
}
