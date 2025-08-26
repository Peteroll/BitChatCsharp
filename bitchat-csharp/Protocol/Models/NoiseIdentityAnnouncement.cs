using System;
using System.Buffers.Binary;
using System.Text;

namespace Bitchat.Protocol.Models;

public sealed class NoiseIdentityAnnouncement
{
    public string PeerId { get; }
    public byte[] PublicKey { get; }
    public byte[] SigningPublicKey { get; }
    public string Nickname { get; }
    public DateTime Timestamp { get; }
    public string? PreviousPeerId { get; }
    public byte[] Signature { get; }

    public NoiseIdentityAnnouncement(string peerId, byte[] publicKey, byte[] signingPublicKey, string nickname, DateTime timestamp, string? previousPeerId, byte[] signature)
    { PeerId = peerId; PublicKey = publicKey; SigningPublicKey = signingPublicKey; Nickname = nickname.Trim(); Timestamp = timestamp; PreviousPeerId = previousPeerId; Signature = signature; }

    public byte[] ToBinary()
    {
        var buf = new List<byte>();
        byte flags = 0; if (PreviousPeerId != null) flags |= 0x01; buf.Add(flags);
        buf.AddRange(Bitchat.Protocol.HexUtil.HexToFixed8(PeerId));
        WriteData(buf, PublicKey);
        WriteData(buf, SigningPublicKey);
        WriteString(buf, Nickname);
        WriteDate(buf, Timestamp);
        if (PreviousPeerId != null) buf.AddRange(Bitchat.Protocol.HexUtil.HexToFixed8(PreviousPeerId));
        WriteData(buf, Signature);
        return buf.ToArray();
    }

    public static bool TryFromBinary(ReadOnlySpan<byte> s, out NoiseIdentityAnnouncement nia)
    {
        nia = default!; int o = 0;
        if (o >= s.Length) return false; byte flags = s[o++]; bool hasPrev = (flags & 0x01) != 0;
        if (o + 8 > s.Length) return false; var peer = s.Slice(o, 8).ToArray(); o += 8;
        if (!ReadData(s, ref o, out var pub) || !ReadData(s, ref o, out var sign)) return false;
        if (!ReadString(s, ref o, out var nick)) return false;
        if (!ReadDate(s, ref o, out var ts)) return false;
        string? prev = null; if (hasPrev) { if (o + 8 > s.Length) return false; prev = Convert.ToHexString(s.Slice(o, 8)); o += 8; }
        if (!ReadData(s, ref o, out var sig)) return false;
        nia = new NoiseIdentityAnnouncement(Convert.ToHexString(peer), pub, sign, nick.Trim(), ts, prev, sig); return true;
    }

    // helpers
    private static void WriteData(List<byte> buf, byte[] data)
    { Span<byte> l = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(l, (ushort)data.Length); buf.AddRange(l.ToArray()); buf.AddRange(data); }
    private static bool ReadData(ReadOnlySpan<byte> s, ref int o, out byte[] data)
    { data = Array.Empty<byte>(); if (o + 2 > s.Length) return false; ushort len = BinaryPrimitives.ReadUInt16BigEndian(s.Slice(o, 2)); o += 2; if (o + len > s.Length) return false; data = s.Slice(o, len).ToArray(); o += len; return true; }
    private static void WriteString(List<byte> buf, string str)
    { var b = Encoding.UTF8.GetBytes(str); Span<byte> l = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(l, (ushort)b.Length); buf.AddRange(l.ToArray()); buf.AddRange(b); }
    private static bool ReadString(ReadOnlySpan<byte> s, ref int o, out string value)
    { value = string.Empty; if (o + 2 > s.Length) return false; ushort len = BinaryPrimitives.ReadUInt16BigEndian(s.Slice(o, 2)); o += 2; if (o + len > s.Length) return false; value = Encoding.UTF8.GetString(s.Slice(o, len)); o += len; return true; }
    private static void WriteDate(List<byte> buf, DateTime dt)
    { var ms = (ulong)new DateTimeOffset(dt).ToUnixTimeMilliseconds(); Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, ms); buf.AddRange(b.ToArray()); }
    private static bool ReadDate(ReadOnlySpan<byte> s, ref int o, out DateTime dt)
    { dt = default; if (o + 8 > s.Length) return false; var ms = BinaryPrimitives.ReadUInt64BigEndian(s.Slice(o, 8)); o += 8; dt = DateTimeOffset.FromUnixTimeMilliseconds((long)ms).UtcDateTime; return true; }
}
