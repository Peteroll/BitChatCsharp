using System;
using System.Buffers.Binary;
using System.Text;

namespace Bitchat.Protocol.Models;

public sealed class VersionAck
{
    public byte AgreedVersion { get; }
    public string ServerVersion { get; }
    public string Platform { get; }
    public string[]? Capabilities { get; }
    public bool Rejected { get; }
    public string? Reason { get; }

    public VersionAck(byte agreedVersion, string serverVersion, string platform, string[]? capabilities = null, bool rejected = false, string? reason = null)
    { AgreedVersion = agreedVersion; ServerVersion = serverVersion; Platform = platform; Capabilities = capabilities; Rejected = rejected; Reason = reason; }

    public byte[] ToBinary()
    {
        var buf = new List<byte>();
        byte flags = 0; if (Capabilities != null) flags |= 0x01; if (Reason != null) flags |= 0x02; buf.Add(flags);
        buf.Add(AgreedVersion);
        WriteString(buf, ServerVersion);
        WriteString(buf, Platform);
        buf.Add(Rejected ? (byte)1 : (byte)0);
        if (Capabilities != null)
        { buf.Add((byte)Math.Min(255, Capabilities.Length)); foreach (var c in Capabilities.AsSpan(0, Math.Min(255, Capabilities.Length)).ToArray()) WriteString(buf, c); }
        if (Reason != null) WriteString(buf, Reason);
        return buf.ToArray();
    }

    public static bool TryFromBinary(ReadOnlySpan<byte> s, out VersionAck va)
    {
        va = default!; int o = 0; if (s.Length < 5) return false;
        byte flags = s[o++]; bool hasCaps = (flags & 0x01) != 0, hasReason = (flags & 0x02) != 0;
        byte agreed = s[o++];
        if (!ReadString(s, ref o, out var server) || !ReadString(s, ref o, out var platform)) return false;
        if (o >= s.Length) return false; bool rejected = s[o++] != 0;
        string[]? caps = null; if (hasCaps) { if (o >= s.Length) return false; int c = s[o++]; caps = new string[c]; for (int i = 0; i < c; i++) { if (!ReadString(s, ref o, out var cap)) return false; caps[i] = cap; } }
        string? reason = null; if (hasReason) { if (!ReadString(s, ref o, out reason)) return false; }
        va = new VersionAck(agreed, server, platform, caps, rejected, reason); return true;
    }

    private static void WriteString(List<byte> buf, string s)
    { var b = Encoding.UTF8.GetBytes(s); buf.Add((byte)Math.Min(255, b.Length)); buf.AddRange(b.AsSpan(0, Math.Min(255, b.Length)).ToArray()); }
    private static bool ReadString(ReadOnlySpan<byte> s, ref int o, out string v)
    { v = string.Empty; if (o >= s.Length) return false; int len = s[o++]; if (o + len > s.Length) return false; v = Encoding.UTF8.GetString(s.Slice(o, len)); o += len; return true; }
}
