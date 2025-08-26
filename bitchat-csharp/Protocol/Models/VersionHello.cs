using System;
using System.Buffers.Binary;
using System.Text;

namespace Bitchat.Protocol.Models;

public sealed class VersionHello
{
    public byte[] SupportedVersions { get; }
    public byte PreferredVersion { get; }
    public string ClientVersion { get; }
    public string Platform { get; }
    public string[]? Capabilities { get; }

    public VersionHello(byte[]? supportedVersions, byte preferredVersion, string clientVersion, string platform, string[]? capabilities = null)
    { SupportedVersions = supportedVersions ?? new byte[] { ProtocolVersion.Current }; PreferredVersion = preferredVersion; ClientVersion = clientVersion; Platform = platform; Capabilities = capabilities; }

    public byte[] ToBinary()
    {
        var buf = new List<byte>();
        byte flags = 0; if (Capabilities != null) flags |= 0x01; buf.Add(flags);
        buf.Add((byte)Math.Min(255, SupportedVersions.Length));
        buf.AddRange(SupportedVersions.AsSpan(0, Math.Min(255, SupportedVersions.Length)).ToArray());
        buf.Add(PreferredVersion);
        WriteString(buf, ClientVersion);
        WriteString(buf, Platform);
        if (Capabilities != null)
        {
            buf.Add((byte)Math.Min(255, Capabilities.Length));
            foreach (var c in Capabilities.AsSpan(0, Math.Min(255, Capabilities.Length)).ToArray()) WriteString(buf, c);
        }
        return buf.ToArray();
    }

    public static bool TryFromBinary(ReadOnlySpan<byte> s, out VersionHello vh)
    {
        vh = default!; int o = 0; if (s.Length < 4) return false;
        byte flags = s[o++]; bool hasCaps = (flags & 0x01) != 0;
        if (o >= s.Length) return false; int count = s[o++];
        if (o + count > s.Length) return false; var vers = s.Slice(o, count).ToArray(); o += count;
        if (o >= s.Length) return false; byte pref = s[o++];
        if (!ReadString(s, ref o, out var client) || !ReadString(s, ref o, out var platform)) return false;
        string[]? caps = null;
        if (hasCaps)
        {
            if (o >= s.Length) return false; int c = s[o++]; caps = new string[c];
            for (int i = 0; i < c; i++) { if (!ReadString(s, ref o, out var cap)) return false; caps[i] = cap; }
        }
        vh = new VersionHello(vers, pref, client, platform, caps); return true;
    }

    private static void WriteString(List<byte> buf, string s)
    { var b = Encoding.UTF8.GetBytes(s); buf.Add((byte)Math.Min(255, b.Length)); buf.AddRange(b.AsSpan(0, Math.Min(255, b.Length)).ToArray()); }
    private static bool ReadString(ReadOnlySpan<byte> s, ref int o, out string v)
    { v = string.Empty; if (o >= s.Length) return false; int len = s[o++]; if (o + len > s.Length) return false; v = Encoding.UTF8.GetString(s.Slice(o, len)); o += len; return true; }
}
