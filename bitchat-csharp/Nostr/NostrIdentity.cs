using System;
using System.Text.Json;

namespace Bitchat.Nostr;

public sealed class NostrIdentity
{
    public string PubKeyHex { get; init; } = string.Empty; // hex-encoded 32 bytes (secp256k1)
    public string? Name { get; init; }
    public string? About { get; init; }
    public string? Picture { get; init; }

    public static NostrIdentity FromKind0ProfileJson(string content)
    {
        try
        {
            var doc = JsonDocument.Parse(content);
            var root = doc.RootElement;
            return new NostrIdentity
            {
                Name = root.TryGetProperty("name", out var n) ? n.GetString() : null,
                About = root.TryGetProperty("about", out var a) ? a.GetString() : null,
                Picture = root.TryGetProperty("picture", out var p) ? p.GetString() : null,
            };
        }
        catch
        {
            return new NostrIdentity();
        }
    }
}
