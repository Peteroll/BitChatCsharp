using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Bitchat.Nostr;

public sealed class NostrEvent
{
    public string Id { get; set; } = string.Empty;          // 32-byte hex
    public string PubKey { get; set; } = string.Empty;      // 32-byte hex
    public long CreatedAt { get; set; }                     // unix seconds
        = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    public int Kind { get; set; }
        = 1;
    public List<string[]> Tags { get; set; } = new();
    public string Content { get; set; } = string.Empty;
    public string Sig { get; set; } = string.Empty;         // 64-byte hex (BIP340)

    public static string SerializeUnsigned(NostrEvent e)
    {
        // NIP-01 serialization array: [0, pubkey, created_at, kind, tags, content]
        var arr = new object[] { 0, e.PubKey, e.CreatedAt, e.Kind, e.Tags, e.Content };
        return JsonSerializer.Serialize(arr);
    }

    public static string ComputeId(NostrEvent e)
    {
        var ser = SerializeUnsigned(e);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(ser));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public string ToJson()
    {
        var obj = new
        {
            id = Id,
            pubkey = PubKey,
            created_at = CreatedAt,
            kind = Kind,
            tags = Tags,
            content = Content,
            sig = Sig
        };
        return JsonSerializer.Serialize(obj);
    }
}
