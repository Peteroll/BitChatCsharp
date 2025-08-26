using System;
using System.Text.Json;
using Bitchat.Nostr;

namespace Bitchat.NostrInterop;

// Maps between BitChat identity announcement <-> Nostr events
public static class NostrProtocolMapper
{
    // Choose a custom kind for NoiseIdentityAnnouncement; using 30315 as an example vendor-specific kind
    public const int KindNoiseIdentity = 30315;

    public static NostrEvent ToNostr(Bitchat.Protocol.Models.NoiseIdentityAnnouncement nia)
    {
        var contentObj = new
        {
            peerId = nia.PeerId,
            x25519 = Convert.ToHexString(nia.PublicKey),
            ed25519 = Convert.ToHexString(nia.SigningPublicKey),
            nickname = nia.Nickname,
            timestamp = new DateTimeOffset(nia.Timestamp).ToUnixTimeMilliseconds(),
            previousPeerId = nia.PreviousPeerId,
            signature = Convert.ToHexString(nia.Signature)
        };
        return new NostrEvent
        {
            Kind = KindNoiseIdentity,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Content = JsonSerializer.Serialize(contentObj)
        };
    }

    public static bool TryFromNostr(NostrEvent ev, out Bitchat.Protocol.Models.NoiseIdentityAnnouncement nia)
    {
        nia = default!;
        if (ev.Kind != KindNoiseIdentity) return false;
        try
        {
            var doc = JsonDocument.Parse(ev.Content);
            var root = doc.RootElement;
            var peerId = root.GetProperty("peerId").GetString() ?? string.Empty;
            var x25519 = Convert.FromHexString(root.GetProperty("x25519").GetString() ?? string.Empty);
            var ed25519 = Convert.FromHexString(root.GetProperty("ed25519").GetString() ?? string.Empty);
            var nickname = root.GetProperty("nickname").GetString() ?? string.Empty;
            var tsMs = root.GetProperty("timestamp").GetInt64();
            var prev = root.TryGetProperty("previousPeerId", out var pr) ? pr.GetString() : null;
            var sig = Convert.FromHexString(root.GetProperty("signature").GetString() ?? string.Empty);
            nia = new Bitchat.Protocol.Models.NoiseIdentityAnnouncement(peerId, x25519, ed25519, nickname,
                DateTimeOffset.FromUnixTimeMilliseconds(tsMs).UtcDateTime, prev, sig);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
