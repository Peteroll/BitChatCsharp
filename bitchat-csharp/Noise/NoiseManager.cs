using System;
using System.Collections.Concurrent;
using Bitchat.Protocol;

namespace Bitchat.Noise;

// Coordinates per-peer sessions. Real version should perform X25519 + AEAD; this mock is plumbing only.
public sealed class NoiseManager
{
    private readonly ConcurrentDictionary<string, INoiseSession> _sessions = new();

    public INoiseSession GetOrCreate(string peerId)
    {
        return _sessions.GetOrAdd(peerId, id => new NoiseSession(id));
    }

    public bool TryGet(string peerId, out INoiseSession session) => _sessions.TryGetValue(peerId, out session!);
}
