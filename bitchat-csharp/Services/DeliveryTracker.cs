using System;
using System.Collections.Concurrent;
using System.Threading;
using Bitchat.Protocol;
using Bitchat.Utils;

namespace Bitchat.Services;

public sealed class DeliveryTracker : IDisposable
{
    private sealed class Entry
    {
        public string PacketId = string.Empty;
        public byte[] Bytes = Array.Empty<byte>();
        public int Attempts = 0;
        public DateTime NextAttempt;
        public bool Delivered = false;
    }

    private readonly ConcurrentDictionary<string, Entry> _pending = new();
    private readonly Timer _timer;
    private readonly Action<byte[]> _send;
    private readonly int _maxAttempts;
    private readonly TimeSpan _baseRetry;

    public DeliveryTracker(Action<byte[]> send, int maxAttempts = 5, int baseRetryMs = 1500)
    {
        _send = send;
        _maxAttempts = maxAttempts;
        _baseRetry = TimeSpan.FromMilliseconds(baseRetryMs);
        _timer = new Timer(_ => Tick(), null, _baseRetry, TimeSpan.FromMilliseconds(500));
    }

    public void Track(BitchatPacket packet, byte[] encoded)
    {
        var id = PacketId.Compute(packet);
        var e = new Entry
        {
            PacketId = id,
            Bytes = encoded,
            Attempts = 0,
            NextAttempt = DateTime.UtcNow + _baseRetry,
            Delivered = false
        };
        _pending[id] = e;
    }

    public void Ack(string originalPacketId)
    {
        if (_pending.TryRemove(originalPacketId, out _)) { /* delivered */ }
    }

    private void Tick()
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _pending)
        {
            var e = kv.Value;
            if (e.Delivered) continue;
            if (e.Attempts >= _maxAttempts) { _pending.TryRemove(kv.Key, out _); continue; }
            if (e.NextAttempt <= now)
            {
                e.Attempts++;
                e.NextAttempt = now + TimeSpan.FromMilliseconds(_baseRetry.TotalMilliseconds * Math.Pow(2, e.Attempts - 1));
                _send(e.Bytes);
            }
        }
    }

    public void Dispose()
    {
        _timer.Dispose();
        _pending.Clear();
    }
}
