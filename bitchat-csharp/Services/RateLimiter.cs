using System;
using System.Threading;

namespace Bitchat.Services;

public sealed class RateLimiter
{
    private readonly int _capacity;
    private readonly double _refillPerMs;
    private double _tokens;
    private long _lastTick;

    public RateLimiter(int permitsPerSecond)
    {
        _capacity = Math.Max(1, permitsPerSecond);
        _refillPerMs = _capacity / 1000.0;
        _tokens = _capacity;
        _lastTick = Environment.TickCount64;
    }

    public bool TryAcquire()
    {
        var now = Environment.TickCount64;
        var elapsed = now - Interlocked.Exchange(ref _lastTick, now);
        if (elapsed < 0) elapsed = 0;
        _tokens = Math.Min(_capacity, _tokens + elapsed * _refillPerMs);
        if (_tokens >= 1.0)
        {
            _tokens -= 1.0;
            return true;
        }
        return false;
    }
}
