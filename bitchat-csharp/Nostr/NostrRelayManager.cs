using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Bitchat.Nostr;

// Minimal Nostr relay client for subscribe/publish of a few kinds.
public sealed class NostrRelayManager : IDisposable
{
    private readonly List<Uri> _relays = new();
    private readonly ConcurrentDictionary<string, ClientWebSocket> _sockets = new();
    private readonly CancellationTokenSource _cts = new();

    public event Action<NostrEvent>? OnEvent;
    public event Action<string>? OnLog;

    public void AddRelay(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            _relays.Add(uri);
            _ = Task.Run(() => ConnectAndListen(uri, _cts.Token));
        }
    }

    public IReadOnlyList<string> GetRelays()
        => _relays.ConvertAll(r => r.ToString()).AsReadOnly();

    public bool RemoveRelay(string url)
    {
        var removed = false;
        for (int i = _relays.Count - 1; i >= 0; i--)
        {
            if (_relays[i].ToString().Equals(url, StringComparison.OrdinalIgnoreCase))
            {
                removed = true;
                _relays.RemoveAt(i);
            }
        }
        if (_sockets.TryRemove(url, out var ws))
        {
            try { ws.Abort(); ws.Dispose(); } catch { }
        }
        return removed;
    }

    public void ConnectRelay(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            _ = Task.Run(() => ConnectAndListen(uri, _cts.Token));
        }
    }

    public Task StartAsync()
    {
        foreach (var uri in _relays)
        {
            _ = Task.Run(() => ConnectAndListen(uri, _cts.Token));
        }
        return Task.CompletedTask;
    }

    private async Task ConnectAndListen(Uri uri, CancellationToken ct)
    {
        int attempt = 0;
        while (!ct.IsCancellationRequested)
        {
            var ws = new ClientWebSocket();
            try
            {
                await ws.ConnectAsync(uri, ct);
                attempt = 0;
                _sockets[uri.ToString()] = ws;
                OnLog?.Invoke($"[Nostr] Connected {uri}");

                // Send a simple subscription to kinds 0 and 30315 (example mapping)
                var subId = Guid.NewGuid().ToString("N");
                var filter = new { kinds = new[] { 0, 30315 } }; // profile + our custom mapping kind
                var subMsg = JsonSerializer.Serialize(new object[] { "REQ", subId, filter });
                await SendAsync(ws, subMsg, ct);

                var buffer = new byte[8192];
                while (!ct.IsCancellationRequested && ws.State == WebSocketState.Open)
                {
                    var seg = new ArraySegment<byte>(buffer);
                    var res = await ws.ReceiveAsync(seg, ct);
                    if (res.MessageType == WebSocketMessageType.Close) break;
                    var json = Encoding.UTF8.GetString(buffer, 0, res.Count);
                    try
                    {
                        var doc = JsonDocument.Parse(json);
                        if (doc.RootElement.ValueKind == JsonValueKind.Array && doc.RootElement.GetArrayLength() >= 3)
                        {
                            var type = doc.RootElement[0].GetString();
                            if (type == "EVENT")
                            {
                                var ev = doc.RootElement[2];
                                var ne = new NostrEvent
                                {
                                    Id = ev.GetProperty("id").GetString() ?? string.Empty,
                                    PubKey = ev.GetProperty("pubkey").GetString() ?? string.Empty,
                                    CreatedAt = ev.GetProperty("created_at").GetInt64(),
                                    Kind = ev.GetProperty("kind").GetInt32(),
                                    Content = ev.GetProperty("content").GetString() ?? string.Empty,
                                    Sig = ev.GetProperty("sig").GetString() ?? string.Empty,
                                };
                                OnEvent?.Invoke(ne);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        OnLog?.Invoke($"[Nostr] Parse error: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                OnLog?.Invoke($"[Nostr] WS error {uri}: {ex.Message}");
            }
            finally
            {
                try { ws.Dispose(); } catch { }
                _sockets.TryRemove(uri.ToString(), out _);
            }

            // backoff then retry
            attempt++;
            var delay = Math.Min(30000, 1000 * attempt);
            try { await Task.Delay(delay, ct); } catch { }
        }
    }

    public async Task PublishAsync(NostrEvent ev, CancellationToken ct = default)
    {
        var json = JsonSerializer.Serialize(new object[] { "EVENT", new
        {
            id = ev.Id, pubkey = ev.PubKey, created_at = ev.CreatedAt,
            kind = ev.Kind, tags = ev.Tags, content = ev.Content, sig = ev.Sig
        }});
        foreach (var ws in _sockets.Values)
        {
            if (ws.State == WebSocketState.Open)
                await SendAsync(ws, json, ct);
        }
    }

    private static Task SendAsync(ClientWebSocket ws, string s, CancellationToken ct)
        => ws.SendAsync(Encoding.UTF8.GetBytes(s), WebSocketMessageType.Text, true, ct);

    public void Dispose()
    {
        _cts.Cancel();
        foreach (var kv in _sockets) kv.Value.Abort();
        _cts.Dispose();
    }
}
