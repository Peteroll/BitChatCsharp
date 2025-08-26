using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Storage.Streams;

namespace Bitchat.Core;

// BLE advertisement-based broadcast transport (Windows-only). Frames are reassembled before delivering to OnReceive.
public sealed class BluetoothBleTransport : IMeshTransport, IDisposable
{
    private static readonly Guid ServiceUuid = new Guid("F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C");
    private static readonly Guid CharacteristicUuid = new Guid("A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D");
    private const ushort CompanyId = 0xFFFE; // development/testing only
    private const byte Proto = 0x42;         // protocol marker
    private const int MaxChunk = 18;         // conservative payload per adv frame

    private readonly BluetoothLEAdvertisementWatcher _watcher;
    private readonly BluetoothLEAdvertisementPublisher _publisher;
    private readonly ConcurrentDictionary<string, AdvSession> _sessions = new();
    private readonly Timer _cleanupTimer;

    public event Action<byte[]>? OnReceive;

    public BluetoothBleTransport()
    {
    _watcher = new BluetoothLEAdvertisementWatcher
        {
            ScanningMode = BluetoothLEScanningMode.Active
        };
    // Filter for our service UUID (iOS app advertises this when acting as peripheral)
    try { _watcher.AdvertisementFilter.Advertisement.ServiceUuids.Add(ServiceUuid); } catch { }
        _watcher.Received += OnAdvReceived;
        _watcher.Start();

        _publisher = new BluetoothLEAdvertisementPublisher();

        _cleanupTimer = new Timer(_ => Cleanup(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    public void Send(byte[] data)
    {
        // Fragment 'data' into advertisement frames
        var id = new byte[8];
        Random.Shared.NextBytes(id);
        int total = (data.Length + MaxChunk - 1) / MaxChunk;
        for (int i = 0; i < total; i++)
        {
            int start = i * MaxChunk;
            int len = Math.Min(MaxChunk, data.Length - start);
            var payload = new byte[1 + 8 + 2 + 2 + len];
            int o = 0;
            payload[o++] = Proto;
            System.Buffer.BlockCopy(id, 0, payload, o, 8); o += 8;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(o, 2), (ushort)i); o += 2;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(o, 2), (ushort)total); o += 2;
            System.Buffer.BlockCopy(data, start, payload, o, len);

            PublishOnce(payload);
            Thread.Sleep(25); // small spacing to reduce collisions
        }
    }

    private void PublishOnce(byte[] manufacturerPayload)
    {
    // Update publisher's advertisement manufacturer data
    var writer = new DataWriter();
    writer.WriteBytes(manufacturerPayload);
    IBuffer buffer = writer.DetachBuffer();
    var md = new BluetoothLEManufacturerData(CompanyId, buffer);
    var adv = _publisher.Advertisement;
    // Advertise our Service UUID so iOS can discover us by service
    adv.ServiceUuids.Clear();
    adv.ServiceUuids.Add(ServiceUuid);
    adv.ManufacturerData.Clear();
    adv.ManufacturerData.Add(md);
    _publisher.Start();
        // short advertise window
        Thread.Sleep(15);
        _publisher.Stop();
    }

    private void OnAdvReceived(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
    {
        // Discovery log for iOS peer advertising the service UUID
        foreach (var su in args.Advertisement.ServiceUuids)
        {
            if (su == ServiceUuid)
            {
                Console.WriteLine($"[BLE] Seen peer advertising service {ServiceUuid} @ RSSI {args.RawSignalStrengthInDBm} dBm");
                break;
            }
        }

        foreach (var md in args.Advertisement.ManufacturerData)
        {
            if (md.CompanyId != CompanyId) continue;
            // Extract bytes from IBuffer
            byte[] buf;
            using (var reader = DataReader.FromBuffer(md.Data))
            {
                buf = new byte[md.Data.Length];
                reader.ReadBytes(buf);
            }
            if (buf.Length < 1 + 8 + 2 + 2) continue;
            if (buf[0] != Proto) continue;
            var fid = Convert.ToHexString(buf.AsSpan(1, 8));
            int index = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(9, 2));
            int total = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(11, 2));
            var chunk = buf.Length > 13 ? buf.AsSpan(13).ToArray() : Array.Empty<byte>();

            var sess = _sessions.GetOrAdd(fid, _ => new AdvSession(total));
            sess.Add(index, chunk);
            if (sess.IsComplete())
            {
                if (_sessions.TryRemove(fid, out var s))
                {
                    var data = s.Concat();
                    OnReceive?.Invoke(data);
                }
            }
        }
    }

    private void Cleanup()
    {
        var cutoff = DateTime.UtcNow - TimeSpan.FromSeconds(30);
        foreach (var kv in _sessions)
        {
            if (kv.Value.Started < cutoff)
                _sessions.TryRemove(kv.Key, out _);
        }
    }

    public void Dispose()
    {
        _watcher.Stop();
        _watcher.Received -= OnAdvReceived;
        _publisher.Stop();
        _cleanupTimer.Dispose();
    }

    private sealed class AdvSession
    {
        private readonly byte[][] _parts;
        public DateTime Started { get; } = DateTime.UtcNow;

        public AdvSession(int total)
        {
            _parts = new byte[total][];
        }

        public void Add(int index, byte[] data)
        {
            if (index >= 0 && index < _parts.Length && _parts[index] == null)
                _parts[index] = data;
        }

        public bool IsComplete()
        {
            for (int i = 0; i < _parts.Length; i++) if (_parts[i] == null) return false;
            return true;
        }

        public byte[] Concat()
        {
            int len = 0; foreach (var p in _parts) len += p.Length;
            var res = new byte[len];
            int o = 0; foreach (var p in _parts) { System.Buffer.BlockCopy(p, 0, res, o, p.Length); o += p.Length; }
            return res;
        }
    }
}
