using System;
using System.Threading;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Storage.Streams;

namespace Bitchat.Core;

// GATT Central transport (Windows-only). Scans for the iOS service and connects to its characteristic.
public sealed class BluetoothGattClientTransport : IMeshTransport, IDisposable
{
    private static readonly Guid ServiceUuid = new Guid("F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C");
    private static readonly Guid CharacteristicUuid = new Guid("A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D");

    private readonly BluetoothLEAdvertisementWatcher _watcher;
    private BluetoothLEDevice? _device;
    private GattCharacteristic? _ch;
    private readonly SemaphoreSlim _connLock = new(1,1);

    public event Action<byte[]>? OnReceive;

    public BluetoothGattClientTransport()
    {
        _watcher = new BluetoothLEAdvertisementWatcher
        {
            ScanningMode = BluetoothLEScanningMode.Active
        };
        _watcher.AdvertisementFilter.Advertisement.ServiceUuids.Add(ServiceUuid);
        _watcher.Received += OnAdv;
        _watcher.Start();
    }

    private async void OnAdv(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
    {
        // Connect once
        if (_ch != null) return;
        if (!_connLock.Wait(0)) return;
        try
        {
            Console.WriteLine($"[BLE] Found iOS peripheral {args.BluetoothAddress:X} RSSI {args.RawSignalStrengthInDBm} dBm");
            _device = await BluetoothLEDevice.FromBluetoothAddressAsync(args.BluetoothAddress);
            if (_device == null) return;
            var sRes = await _device.GetGattServicesForUuidAsync(ServiceUuid);
            if (sRes.Status != GattCommunicationStatus.Success || sRes.Services.Count == 0) return;
            var svc = sRes.Services[0];
            var cRes = await svc.GetCharacteristicsForUuidAsync(CharacteristicUuid);
            if (cRes.Status != GattCommunicationStatus.Success || cRes.Characteristics.Count == 0) return;
            _ch = cRes.Characteristics[0];
            _ch.ValueChanged += OnValueChanged;
            _ = await _ch.WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue.Notify);
            Console.WriteLine("[BLE] Connected and subscribed to notifications.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[BLE] Connect error: {ex.Message}");
        }
        finally { _connLock.Release(); }
    }

    private void OnValueChanged(GattCharacteristic sender, GattValueChangedEventArgs args)
    {
        byte[] data;
        using (var reader = DataReader.FromBuffer(args.CharacteristicValue))
        {
            data = new byte[args.CharacteristicValue.Length];
            reader.ReadBytes(data);
        }
        OnReceive?.Invoke(data);
    }

    public void Send(byte[] data)
    {
        var ch = _ch;
        if (ch == null) return;
        var writer = new DataWriter();
        writer.WriteBytes(data);
        var buffer = writer.DetachBuffer();
        try { _ = ch.WriteValueAsync(buffer, GattWriteOption.WriteWithoutResponse).AsTask().GetAwaiter().GetResult(); }
        catch { }
    }

    public void Dispose()
    {
        try { _watcher.Stop(); _watcher.Received -= OnAdv; } catch { }
        if (_ch != null) _ch.ValueChanged -= OnValueChanged;
        _device?.Dispose();
        _connLock.Dispose();
    }
}
