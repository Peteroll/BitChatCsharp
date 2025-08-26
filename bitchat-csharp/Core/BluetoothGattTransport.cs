using System;
using System.Collections.Generic;
using System.Threading;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Storage.Streams;

namespace Bitchat.Core;

// GATT Peripheral transport (Windows-only). Exposes the same Service/Characteristic UUIDs as the iOS app.
public sealed class BluetoothGattTransport : IMeshTransport, IDisposable
{
    private static readonly Guid ServiceUuid = new Guid("F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C");
    private static readonly Guid CharacteristicUuid = new Guid("A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D");

    private readonly GattServiceProvider _provider;
    private readonly GattLocalCharacteristic _characteristic;
    private readonly Timer _advRefreshTimer;
    private readonly BluetoothLEAdvertisementPublisher? _publisher; // to set LocalName (peerID) for iOS discovery

    public event Action<byte[]>? OnReceive;

    public BluetoothGattTransport(string? localName = null)
    {
        var create = GattServiceProvider.CreateAsync(ServiceUuid).AsTask().GetAwaiter().GetResult();
        if (create.Error != BluetoothError.Success || create.ServiceProvider is null)
            throw new InvalidOperationException("Failed to create GATT service provider");
        _provider = create.ServiceProvider;

        var charParams = new GattLocalCharacteristicParameters
        {
            CharacteristicProperties = GattCharacteristicProperties.Read | GattCharacteristicProperties.Write | GattCharacteristicProperties.WriteWithoutResponse | GattCharacteristicProperties.Notify,
            WriteProtectionLevel = GattProtectionLevel.Plain,
            ReadProtectionLevel = GattProtectionLevel.Plain,
            UserDescription = "BitChat"
        };
        var cRes = _provider.Service.CreateCharacteristicAsync(CharacteristicUuid, charParams).AsTask().GetAwaiter().GetResult();
        if (cRes.Error != BluetoothError.Success || cRes.Characteristic is null)
            throw new InvalidOperationException("Failed to create GATT characteristic");
        _characteristic = cRes.Characteristic;
        _characteristic.WriteRequested += OnWriteRequested;
        _characteristic.ReadRequested += OnReadRequested;

        var advParams = new GattServiceProviderAdvertisingParameters
        {
            IsConnectable = true,
            IsDiscoverable = true
        };
        _provider.StartAdvertising(advParams);

        // Optional concurrent advertiser to include LocalName (peerID) + Service UUID (helps iOS discover + parse peerID)
        if (!string.IsNullOrWhiteSpace(localName))
        {
            _publisher = new BluetoothLEAdvertisementPublisher();
            _publisher.Advertisement.ServiceUuids.Add(ServiceUuid);
            _publisher.Advertisement.LocalName = localName;
            try { _publisher.Start(); } catch { }
        }

        // Refresh advertising periodically to keep presence visible
        _advRefreshTimer = new Timer(_ =>
        {
            try { _provider.StopAdvertising(); _provider.StartAdvertising(advParams); } catch { }
        }, null, TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(2));
    }

    private async void OnReadRequested(GattLocalCharacteristic sender, GattReadRequestedEventArgs args)
    {
        var deferral = args.GetDeferral();
        try
        {
            var request = await args.GetRequestAsync();
            if (request == null) return;
            // Minimal read response (empty payload) – iOS expects characteristic to be readable per its props
            var writer = new DataWriter();
            // Optionally include a short banner/version in future
            request.RespondWithValue(writer.DetachBuffer());
        }
        catch { }
        finally { deferral.Complete(); }
    }

    private async void OnWriteRequested(GattLocalCharacteristic sender, GattWriteRequestedEventArgs args)
    {
        var deferral = args.GetDeferral();
        try
        {
            var req = await args.GetRequestAsync();
            if (req == null) return;
            var buf = req.Value;
            byte[] data;
            using (var reader = DataReader.FromBuffer(buf))
            {
                data = new byte[buf.Length];
                reader.ReadBytes(data);
            }
            // Accept write
            req.Respond();
            OnReceive?.Invoke(data);
        }
        catch { }
        finally { deferral.Complete(); }
    }

    public void Send(byte[] data)
    {
        // Notify all subscribed centrals
        var clients = _characteristic.SubscribedClients;
        if (clients == null || clients.Count == 0) return;
        var writer = new DataWriter();
        writer.WriteBytes(data);
        var buffer = writer.DetachBuffer();
        try
        {
            foreach (var client in clients)
            {
                _ = _characteristic.NotifyValueAsync(buffer, client).AsTask().GetAwaiter().GetResult();
            }
        }
        catch { }
    }

    public void Dispose()
    {
        try { _advRefreshTimer.Dispose(); } catch { }
        try { _provider.StopAdvertising(); } catch { }
        _characteristic.WriteRequested -= OnWriteRequested;
    _characteristic.ReadRequested -= OnReadRequested;
    try { _publisher?.Stop(); } catch { }
    }
}
