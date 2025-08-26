using System;

namespace Bitchat.Core;

// Runs both GATT Peripheral and GATT Central at once. Useful to match iOS dual role behavior.
public sealed class BluetoothGattDualTransport : IMeshTransport, IDisposable
{
    private readonly BluetoothGattTransport _peripheral;
    private readonly BluetoothGattClientTransport _central;

    public event Action<byte[]>? OnReceive;

    public BluetoothGattDualTransport(string? localName)
    {
        _peripheral = new BluetoothGattTransport(localName);
        _central = new BluetoothGattClientTransport();
        _peripheral.OnReceive += data => OnReceive?.Invoke(data);
        _central.OnReceive += data => OnReceive?.Invoke(data);
    }

    public void Send(byte[] data)
    {
        // Send via both roles to maximize reach (connected centrals and connected peripherals)
        _peripheral.Send(data);
        _central.Send(data);
    }

    public void Dispose()
    {
        try { _peripheral.Dispose(); } catch { }
        try { _central.Dispose(); } catch { }
    }
}
