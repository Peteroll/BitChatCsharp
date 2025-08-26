using System;
using System.Security.Cryptography;

namespace Bitchat.Protocol;

public static class MessagePadding
{
    private static readonly int[] BlockSizes = { 256, 512, 1024, 2048 };

    public static int OptimalBlockSize(int dataSize)
    {
        var total = dataSize + 16; // AEAD tag allowance similar to Swift comment
        foreach (var b in BlockSizes)
            if (total <= b) return b;
        return dataSize; // large messages likely fragmented elsewhere
    }

    public static byte[] Pad(byte[] data, int targetSize)
    {
        if (data.Length >= targetSize) return (byte[])data.Clone();
        int paddingNeeded = targetSize - data.Length;
        if (paddingNeeded > 255) return (byte[])data.Clone(); // follow Swift safeguard
        var output = new byte[targetSize];
        Buffer.BlockCopy(data, 0, output, 0, data.Length);
        // PKCS#7-like: fill padding-1 bytes random, last byte = padding length
        if (paddingNeeded > 1)
        {
            var rand = new byte[paddingNeeded - 1];
            RandomNumberGenerator.Fill(rand);
            Buffer.BlockCopy(rand, 0, output, data.Length, rand.Length);
        }
        output[targetSize - 1] = (byte)paddingNeeded;
        return output;
    }

    public static byte[] Unpad(byte[] data)
    {
        if (data.Length == 0) return Array.Empty<byte>();
        int padLen = data[data.Length - 1];
        if (padLen <= 0 || padLen > data.Length) return (byte[])data.Clone();
        var output = new byte[data.Length - padLen];
        Buffer.BlockCopy(data, 0, output, 0, output.Length);
        return output;
    }
}
