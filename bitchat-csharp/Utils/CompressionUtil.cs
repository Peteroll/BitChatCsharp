using System;
using K4os.Compression.LZ4;

namespace Bitchat.Protocol;

public static class CompressionUtil
{
    // Threshold similar to Swift policy
    public static bool ShouldCompress(ReadOnlySpan<byte> payload) => payload.Length > 256;

    public static byte[]? Compress(ReadOnlySpan<byte> payload)
    {
        try
        {
            // bound size as per LZ4 maximum
            int max = LZ4Codec.MaximumOutputSize(payload.Length);
            var buffer = new byte[max];
            int written = LZ4Codec.Encode(payload.ToArray(), 0, payload.Length, buffer, 0, buffer.Length);
            if (written <= 0 || written >= payload.Length) return null; // no benefit
            Array.Resize(ref buffer, written);
            return buffer;
        }
        catch { return null; }
    }

    public static byte[]? Decompress(ReadOnlySpan<byte> compressed, int originalSize)
    {
        var output = new byte[originalSize];
        try
        {
            int read = LZ4Codec.Decode(compressed.ToArray(), 0, compressed.Length, output, 0, output.Length);
            if (read != originalSize) return null;
            return output;
        }
        catch { return null; }
    }
}
