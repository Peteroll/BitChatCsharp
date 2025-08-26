using System;

namespace Bitchat.Protocol;

public static class HexUtil
{
    public static byte[] HexToFixed8(ReadOnlySpan<char> hex)
    {
        var outBytes = new byte[8];
        int idx = 0;
        for (int i = 0; i + 1 < hex.Length && idx < 8; i += 2)
        {
            if (byte.TryParse(hex.Slice(i, 2), System.Globalization.NumberStyles.HexNumber, null, out var b))
                outBytes[idx++] = b;
            else break;
        }
        return outBytes;
    }
}
