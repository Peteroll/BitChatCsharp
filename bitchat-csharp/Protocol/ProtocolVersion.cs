namespace Bitchat.Protocol;

public static class ProtocolVersion
{
    public const byte Current = 1;
    public const byte Minimum = 1;
    public const byte Maximum = 1;

    private static readonly HashSet<byte> SupportedVersions = new() { 1 };

    public static bool IsSupported(byte v) => SupportedVersions.Contains(v);

    public static byte? NegotiateVersion(IEnumerable<byte> client, IEnumerable<byte> server)
    {
        var common = new HashSet<byte>(client);
        common.IntersectWith(server);
        return common.Count == 0 ? null : common.Max();
    }
}
