using System;
using System.Security.Cryptography;
using System.Text;
using Bitchat.Protocol;

namespace Bitchat.Utils;

public static class PacketId
{
    public static string Compute(BitchatPacket packet)
    {
        using var sha = SHA256.Create();
        // Hash selected stable fields
        var bytes = new List<byte>();
        bytes.Add(packet.Version);
        bytes.Add((byte)packet.Type);
        bytes.AddRange(packet.SenderId);
        if (packet.RecipientId != null) bytes.AddRange(packet.RecipientId);
        // timestamp and ttl
        bytes.AddRange(BitConverter.GetBytes(packet.Timestamp));
        bytes.Add(packet.Ttl);
        bytes.AddRange(packet.Payload);
        if (packet.Signature != null) bytes.AddRange(packet.Signature);
        var hash = sha.ComputeHash(bytes.ToArray());
        // Use first 16 bytes as GUID
        Span<byte> guidBytes = stackalloc byte[16];
        hash.AsSpan(0, 16).CopyTo(guidBytes);
        var guid = new Guid(guidBytes);
        return guid.ToString();
    }
}
