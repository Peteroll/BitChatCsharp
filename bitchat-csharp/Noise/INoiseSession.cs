using System;

namespace Bitchat.Noise;

public interface INoiseSession
{
    bool IsEstablished { get; }
    string PeerId { get; }
    bool Initiated { get; }

    // Produce our handshake-init payload (ephemeral public key)
    byte[] GetInitPayload();

    // Process handshake payload. Returns optional response payload to send back.
    byte[]? ProcessHandshake(ReadOnlySpan<byte> payload);

    // Encrypt/Decrypt once established. Return null on failure/not established.
    byte[]? Encrypt(ReadOnlySpan<byte> plaintext, out byte[] nonce, out byte[] tag);
    byte[]? Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> ciphertext);
}
