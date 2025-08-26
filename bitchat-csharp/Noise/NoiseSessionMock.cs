using System;
using System.Security.Cryptography;
using System.Collections.Generic;

namespace Bitchat.Noise;

// Minimal session using ephemeral random keying + ChaCha20-Poly1305 (PLACEHOLDER for real Noise/X25519).
public sealed class NoiseSessionMock : INoiseSession
{
    private byte[]? _sharedKey; // 32 bytes
    private byte[]? _priv;      // 32 bytes (placeholder secret)
    private byte[]? _pub;       // 32 bytes (placeholder public)

    public bool IsEstablished { get; private set; }
    public string PeerId { get; }
    public bool Initiated { get; private set; }

    public NoiseSessionMock(string peerId)
    {
        PeerId = peerId;
        IsEstablished = false;
        Initiated = false;
        // generate placeholder ephemeral
        _priv = RandomScalar();
        _pub = DerivePseudoPublic(_priv);
    }

    public byte[] GetInitPayload()
    {
        Initiated = true;
        return _pub!;
    }

    public byte[]? ProcessHandshake(ReadOnlySpan<byte> payload)
    {
        // payload = remote pseudo public key (32B)
        if (payload.Length != 32) return null;
        var remotePub = payload.ToArray();
        if (_priv == null) return null;
        _sharedKey = HkdfSha256(_priv, remotePub, 32);
        if (!Initiated)
        {
            // we're responder: send our pubkey back
            IsEstablished = true;
            return _pub;
        }
        else
        {
            // initiator: received responder key, now established, no response needed
            IsEstablished = true;
            return null;
        }
    }

    public byte[]? Encrypt(ReadOnlySpan<byte> plaintext, out byte[] nonce, out byte[] tag)
    {
        nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        if (!IsEstablished || _sharedKey == null) { tag = Array.Empty<byte>(); return null; }
        return AeadChaCha20Poly1305.Encrypt(plaintext, _sharedKey, nonce, ReadOnlySpan<byte>.Empty, out tag);
    }

    public byte[]? Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> ciphertext)
    {
        if (!IsEstablished || _sharedKey == null) return null;
        return AeadChaCha20Poly1305.Decrypt(ciphertext, _sharedKey, nonce, ReadOnlySpan<byte>.Empty, tag);
    }

    // X25519 helpers
    private static byte[] RandomScalar() { var s = new byte[32]; RandomNumberGenerator.Fill(s); return s; }
    private static byte[] DerivePseudoPublic(byte[] priv) { using var sha = SHA256.Create(); return sha.ComputeHash(priv)[..32]; }
    private static byte[] HkdfSha256(byte[] ikm, byte[] salt, int len)
    {
        using var hk = new HMACSHA256(salt);
        var prk = hk.ComputeHash(ikm);
        var t = Array.Empty<byte>();
        using var h2 = new HMACSHA256(prk);
        var okm = new List<byte>(len);
        byte counter = 1;
        while (okm.Count < len)
        {
            var input = new byte[t.Length + 1];
            Buffer.BlockCopy(t, 0, input, 0, t.Length);
            input[^1] = counter++;
            t = h2.ComputeHash(input);
            okm.AddRange(t);
        }
        return okm.GetRange(0, len).ToArray();
    }
}

internal static class AeadChaCha20Poly1305
{
    // .NET built-in ChaCha20Poly1305 exists in newer versions; here simulate via libsodium-like API using BCL
    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, out byte[] tag)
    {
        using var aead = new System.Security.Cryptography.ChaCha20Poly1305(key.ToArray());
        var ct = new byte[plaintext.Length];
        tag = new byte[16];
        aead.Encrypt(nonce, plaintext, ct, tag, aad);
        return ct;
    }
    public static byte[]? Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> tag)
    {
        using var aead = new System.Security.Cryptography.ChaCha20Poly1305(key.ToArray());
        var pt = new byte[ciphertext.Length];
        try { aead.Decrypt(nonce, ciphertext, tag, pt, aad); return pt; } catch { return null; }
    }
}
