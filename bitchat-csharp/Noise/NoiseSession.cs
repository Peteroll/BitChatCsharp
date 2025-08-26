using System;
using System.Security.Cryptography;
using NSec.Cryptography;

namespace Bitchat.Noise;

// Real session with X25519 ECDH (via NSec) + ChaCha20-Poly1305 for AEAD.
public sealed class NoiseSession : INoiseSession
{
    private Key? _ephKey;                 // Our ephemeral X25519 private key
    private byte[]? _ephPub;              // Our ephemeral public key (32B)
    private byte[]? _aeadKey;             // 32B symmetric key derived via HKDF

    public bool IsEstablished { get; private set; }
    public string PeerId { get; }
    public bool Initiated { get; private set; }

    public NoiseSession(string peerId)
    {
        PeerId = peerId;
        IsEstablished = false;
        Initiated = false;
    }

    public byte[] GetInitPayload()
    {
        Initiated = true;
        EnsureEphemeralKey();
        return _ephPub!;
    }

    public byte[]? ProcessHandshake(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 32) return null;
        EnsureEphemeralKey();

        // Import peer ephemeral public key
        var peerPub = PublicKey.Import(KeyAgreementAlgorithm.X25519, payload, KeyBlobFormat.RawPublicKey);

    using var shared = KeyAgreementAlgorithm.X25519.Agree(_ephKey!, peerPub);
        // Derive 32-byte AEAD key via HKDF-SHA256 (no salt/info for demo)
    var key = KeyDerivationAlgorithm.HkdfSha256.DeriveBytes(shared!, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, 32);
        _aeadKey = key;
        IsEstablished = true;

        if (!Initiated)
        {
            // Responder returns its public key to initiator
            return _ephPub;
        }
        return null;
    }

    public byte[]? Encrypt(ReadOnlySpan<byte> plaintext, out byte[] nonce, out byte[] tag)
    {
        nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        if (!IsEstablished || _aeadKey == null) { tag = Array.Empty<byte>(); return null; }
        using var aead = new System.Security.Cryptography.ChaCha20Poly1305(_aeadKey);
        var ct = new byte[plaintext.Length];
        tag = new byte[16];
        aead.Encrypt(nonce, plaintext, ct, tag, ReadOnlySpan<byte>.Empty);
        return ct;
    }

    public byte[]? Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> ciphertext)
    {
        if (!IsEstablished || _aeadKey == null) return null;
        using var aead = new System.Security.Cryptography.ChaCha20Poly1305(_aeadKey);
        var pt = new byte[ciphertext.Length];
        try
        {
            aead.Decrypt(nonce, ciphertext, tag, pt, ReadOnlySpan<byte>.Empty);
            return pt;
        }
        catch { return null; }
    }

    private void EnsureEphemeralKey()
    {
        if (_ephKey is not null) return;
        var kcp = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        _ephKey = new Key(KeyAgreementAlgorithm.X25519, kcp);
        _ephPub = _ephKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    }
}
