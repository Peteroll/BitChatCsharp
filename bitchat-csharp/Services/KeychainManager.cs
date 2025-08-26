using System;
using System.IO;
using System.Security.Cryptography;
using NSec.Cryptography;

namespace Bitchat.Services;

public sealed class KeychainManager
{
    private readonly string _dir;

    public KeychainManager(string appName = "bitchat-csharp")
    {
        _dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), appName, "keys");
        Directory.CreateDirectory(_dir);
    }

    public void StoreSecret(string name, byte[] data)
    {
        var path = Path.Combine(_dir, name + ".bin");
        byte[] toWrite;
#if WINDOWS
    toWrite = System.Security.Cryptography.ProtectedData.Protect(data, null, System.Security.Cryptography.DataProtectionScope.CurrentUser);
#else
        toWrite = data; // fallback: plaintext (consider using a cross-platform KMS)
#endif
        File.WriteAllBytes(path, toWrite);
    }

    public byte[]? LoadSecret(string name)
    {
        var path = Path.Combine(_dir, name + ".bin");
        if (!File.Exists(path)) return null;
        var enc = File.ReadAllBytes(path);
#if WINDOWS
    try { return System.Security.Cryptography.ProtectedData.Unprotect(enc, null, System.Security.Cryptography.DataProtectionScope.CurrentUser); } catch { return null; }
#else
        return enc; // plaintext fallback
#endif
    }

    public (PublicKey pub, Key priv) GetOrCreateEd25519(string name)
    {
        var curve = SignatureAlgorithm.Ed25519;
        var priv = LoadSecret(name);
        if (priv == null)
        {
            var key = new Key(curve, new KeyCreationParameters { ExportPolicy = NSec.Cryptography.KeyExportPolicies.AllowPlaintextExport });
            var privRaw = key.Export(NSec.Cryptography.KeyBlobFormat.RawPrivateKey);
            StoreSecret(name, privRaw);
            return (key.PublicKey, key);
        }
        else
        {
            var k = Key.Import(curve, priv, NSec.Cryptography.KeyBlobFormat.RawPrivateKey);
            return (k.PublicKey, k);
        }
    }

    public static bool VerifyEd25519(PublicKey pub, ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig)
    {
        return SignatureAlgorithm.Ed25519.Verify(pub, data, sig);
    }

    public (PublicKey pub, Key priv) GetOrCreateX25519(string name)
    {
        var alg = KeyAgreementAlgorithm.X25519;
        var priv = LoadSecret(name);
        if (priv == null)
        {
            var key = new Key(alg, new KeyCreationParameters { ExportPolicy = NSec.Cryptography.KeyExportPolicies.AllowPlaintextExport });
            var privRaw = key.Export(NSec.Cryptography.KeyBlobFormat.RawPrivateKey);
            StoreSecret(name, privRaw);
            return (key.PublicKey, key);
        }
        else
        {
            var k = Key.Import(alg, priv, NSec.Cryptography.KeyBlobFormat.RawPrivateKey);
            return (k.PublicKey, k);
        }
    }
}
