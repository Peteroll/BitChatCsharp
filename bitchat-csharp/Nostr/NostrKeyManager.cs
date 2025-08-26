using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NBitcoin.Secp256k1;

namespace Bitchat.Nostr;

public sealed class NostrKeyManager
{
    private readonly string _path;
    private ECPrivKey? _priv;

    public NostrKeyManager(string appName = "bitchat-csharp")
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), appName, "nostr");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "secp256k1.json");
        LoadOrCreate();
    }

    public byte[] GetXOnlyPub()
    {
        if (_priv is null) throw new InvalidOperationException("Key not loaded");
        var pub = _priv.CreatePubKey();
        var comp = pub.ToBytes(true);
        if (comp.Length != 33) throw new InvalidOperationException("pubkey serialize failed");
        var x = new byte[32];
        Array.Copy(comp, 1, x, 0, 32);
        return x;
    }

    public string GetXOnlyPubHex() => Convert.ToHexString(GetXOnlyPub()).ToLowerInvariant();

    public byte[] SignBip340(byte[] msg32)
        => throw new NotSupportedException("BIP340 signing not wired yet");

    private void LoadOrCreate()
    {
        try
        {
            if (File.Exists(_path))
            {
                var json = File.ReadAllText(_path);
                var obj = JsonSerializer.Deserialize<KeyFile>(json);
                if (obj != null)
                {
                    var raw = Convert.FromHexString(obj.Priv);
                    if (ECPrivKey.TryCreate(raw, out var key)) { _priv = key; return; }
                }
            }
        }
        catch { }
        // create new
        Span<byte> sk = stackalloc byte[32];
        do { RandomNumberGenerator.Fill(sk); } while (!ECPrivKey.TryCreate(sk, out _priv));
        var kf = new KeyFile { Priv = Convert.ToHexString(sk).ToLowerInvariant() };
        try { File.WriteAllText(_path, JsonSerializer.Serialize(kf)); } catch { }
    }

    private sealed class KeyFile { public string Priv { get; set; } = string.Empty; }
}
