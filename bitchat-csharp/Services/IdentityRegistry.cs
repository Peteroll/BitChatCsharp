using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using NSec.Cryptography;

namespace Bitchat.Services;

public sealed class IdentityRegistry
{
    private readonly ConcurrentDictionary<string, PublicKey> _eds = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _storePath;

    public IdentityRegistry()
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "bitchat-csharp", "ids");
        Directory.CreateDirectory(dir);
        _storePath = Path.Combine(dir, "ed25519.json");
        TryLoad();
    }

    public bool TryGetEd25519(string peerHex8, out PublicKey pub) => _eds.TryGetValue(Normalize(peerHex8), out pub!);

    public bool AddOrUpdateEd25519(string peerHex8, ReadOnlySpan<byte> raw32)
    {
        try
        {
            var pub = PublicKey.Import(SignatureAlgorithm.Ed25519, raw32.ToArray(), KeyBlobFormat.RawPublicKey);
            _eds[Normalize(peerHex8)] = pub;
            TrySave();
            return true;
        }
        catch
        {
            return false;
        }
    }

    public IReadOnlyDictionary<string, string> ListEd25519()
    {
        var dict = new Dictionary<string, string>(_eds.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var kv in _eds)
            dict[kv.Key] = Convert.ToHexString(kv.Value.Export(KeyBlobFormat.RawPublicKey));
        return dict;
    }

    private static string Normalize(string hex)
    {
        return hex.Length > 16 ? hex[..16].ToUpperInvariant() : hex.ToUpperInvariant();
    }

    private void TrySave()
    {
        try
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in _eds)
                dict[kv.Key] = Convert.ToHexString(kv.Value.Export(KeyBlobFormat.RawPublicKey));
            var json = System.Text.Json.JsonSerializer.Serialize(dict);
            File.WriteAllText(_storePath, json);
        }
        catch { }
    }

    private void TryLoad()
    {
        try
        {
            if (!File.Exists(_storePath)) return;
            var json = File.ReadAllText(_storePath);
            var dict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            if (dict == null) return;
            foreach (var kv in dict)
            {
                try
                {
                    var raw = Convert.FromHexString(kv.Value);
                    var pub = PublicKey.Import(SignatureAlgorithm.Ed25519, raw, KeyBlobFormat.RawPublicKey);
                    _eds[kv.Key] = pub;
                }
                catch { }
            }
        }
        catch { }
    }
}
