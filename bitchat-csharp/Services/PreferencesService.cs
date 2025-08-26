using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Bitchat.Services;

public sealed class PreferencesService
{
    private readonly string _path;
    private Dictionary<string, string> _kv = new();

    public PreferencesService(string appName = "bitchat-csharp")
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), appName);
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "prefs.json");
        Load();
    }

    public void Set(string key, string value) { _kv[key] = value; Save(); }
    public bool TryGet(string key, out string value) => _kv.TryGetValue(key, out value!);

    private void Load()
    {
        if (!File.Exists(_path)) return;
        try { _kv = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(_path)) ?? new(); }
        catch { _kv = new(); }
    }
    private void Save()
    {
        try { File.WriteAllText(_path, JsonSerializer.Serialize(_kv)); } catch { }
    }
}
