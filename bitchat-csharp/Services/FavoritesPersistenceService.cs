using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Bitchat.Services;

public sealed class FavoritesPersistenceService
{
    private readonly string _path;
    private readonly HashSet<string> _favorites = new(StringComparer.OrdinalIgnoreCase);

    public FavoritesPersistenceService(string appName = "bitchat-csharp")
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), appName);
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "favorites.json");
        Load();
    }

    public void Add(string peerId) { if (_favorites.Add(peerId)) Save(); }
    public void Remove(string peerId) { if (_favorites.Remove(peerId)) Save(); }
    public bool Contains(string peerId) => _favorites.Contains(peerId);
    public IEnumerable<string> All() => _favorites;

    private void Load()
    {
        if (!File.Exists(_path)) return;
        try
        {
            var list = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(_path));
            if (list != null) foreach (var s in list) _favorites.Add(s);
        }
        catch { }
    }
    private void Save()
    {
        try { File.WriteAllText(_path, JsonSerializer.Serialize(_favorites)); } catch { }
    }
}
