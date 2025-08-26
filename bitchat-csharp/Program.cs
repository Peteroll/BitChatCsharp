using System;
using Bitchat.Core;
using Bitchat.Protocol;
using Bitchat.Tests;

Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.WriteLine("BitChat (C# console) — minimal demo");

#if WINDOWS
// Prefer dual-role BLE to match iOS behavior; allow overrides via switches
string myPeer = RandomPeerId();
string? force = null; string? nameArg = null;
foreach (var a in args)
{
    if (a.Equals("--ble-client", StringComparison.OrdinalIgnoreCase)) force = "client";
    else if (a.Equals("--ble-peripheral", StringComparison.OrdinalIgnoreCase)) force = "peripheral";
    else if (a.StartsWith("--name=", StringComparison.OrdinalIgnoreCase)) nameArg = a.Substring(7);
}
var localName = string.IsNullOrWhiteSpace(nameArg) ? myPeer : nameArg;

IMeshTransport transport = force switch
{
    "client" => new BluetoothGattClientTransport(),
    "peripheral" => new BluetoothGattTransport(localName),
    _ => new BluetoothGattDualTransport(localName)
};
Console.WriteLine(force switch
{
    "client" => "Transport: BLE (GATT Central)",
    "peripheral" => $"Transport: BLE (GATT Peripheral), LocalName={localName}",
    _ => $"Transport: BLE (Dual: Peripheral+Central), LocalName={localName}"
});
#else
IMeshTransport transport = new InMemoryMeshTransport();
Console.WriteLine("Transport: InMemory");
#endif
IDisposable? transportDisposable = transport as IDisposable;
var router = new SimpleRouter(transport);
#if !WINDOWS
string myPeer = RandomPeerId();
#endif
Console.WriteLine($"Your peerID: {myPeer}");
Console.WriteLine("Commands: \n  /b <text>  (broadcast)\n  /pm <peerHex8> <text>  (private message via Noise)\n  /pmn <peerHex8> <text>  (alias for Noise PM)\n  /ne <peerHex8> <text>  (noise-encrypted send of raw text)\n  /testfrag <bytes> (send a large message to trigger fragmentation)\n  /selftest (run protocol self-tests)\n  /q to quit");
#if WINDOWS
Console.WriteLine("Windows BLE switches: --ble-client | --ble-peripheral | --name=<peerID> (override local name). Default: dual-role.");
#endif
Console.WriteLine("Advanced: \n  /pub (print local signing pubkey raw32 hex)\n  /reg <peerHex8> <pubHex64> (register peer Ed25519 pubkey)");
Console.WriteLine("Identity: \n  /announce <nickname> (broadcast Noise identity announcement)");
Console.WriteLine("Nostr: \n  /relays (list relays)\n  /relay add <wss-url>\n  /relay rm <wss-url>\n  /ids (list registered Ed25519 identities)");
Console.WriteLine("Nostr Keys: \n  /npub (print nostr x-only pubkey hex)");

while (true)
{
    Console.Write("> ");
    var line = Console.ReadLine();
    if (string.IsNullOrWhiteSpace(line)) continue;
    if (line.Equals("/q", StringComparison.OrdinalIgnoreCase)) break;

    if (line.StartsWith("/b "))
    {
        var msg = line[3..];
        router.Broadcast(myPeer, msg);
        continue;
    }
    if (line.StartsWith("/pm "))
    {
        var parts = line.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3) { Console.WriteLine("Usage: /pm <peerHex8> <text>"); continue; }
        if (router is SimpleRouter sr)
            sr.PrivateMessageNoise(myPeer, parts[1], parts[2]);
        continue;
    }
    if (line.StartsWith("/pmn ", StringComparison.OrdinalIgnoreCase))
    {
        var parts = line.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3) { Console.WriteLine("Usage: /pmn <peerHex8> <text>"); continue; }
        if (router is SimpleRouter sr)
            sr.PrivateMessageNoise(myPeer, parts[1], parts[2]);
        continue;
    }
    if (line.Equals("/selftest", StringComparison.OrdinalIgnoreCase))
    {
        _ = SelfTests.RunAll();
        continue;
    }
    if (line.Equals("/pub", StringComparison.OrdinalIgnoreCase))
    {
        if (router is SimpleRouter sr)
        {
            var raw = sr.ExportLocalSigningPublicKeyRaw32();
            Console.WriteLine($"Local Ed25519 pub (raw32): {Convert.ToHexString(raw)}");
        }
        continue;
    }
    if (line.StartsWith("/reg ", StringComparison.OrdinalIgnoreCase))
    {
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 3) { Console.WriteLine("Usage: /reg <peerHex8> <pubHex64>"); continue; }
        if (router is SimpleRouter sr)
        {
            try
            {
                var raw = Convert.FromHexString(parts[2]);
                var ok = sr.RegisterPeerSigningKey(parts[1], raw);
                Console.WriteLine(ok ? "Registered." : "Register failed.");
            }
            catch { Console.WriteLine("Invalid pubHex64"); }
        }
        continue;
    }
    if (line.StartsWith("/ne ", StringComparison.OrdinalIgnoreCase))
    {
        var parts = line.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3) { Console.WriteLine("Usage: /ne <peerHex8> <text>"); continue; }
        if (router is SimpleRouter sr)
            sr.SendNoiseEncrypted(myPeer, parts[1], parts[2]);
        continue;
    }
    if (line.StartsWith("/testfrag ", StringComparison.OrdinalIgnoreCase))
    {
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !int.TryParse(parts[1], out var n) || n <= 0)
        { Console.WriteLine("Usage: /testfrag <bytes>"); continue; }
        var big = new string('A', n);
        router.Broadcast(myPeer, big);
        continue;
    }
    if (line.StartsWith("/announce ", StringComparison.OrdinalIgnoreCase))
    {
        var parts = line.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2) { Console.WriteLine("Usage: /announce <nickname>"); continue; }
        if (router is SimpleRouter sr) sr.AnnounceIdentity(myPeer, parts[1]);
        continue;
    }
    if (line.Equals("/relays", StringComparison.OrdinalIgnoreCase))
    {
        if (router is SimpleRouter sr)
        {
            var lst = sr.ListRelays();
            Console.WriteLine(lst.Count == 0 ? "(no relays)" : string.Join(Environment.NewLine, lst));
        }
        continue;
    }
    if (line.StartsWith("/relay add ", StringComparison.OrdinalIgnoreCase))
    {
        var parts = line.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 3) { Console.WriteLine("Usage: /relay add <wss-url>"); continue; }
        if (router is SimpleRouter sr)
        {
            sr.AddRelay(parts[2]);
            Console.WriteLine("added.");
        }
        continue;
    }
    if (line.StartsWith("/relay rm ", StringComparison.OrdinalIgnoreCase))
    {
        var parts = line.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 3) { Console.WriteLine("Usage: /relay rm <wss-url>"); continue; }
        if (router is SimpleRouter sr)
        {
            Console.WriteLine(sr.RemoveRelay(parts[2]) ? "removed." : "not found.");
        }
        continue;
    }
    if (line.Equals("/ids", StringComparison.OrdinalIgnoreCase))
    {
        if (router is SimpleRouter sr)
        {
            var dict = sr.ListIdentities();
            if (dict.Count == 0) Console.WriteLine("(no identities)");
            else foreach (var kv in dict) Console.WriteLine($"{kv.Key} = {kv.Value}");
        }
        continue;
    }
    if (line.Equals("/npub", StringComparison.OrdinalIgnoreCase))
    {
        if (router is SimpleRouter sr)
        {
            Console.WriteLine(sr.GetNostrPubKeyHex());
        }
        continue;
    }
    Console.WriteLine("Unknown command");
}

// Cleanup
transportDisposable?.Dispose();

static string RandomPeerId()
{
    var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
    Span<byte> b = stackalloc byte[8];
    rng.GetBytes(b);
    return Convert.ToHexString(b);
}
