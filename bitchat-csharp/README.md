# BitChat C# Console Port

Language: [English](#english-version) | [繁體中文](#繁體中文版本)

---

## English Version

This directory contains an **experimental .NET 8 C# console port** of the original Swift project (`bitchat-1.2.0`). Focus: faithfully reproducing the binary protocol, Noise crypto layer, message routing, fragmentation, and BLE interop with the iOS app (not a full UI).

> Status: Cross‑platform (Windows ↔ iOS) basic broadcast + Noise private messaging works. Multi‑hop + long‑run reliability + full signature coverage still being hardened. Research / test only.

### Goals

- Binary protocol parity (header / flags / signature segment / fragmentation / compression)
- Noise (X25519 + ChaCha20-Poly1305 + HKDF-SHA256) encrypted PM + identity announce
- BLE GATT + advertising interoperability (same Service / Characteristic UUIDs as iOS)
- Reliability: retransmit / ACK / NACK / TTL / dedup / rate limit
- Swift `BitchatMessage` payload compatibility (sender / timestamp / content / optional fields)
- Early Nostr integration (relay management, identity publishing)

### Completed (Done)

Protocol Layer:

- 14‑byte header (type / flags / ttl / hop / payloadLen / msgID / optional recipient / signature segment / padding)
- LZ4 compression (K4os)
- Fragmentation & reassembly (469B paced fragments, time/memory limits)
- Signature segment extraction (placeholder signing pipeline)

Crypto & Identity:


- Noise session (X25519, ChaCha20-Poly1305, HKDF-SHA256, packed nonce)
- Lazy handshake (initiated on first need)
- Noise Identity Announcement (Ed25519 pubkey + signature verify)
- Ed25519 key mgmt (NSec) + Windows ProtectedData storage

Messaging Flow:

- `BitchatMessage` encode/decode (Swift parity)
- Unified broadcast / private / NoiseEncrypted path using the same payload format
- ACK / NACK / DeliveryTracker / retry backoff
- TTL forwarding + RateLimiter + duplicate suppression

BLE:


- GATT Peripheral & Central (Service UUID: F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C, Char UUID: A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D)
- Dual-role transport (Peripheral + Central concurrently)
- Peripheral advertising with LocalName = peerID (16 hex) + Service UUID
- Notify broadcast path (/b delivered to subscribed iOS devices)

Nostr:

- Relay add/remove/list
- Basic x-only pubkey export + event skeleton

CLI:

- /b /pm /pmn /ne /announce /relays /relay add|rm /ids /pub /reg /npub /testfrag /selftest

### In Progress / TODO

- Deeper multi-hop & stress verification (current: basic TTL forwarding)
- Full Ed25519 signing (all packet types) & signature distribution
- Bi-directional advertising strategy + adaptive power (match Swift BatteryOptimizer)
- Advanced Nostr: BIP340 event signing + relay subscriptions
- Windows BLE reconnection, scan cadence tuning, multi-device pool
- Long-run memory / fragmentation endurance tests
- Persistence layer (delivery queue & offline storage)
- Log redaction / structured security logging

### Build & Run

Requires .NET 8 SDK.

```pwsh
cd bitchat-csharp
dotnet build -c Release
# Run (dual-role BLE, random peerID as LocalName)
dotnet run -c Release -f net8.0-windows10.0.19041.0
# Central only
dotnet run -c Release -f net8.0-windows10.0.19041.0 -- --ble-client
# Peripheral only with fixed name (16 hex)
dotnet run -c Release -f net8.0-windows10.0.19041.0 -- --ble-peripheral --name=0123456789ABCDEF
```

### Commands

| Command | Description |
|---------|-------------|
| /b text | Broadcast message |
| /pm peerHex8 text | Noise private message |
| /pmn peerHex8 text | Alias for /pm |
| /ne peerHex8 text | Raw Noise-encrypted send |
| /announce nick | Broadcast identity announcement |
| /testfrag bytes | Send large message to test fragmentation |
| /pub | Print local Ed25519 pub (raw32) |
| /reg peer pubHex64 | Register peer Ed25519 pubkey |
| /relays /relay add /relay rm | Manage Nostr relays |
| /ids | List registered identities |
| /npub | Print nostr x-only pubkey |
| /selftest | Run protocol self-tests |
| /q | Quit |

### Architecture Overview

- Core/
  - MeshTransport (assembly, routing, TTL, Noise decrypt, BitchatMessage decode)
  - BluetoothGattTransport / BluetoothGattClientTransport / BluetoothGattDualTransport
- Protocol/
  - BinaryProtocol (header/flags/padding/compression/signature segment)
  - Models/BitchatMessage.cs (Swift-compatible payload)
  - MessageTypes (fragment / Noise / ack enums)
- Noise/
  - NoiseSession (X25519 ECDH + AEAD + HKDF)
- Services/
  - DeliveryTracker / IdentityRegistry / Favorites / Retry / RateLimiter
- Nostr/
  - RelayManager / KeyManager (BIP340 TODO)

### iOS Interop Test Steps

1. Start Windows app (dual-role default), note peerID.
2. Open iOS bitchat app – your peerID should appear (not “nobody around”).
3. Send message from iPhone; Windows prints `<@sender> text`.
4. Use /b on Windows; iPhone should receive.
5. Test /pm both directions (Noise handshake auto-starts).

If iPhone does not see you:

- Ensure Windows adapter supports GATT Peripheral mode.
- Try `--ble-peripheral` only.
- Ensure no other app monopolizes advertising.

### Security Notes

- Not externally audited; avoid high‑risk use cases.
- Incomplete ubiquitous signing & mesh reliability may affect integrity / ordering guarantees.

### Roadmap (Priority)

1. Full Ed25519 signing pipeline (all packet types)
2. BLE connection pool + adaptive load shedding
3. BIP340 Nostr event signing + relay subscription flow
4. Persistence (offline delivery, identity cache)
5. Battery / duty-cycle model parity with Swift
6. Metrics & observability (rates, failures)
7. Extended test suite (multi-node sim / fuzz / property-based)

### License

Public Domain (UNLICENSE) – same as original Swift project.

---

## 繁體中文版本

這個資料夾包含從 Swift 原始專案 (bitchat-1.2.0) 移植的 **實驗性 .NET 8 C# 主控台版本**，重點在於重現核心協定、加密與 BLE Mesh 互通，而非提供完整 GUI。

> 狀態：可進行跨平台（Windows ↔ iOS）基本廣播與 Noise 私訊互通；仍在強化多跳與可靠性細節。此版本僅供研究 / 測試用途。

### 主要目標

- Binary 協定完整相容（Header / Flags / Signature / Fragmentation / Compression）
- Noise (X25519 + ChaCha20-Poly1305 + HKDF-SHA256) 私訊與身份宣告
- BLE GATT / 廣告互通（與 iOS 使用相同 Service / Characteristic UUID）
- 訊息重傳 / ACK / NACK / TTL / 去重 / 節流
- Swift `BitchatMessage` payload 互通（sender / timestamp / content / optional fields）
- Nostr 整合雛型（relay 管理、身份發布）

### 目前已完成 (Done)

- 協定層
  - 14-byte header（type / flags / ttl / hop / payloadLength / messageID / optional recipient / signature 區段 / padding）
  - LZ4 壓縮與解壓（K4os）
  - Fragmentation / Reassembly（469B chunk pacing, timeout & memory 限制）
  - Signature placeholder + 區段抽取 (TryGetSignatureSegments)
- 加密與身份
  - Noise Session：X25519、ChaCha20-Poly1305、HKDF-SHA256、nonce 打包
  - Lazy Handshake：自動在第一則私訊或加密訊息時建立
  - Noise Identity Announcement (Ed25519 公鑰 + 簽章驗證)
  - Ed25519 Key 管理（NSec）與本地儲存（Windows ProtectedData）
- 訊息流程
  - BitchatMessage payload 編碼/解碼（與 Swift 對齊）
  - Broadcast / PrivateMessage / NoiseEncrypted path 統一使用 payload 格式
  - ACK / NACK / DeliveryTracker / Retry Backoff
  - TTL 轉送 + RateLimiter + 去重快取
- BLE
  - GATT Peripheral / Central 實作（ServiceUUID: F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C, CharUUID: A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D）
  - Dual 角色傳輸（同時 Peripheral + Central）
  - Peripheral 廣告：含 LocalName=peerID（16 hex）+ Service UUID（供 iOS 掃描配對）
  - Notify 廣播路徑（/b 可被訂閱的 iOS 裝置接收）
- Nostr
  - Relay 管理 (新增/移除/列出)
  - 基本公鑰 (x-only) 匯出與事件封裝骨架
- CLI
  - /b /pm /pmn /ne /announce /relays /relay add|rm /ids /pub /reg /npub /testfrag /selftest

### 進行中 / 未完成 (Pending / TODO)

- 更完整的多跳 Mesh 測試與壓力驗證（目前僅基本 TTL 轉送）
- 更嚴謹的訊息簽章（完整 Ed25519 簽署與驗證流程套入所有類型）
- 雙向廣告 + 動態功耗調節策略（對齊 Swift BatteryOptimizer 行為）
- 更進階 Nostr：事件簽章 (BIP340) 實作、Relay 訂閱與同步
- 優化 BLE 在 Windows 上的重連 / 掃描節奏與多裝置連線池
- 長時間運行記憶體壓力與碎片化測試
- 儲存層：DeliveryQueue / 未送達訊息持久化（目前記憶體內）
- Logging 等級與安全清洗（避免敏感原始內容洩漏）

### 建構與執行

需要 .NET 8 SDK。

```pwsh
cd bitchat-csharp
dotnet build -c Release
dotnet run -c Release -f net8.0-windows10.0.19041.0
dotnet run -c Release -f net8.0-windows10.0.19041.0 -- --ble-client
dotnet run -c Release -f net8.0-windows10.0.19041.0 -- --ble-peripheral --name=0123456789ABCDEF
```

### 指令摘要

| 指令 | 說明 |
|------|------|
| /b text | 廣播訊息 |
| /pm peerHex8 text | 私訊（Noise）|
| /pmn peerHex8 text | 私訊別名 |
| /ne peerHex8 text | 直接送 Noise 加密 payload (raw) |
| /announce nickname | 廣播身份公告 |
| /testfrag bytes | 發送大訊息測 fragmentation |
| /pub | 顯示本地 Ed25519 公鑰 (raw32) |
| /reg peer pubHex64 | 登錄對方 Ed25519 公鑰 |
| /relays /relay add /relay rm | 管理 Nostr relays |
| /ids | 列出已註冊身份 |
| /npub | 顯示 nostr x-only pubkey |
| /selftest | 執行基本協定測試 |
| /q | 離開 |

### 架構概述

- Core/
  - MeshTransport：封包組裝、路由、TTL、Noise 解密、BitchatMessage 解碼
  - BluetoothGattTransport / BluetoothGattClientTransport / BluetoothGattDualTransport
- Protocol/
  - BinaryProtocol：Header/Flags/Padding/壓縮/簽章區段抽取
  - Models/BitchatMessage.cs：Swift 對齊的訊息 payload 結構
  - MessageTypes：封包類型列舉（含 Fragment / Noise / Ack）
- Noise/
  - NoiseSession：X25519 ECDH + AEAD + HKDF
- Services/
  - DeliveryTracker / IdentityRegistry / Favorites / Retry / RateLimiter
- Nostr/
  - RelayManager / KeyManager (BIP340 TODO)

### iOS 互通測試建議

1. 先在 Windows 執行（預設雙角色）記下 peerID。
2. 開啟 iPhone bitchat App，應可看到你的 peerID（非 “nobody around”）。
3. iPhone 傳訊息，Windows 會顯示 <@sender> 內容。
4. Windows /b 廣播，iPhone 應收到。
5. 測試 /pm：先在 iPhone 端執行對等的私訊；確認雙向 Noise OK。

若 iPhone 看不到你：

- 確認 Windows 藍牙支援 GATT 周邊（Peripheral）模式。
- 改用 `--ble-peripheral` 單一模式測試。
- 確保沒有其他程式佔用藍牙廣告。

### 安全注意

- 尚未完成全面第三方審計。請勿用於高敏感情境。
- 未完成的簽章統一與多跳可靠性優化可能影響訊息完整/順序保證。

### 後續 Roadmap（優先順）

1. 完整 Ed25519 簽章流程嵌入所有封包類型
2. BLE 多連線池與自動降載/回復策略
3. BIP340 Nostr 事件簽章 + Relay 訂閱同步
4. 持久化儲存（離線訊息與 Identity Cache）
5. Battery / Duty-cycle 模擬層（與 Swift 對齊）
6. 更細緻的記錄與統計（封包速率、失敗率）
7. 測試套件擴充（多節點模擬 / fuzz / property-based）

### 授權

沿用原專案 Public Domain（UNLICENSE）。

---

This README focuses on the C# port. For the original Swift project, see `bitchat-1.2.0/README.md`.
