# Packet Flow Comparison: NekogameECO vs lumeris-go

## Summary of Fixes Applied (2026-06-08)

Berdasarkan proxy capture dari NekogameECO (161.117.42.60:12000), berikut adalah perbedaan kritis yang sudah diperbaiki:

---

## 1. Validation Server Flow

### ❌ **BEFORE (Incorrect)**
```
C->S 0x0001 CSMG_SEND_VERSION
S->C 0xFFFF Mystery Packet (20 bytes) ← TIDAK ADA DI NEKOGAME!
S->C 0x0002 SSMG_VERSION_ACK
S->C 0x001E SSMG_LOGIN_ALLOWED
C->S 0x001F CSMG_LOGIN
S->C 0x0020 SSMG_LOGIN_ACK
C->S 0x0031 CSMG_SERVERLET_ASK
```

### ✅ **AFTER (Fixed, sesuai NekogameECO)**
```
C->S 0x0001 CSMG_SEND_VERSION (6 byte version)
S->C 0x0002 SSMG_VERSION_ACK (8 bytes: result + version echo)
S->C 0x001E SSMG_LOGIN_ALLOWED (8 bytes: FrontWord + BackWord)
C->S 0x001F CSMG_LOGIN (username + SHA1 hash + MAC)
S->C 0x0020 SSMG_LOGIN_ACK (19 bytes)
C->S 0x002F Unknown packet (2 bytes) ← BARU DITAMBAHKAN!
S->C 0x0030 Response (4 bytes body = 00 00 00 00) ← BARU DITAMBAHKAN!
C->S 0x0031 CSMG_SERVERLET_ASK (server list request)
S->C 0x0032 SSMG_SERVER_LST_START
S->C 0x0033 SSMG_SERVER_LST_SEND (nama server + IP)
S->C 0x0034 SSMG_SERVER_LST_END
```

**Changes Made:**
- ❌ **REMOVED**: Mystery packet 0xFFFF (tidak ada di capture NekogameECO)
- ✅ **ADDED**: Handler untuk 0x002F → response 0x0030 (4 bytes body nol)
- ✅ **CONFIRMED**: Opcode 0x001F = CSMG_LOGIN, 0x0020 = SSMG_LOGIN_ACK (sudah benar)

---

## 2. Map Server Flow

### ❌ **BEFORE (Incorrect Opcodes)**
```
SSMG_LOGIN_ALLOWED  = 0x0011  ← SALAH!
SSMG_LOGIN_ACK      = 0x0012  ← SALAH!
```

### ✅ **AFTER (Fixed, sesuai NekogameECO)**
```
C->S 0x000A CSMG_SEND_VERSION
S->C 0x000B SSMG_VERSION_ACK
S->C 0x000F SSMG_LOGIN_ALLOWED ← FIXED dari 0x0011!
C->S 0x0010 CSMG_LOGIN
S->C 0x0011 SSMG_LOGIN_ACK ← FIXED dari 0x0012!
C->S 0x01FD CSMG_CHAR_SLOT (pilih slot karakter)
S->C ... (spawn sequence: GOLEM_ACTOR_APPEAR, ACTOR_PC_APPEAR, dll)
```

**Changes Made:**
- ✅ **FIXED**: `SSMG_LOGIN_ALLOWED = 0x000F` (dari 0x0011)
- ✅ **FIXED**: `SSMG_LOGIN_ACK = 0x0011` (dari 0x0012)
- ✅ **CONFIRMED**: CSMG_CHAR_SLOT = 0x01FD (sudah benar)

---

## 3. Server List Format

### Validation Server
**Format IP**: `T<ip>,<ip>,<ip>,<ip>` (prefix "T" + 4 copies)
- Example: `T127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1`

### NekogameECO (from capture)
**Format IP**: `P<ip>:<port>,<ip>:<port>,...` (prefix "P" + IP:port pairs)
- Example: `P161.117.42.60:12001,161.117.42.60:12001,...`

**Status**: ⚠️ Format berbeda, tapi untuk localhost testing format "T" sudah cukup. Nanti bisa upgrade ke format "P" bila perlu.

---

## 4. Critical Discoveries

### Mystery Packet 0xFFFF
- **C# SagaECO Server**: Mengirim mystery packet 0xFFFF (20 bytes)
- **NekogameECO Server**: **TIDAK mengirim** mystery packet sama sekali!
- **Kesimpulan**: Mystery packet adalah quirk dari C# implementation, bukan bagian dari protokol asli ECO

### Packet 0x002F & 0x0030
- **Flow baru yang ditemukan**: Setelah LOGIN_ACK, client kirim 0x002F, server balas 0x0030
- **Fungsi**: Belum diketahui (mungkin heartbeat atau session confirmation)
- **Implementasi**: Handler sudah ditambahkan di validation.go

---

## 5. Files Modified

### ✅ `internal/login/validation.go`
- **Line 51-67**: Hapus mystery packet 0xFFFF
- **Line 155-162**: Tambah handler OnUnknown002F() dengan response 0x0030

### ✅ `internal/mapserver/opcodes.go`
- **Line 14**: `SSMG_LOGIN_ALLOWED = 0x000F` (was 0x0011)
- **Line 15**: `SSMG_LOGIN_ACK = 0x0011` (was 0x0012)

### ✅ `internal/login/packets.go`
- **Already correct**: CSMG_LOGIN = 0x001F, SSMG_LOGIN_ACK = 0x0020

---

## 6. Testing Checklist

- [x] Build successful (`go build -o lumeris-go.exe`)
- [ ] Test Validation server dengan client lokal
- [ ] Verify 0x002F → 0x0030 exchange
- [ ] Test Login server character list
- [ ] Test Map server handshake (0x000F LOGIN_ALLOWED)
- [ ] Test CSMG_CHAR_SLOT (0x01FD) handling

---

## 7. Next Steps (Pending)

1. **Implement spawn sequence** di Map Server:
   - GOLEM_ACTOR_APPEAR (actor spawning)
   - ACTOR_PC_APPEAR (player appearance)
   - PLAYER_MOVE (movement packets)
   - CHAT messages

2. **Fix server list format** bila perlu (T → P prefix)

3. **Implement inventory/equipment system** (SSMG_CHAR_EQUIP sudah ada tapi masih placeholder)

4. **Add more Map Server opcodes** dari capture (movement, chat, skill, dll)

---

## Reference: Proxy Capture Timestamps

- **Validation Phase**: 26829ms - 27103ms
- **Login Phase**: 50543ms - 50761ms
- **Map Entry**: 87878ms - 88018ms
- **Map Spawn**: 88018ms - 88xxx ms

Capture file: `C:\Users\RASYA\Documents\Lumeris-Project\ProxyTool\TomatoProxyTool\bin\Debug\proxy_packets.log`
