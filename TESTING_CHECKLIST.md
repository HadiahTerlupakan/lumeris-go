# Testing Checklist - lumeris-go (2026-06-08)

## ✅ Selesai (Completed)

### 1. Proxy Capture Analysis
- [x] Setup TomatoProxyTool untuk intercept NekogameECO traffic
- [x] Capture full login flow (Validation → Login → Map entry)
- [x] Analyze proxy_packets.log (150 lines, 88+ seconds)
- [x] Extract opcode mappings dari capture
- [x] Document packet flow differences

### 2. Code Fixes
- [x] **Fix #1**: Remove mystery packet 0xFFFF dari validation.go
- [x] **Fix #2**: Add handler 0x002F → response 0x0030
- [x] **Fix #3**: Fix Map Server SSMG_LOGIN_ALLOWED (0x0011 → 0x000F)
- [x] **Fix #4**: Fix Map Server SSMG_LOGIN_ACK (0x0012 → 0x0011)
- [x] Build verification (go build -o lumeris-go.exe)
- [x] Git commit dengan dokumentasi lengkap

### 3. Documentation
- [x] Create PACKET_FLOW_COMPARISON.md (detailed flow comparison)
- [x] Create FIXES_SUMMARY.txt (ASCII art summary)
- [x] Create TESTING_CHECKLIST.md (this file)
- [x] Update commit message dengan Co-Authored-By

---

## 🔄 Next Step - Testing dengan Client Lokal

### Prerequisites
1. **ECO Client Setup**
   - Install eco.exe (Emil Chronicle Online client)
   - Locate `server.lst` file (biasanya di folder client)
   - Backup `server.lst` original

2. **Database Setup**
   - Ensure PostgreSQL running
   - Database `lumeris_test` exists
   - Account `test123` dengan password MD5 stored
   - Karakter test ada di slot 0

3. **Server Ready**
   - Build: `go build -o lumeris-go.exe cmd/lumeris-go/main.go`
   - Config: `config.yaml` pointing ke localhost
   - Ports: 12022 (Validation), 12023 (Login), 12024 (Map)

### Test Sequence

#### Phase 1: Validation Server Test
```
[ ] 1. Edit server.lst:
      PROXY,127.0.0.1:12022,12022,0
      
[ ] 2. Start server: ./lumeris-go.exe
      
[ ] 3. Launch eco.exe
      
[ ] 4. Verify logs show:
      [Validation] Client version bytes: [...]
      [Validation] Sending VERSION_ACK
      [Validation] Sending LOGIN_ALLOWED
      [Validation] Received CSMG_LOGIN from: test123
      [Validation] Login SUCCESS for test123
      [Validation] Received 0x002F ← CRITICAL!
      [Validation] Sent 0x0030 response ← CRITICAL!
      [Validation] Server list sent
      
[ ] 5. Client should show server list "SagaECO"
```

**Expected Result**: Client reaches server selection screen without error

---

#### Phase 2: Login Server Test
```
[ ] 1. Click "SagaECO" server di client
      
[ ] 2. Verify logs show:
      [Login] Client connected from [...]
      [Login] Sending VERSION_ACK
      [Login] Character list request from test123
      [Login] Sending char data for slot 0
      [Login] Char selected: slot 0
      
[ ] 3. Client should show character list
      
[ ] 4. Click character → "Enter World"
      
[ ] 5. Verify logs show:
      [Login] Map server request for slot 0
      [Login] Sending map server address: 127.0.0.1:12024
```

**Expected Result**: Client receives Map server address dan auto-connect

---

#### Phase 3: Map Server Test
```
[ ] 1. Client auto-connect ke Map server (12024)
      
[ ] 2. Verify logs show:
      [Map] Client connected from [...]
      [Map] Sending VERSION_ACK
      [Map] Sending LOGIN_ALLOWED (0x000F) ← CRITICAL!
      [Map] Received CSMG_LOGIN
      [Map] Login SUCCESS, sending LOGIN_ACK (0x0011) ← CRITICAL!
      [Map] Received CSMG_CHAR_SLOT: slot 0
      
[ ] 3. Client waiting for spawn sequence (belum diimplementasi)
```

**Expected Result**: 
- ✅ Client tidak disconnect
- ✅ Logs menunjukkan CSMG_CHAR_SLOT received
- ⚠️ Client stuck di "loading" (normal, spawn belum ada)

---

## ❌ Known Issues (Belum Diimplementasi)

### Map Server Spawn Sequence
Setelah CSMG_CHAR_SLOT, client expect packet sequence:

```
S->C GOLEM_ACTOR_APPEAR (spawn NPCs/mobs)
S->C ACTOR_PC_APPEAR (spawn player character)
S->C PLAYER_MOVE (movement packets)
S->C CHAT (chat messages)
S->C ... (banyak packet lain)
```

**Status**: ❌ Belum diimplementasi
**Impact**: Client stuck di loading screen (tidak ada error, just waiting)

---

## 🐛 Potential Issues & Solutions

### Issue 1: Client disconnect setelah VERSION_ACK
**Symptom**: Client disconnect sebelum LOGIN_ALLOWED
**Possible Causes**:
1. Version bytes mismatch (check client version vs server echo)
2. Encryption issue (re-verify AES keys)
3. Packet size mismatch

**Debug Steps**:
```bash
# Enable verbose logging
export LOG_LEVEL=debug
./lumeris-go.exe

# Check exact bytes sent
grep "Sending VERSION_ACK" logs/lumeris.log
```

---

### Issue 2: Mystery packet 0xFFFF still sent
**Symptom**: Logs show "Sent mystery packet"
**Solution**: Code sudah di-fix, tapi verify line 60-66 di validation.go benar-benar terhapus

**Verify**:
```bash
grep -n "0xFFFF" internal/login/validation.go
# Should return: (empty, atau hanya di comment)
```

---

### Issue 3: Client tidak kirim 0x002F
**Symptom**: Logs tidak show "Received 0x002F"
**Possible Causes**:
1. Client version beda (mungkin packet ini opsional)
2. Flow berbeda untuk client tertentu

**Solution**: Tidak critical, skip saja. Handler tetap ada untuk compatibility.

---

### Issue 4: Map Server opcodes masih salah
**Symptom**: Client disconnect setelah connect ke Map server
**Verify opcodes**:
```bash
grep "SSMG_LOGIN_ALLOWED\|SSMG_LOGIN_ACK" internal/mapserver/opcodes.go
# Should show:
# SSMG_LOGIN_ALLOWED  = 0x000F
# SSMG_LOGIN_ACK      = 0x0011
```

---

## 📊 Success Criteria

### Minimum Success (Phase 1-2)
- [x] Server builds without errors
- [ ] Client connects to Validation server
- [ ] Client receives server list
- [ ] Client connects to Login server
- [ ] Client shows character list
- [ ] Client receives Map server address

### Full Success (Phase 1-3)
- [ ] All above +
- [ ] Client connects to Map server
- [ ] Map server receives CSMG_CHAR_SLOT
- [ ] No unexpected disconnects
- [ ] Logs show correct packet flow (sesuai NekogameECO capture)

### Future Success (Phase 4 - Spawn)
- [ ] Implement spawn sequence
- [ ] Client enters map world
- [ ] Player character visible
- [ ] Movement works
- [ ] Chat works

---

## 🔧 Quick Commands

### Build & Run
```bash
go build -o lumeris-go.exe cmd/lumeris-go/main.go
./lumeris-go.exe
```

### Check Ports
```bash
netstat -an | grep -E ":(12022|12023|12024)"
```

### Watch Logs (Live)
```bash
tail -f logs/lumeris.log
```

### Stop Server
```bash
taskkill //F //IM lumeris-go.exe
```

### Git Status
```bash
git log --oneline -5
git diff HEAD~1
```

---

## 📝 Test Log Template

Copy template ini untuk dokumentasi testing:

```
=== TEST RUN: 2026-06-08 HH:MM ===

PHASE 1: VALIDATION
- [ ] Server started successfully
- [ ] Client connected
- [ ] VERSION_ACK sent
- [ ] LOGIN_ALLOWED sent
- [ ] CSMG_LOGIN received
- [ ] LOGIN_ACK sent
- [ ] 0x002F received
- [ ] 0x0030 sent
- [ ] Server list shown
Result: PASS / FAIL
Notes: 

PHASE 2: LOGIN
- [ ] Client selected server
- [ ] VERSION_ACK sent
- [ ] Character list shown
- [ ] Character selected
- [ ] Map server address sent
Result: PASS / FAIL
Notes:

PHASE 3: MAP
- [ ] Client connected to Map
- [ ] VERSION_ACK sent
- [ ] LOGIN_ALLOWED (0x000F) sent
- [ ] CSMG_LOGIN received
- [ ] LOGIN_ACK (0x0011) sent
- [ ] CSMG_CHAR_SLOT received
Result: PASS / FAIL
Notes:

OVERALL: PASS / FAIL
Issues Found:
1. 
2. 
3. 
```

---

## 📚 Reference Files

- **Packet Flow**: [PACKET_FLOW_COMPARISON.md](PACKET_FLOW_COMPARISON.md)
- **Fixes Summary**: [FIXES_SUMMARY.txt](FIXES_SUMMARY.txt)
- **Proxy Capture**: `C:\Users\RASYA\Documents\Lumeris-Project\ProxyTool\TomatoProxyTool\bin\Debug\proxy_packets.log`
- **NekogameECO**: 161.117.42.60:12000 (reference server)

---

**Last Updated**: 2026-06-08
**Status**: Ready for Phase 1 testing dengan ECO client lokal
