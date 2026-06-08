# Plan 4 — Login Flow (Validation + Login + register API)

**Tanggal:** 2026-06-08
**Status:** Disetujui (siap masuk fase rencana implementasi)
**Mendahului:** Plan 5 (map entry: spawn + gerak + chat)
**Bergantung pada:** Plan 1-3 (sudah merged: protocol/crypto/frame, session/listener, model/Store/migrations)

## Ringkasan

Mengimplementasikan **seluruh alur login** server emulator ECO di Go, cukup agar klien
`eco.exe` asli (Saga11) bisa: connect → version handshake → login (SHA1-challenge) →
lihat daftar karakter → buat/hapus/pilih karakter → minta alamat map server. Ditambah
**HTTP register endpoint** untuk membuat akun (klien tak pernah mengirim plaintext, jadi
akun harus dibuat di luar jalur login).

Dua listener TCP — **Validation (:12022)** dan **Login (:12023)** — dengan **tabel dispatch
terpisah**, persis seperti C# (SagaValidation vs SagaLogin adalah dua server berbeda). Klien
menjalankan ulang version+login handshake di tiap listener.

Plan 4 menghasilkan **binary pertama yang bisa dijalankan**: `cmd/lumeris-go`.

## Keputusan kunci (sesi ini)

| Topik | Keputusan | Alasan |
|---|---|---|
| Skema auth | **MD5(pw) tersimpan + SHA1-challenge** (BUKAN bcrypt, BUKAN auto-create) | Verifikasi byte-exact C# (`MySQLAccountDB.cs:247`, `WebServer.Account.cs:13-16`): klien kirim `SHA1(front+MD5+back)`, tak pernah plaintext. Override spec & Plan 3. |
| Buat akun | **HTTP register endpoint** (username 4-30, password 4-32 → simpan MD5Hex) | Klien tak kirim plaintext; akun dibuat out-of-band. Port `WebServer.Account.cs`. |
| Cakupan | **Full login flow** (Validation + Login + register) | Pilihan user. |
| Version check | **Terima versi apa saja** (selalu VERSION_ACK=OK) | Milestone; tighten nanti saat tahu version bytes klien target. |
| Store runtime | **Postgres-only** (DSN dari env, migrasi saat boot, exit bila gagal) | Sesuai target Docker; tak ada fallback MemStore di binary. |
| Model karakter | **Diperluas sekarang** (field appearance/job-level/quest) + migrasi 002 | Char-list packet butuh race/gender/face/dll; visual benar di layar pilih-karakter. |
| Logika challenge | **Fungsi murni `VerifyChallenge`** (handler fetch akun via `GetAccountByName`) | Mudah dites tanpa DB; `Store` tetap tipis (tak ada perubahan interface). |
| Handoff Login→Map | **TANPA token/Registry** | Klien re-login dari nol di :12024 (Plan 5) thd Store yang sama. Konfirmasi RE: tak ada token di `SSMG_SEND_TO_MAP_SERVER`. |

## Arsitektur

```
cmd/lumeris-go/main.go
  └─ load config (env) → connect PostgresStore → RunMigrations
     ├─ netio.Listener(:12022, validationDispatch)   ┐
     ├─ netio.Listener(:12023, loginDispatch)         ├─ semua share *db.Store
     └─ register.HTTPServer(:port, store)             ┘
internal/login/      → packets.go (build/parse byte-exact), validation.go, login.go (dispatch + handler)
internal/register/   → HTTP register endpoint (port WebServer.Account.cs)
internal/auth/       → VerifyChallenge (SHA1) + MD5Hex   (atau taruh di internal/db)
```

### Perubahan ke lapisan yang sudah ada

1. **`internal/db/password.go`** — ganti `HashPassword` bcrypt → `MD5Hex(pw)` (hex lowercase).
2. **`internal/db` (MemStore + PostgresStore)** — `CheckPassword` tak lagi bcrypt-compare.
   Karena auth Plan 4 pakai challenge (bukan plaintext-compare), `CheckPassword` jadi tak relevan
   untuk login; pertimbangkan hapus dari interface ATAU repurpose. **Keputusan:** tambah
   `VerifyChallenge(storedMD5, front, back, resp) bool` sebagai fungsi murni; handler login
   panggil `GetAccountByName` lalu `VerifyChallenge`. `CheckPassword` di-deprecate (hapus dari
   `Store` bila tak ada pemakai lain — cek dulu).
3. **`internal/model/account.go`** — tambah `DeletePass string` (untuk char-delete; default "0000").
   `PasswordHash` sudah ada & sudah dikembalikan `GetAccountByName` (tak perlu ubah).
4. **`internal/model/character.go`** — tambah field yang dibutuhkan char-list packet:
   `Race, Gender, Form, Wig, Face, QuestRemaining, JobLevel1, JobLevel2X, JobLevel2T, JobLevel3,
   Rebirth byte/bool`. (Hair/HairColor/Face sebagian sudah di `Appearance` — selaraskan.)
5. **`internal/migrations/files/002_*.sql`** — kolom baru di `accounts` (deletepass) & `characters`
   (field di atas), default sesuai hardcode char-create C#.
6. **`internal/session/session.go`** — tambah field `Context any` (per-session app state:
   front/back word, akun ter-auth, daftar char). Sesuai catatan memori
   `plan4-session-extension-points` poin 1. Handler login meng-cast `s.Context`.

## Spesifikasi wire (byte-exact, Saga11)

Semua integer **big-endian**. String UTF-8 via Shift_JIS layer (`protocol.Packet.PutStringAt`)
KECUALI username/password/deletepass = **ASCII**. Sumber: ekstraksi RE dari `SagaLogin/Packets/`.

### Outbound (S→C) — builder

| Packet | ID | Layout |
|---|---|---|
| SSMG_VERSION_ACK | 0x0002 | result int16@2 (OK=0, mismatch=0xFFFF); 6 version bytes@4 |
| SSMG_LOGIN_ALLOWED | 0x001E | FrontWord uint32@2; BackWord uint32@6 |
| SSMG_LOGIN_ACK | 0x0020 | LoginResult uint32@2; AccountID uint32@6; RestTestTime@10; TestEndTime@14 |
| SSMG_REQUEST_NYA | 0x0150 | body kosong |
| SSMG_SERVER_LST_START | 0x0032 | body kosong |
| SSMG_SERVER_LST_SEND | 0x0033 | nameLen byte@2; name UTF-8+\0@3; ipLen byte@(L1+3); ip UTF-8+\0@(L1+4) |
| SSMG_SERVER_LST_END | 0x0034 | body kosong |
| SSMG_CHAR_DATA | 0x0028 | Saga11: base 131 byte, blok field paralel (lihat SSMG_CHAR_DATA.cs — sudah dibaca) |
| SSMG_CHAR_EQUIP | 0x0029 | Saga11: 230 byte, 4 slot, marker 0x0E@{2,59,116,173}, per slot i / equip j: uint32@(3+i*57+j*4) |
| SSMG_CHAR_CREATE_ACK | 0x00A1 | CreateResult uint32@2 (OK=0, NAME_CONFLICT=0xFFFFFF9E, ALREADY_SLOT=0xFFFFFF9D, NAME_BADCHAR=0xFFFFFFA0) |
| SSMG_CHAR_SELECT_ACK | 0x00A8 | MapID uint32@2 |
| SSMG_SEND_TO_MAP_SERVER | 0x0033 | ServerID byte@2; ipLen byte@3 (=bytes+1); IP UTF-8 (TANPA \0)@4; Port int32@(4+ipLen) |

**SSMG_LOGIN_ACK Result (uint32, two's-complement):** OK=0, UNKNOWN_ACC=-2(0xFFFFFFFE),
BADPASS=-3(0xFFFFFFFD), BFALOCK/ban=-4(0xFFFFFFFC), ALREADY=-5(0xFFFFFFFB), IPBLOCK=-6(0xFFFFFFFA).

**Catatan ID 0x0033 dipakai dua kali** (SERVER_LST_SEND & SEND_TO_MAP_SERVER) — beda fase, klien
disambiguasi dari state alur. Aman karena outbound (kita yang kirim).

### Inbound (C→S) — parse

| Packet | ID | Parse |
|---|---|---|
| CSMG_SEND_VERSION | 0x0001 | 6 version bytes@4 → hex string |
| CSMG_PING | 0x000A | tanpa body → balas PONG (0x000B) |
| CSMG_LOGIN | 0x001F | ASCII, length-prefixed: off=2; uLen=byte; user=ASCII(uLen-1); off+=uLen; pLen=byte; pass=ASCII(pLen-1); **off++ lalu off+=pLen**; MAC=ushort@off + uint@(off+2). ASIMETRI off++ WAJIB direplikasi. |
| CSMG_SERVERLET_ASK | 0x0031 | (Validation) → kirim SERVER_LST_START/SEND/END |
| CSMG_CHAR_STATUS | 0x002A | Slot byte@2 |
| CSMG_CHAR_CREATE | 0x00A0 | Slot@2; nameLen@3; name@4..; D=4+nameLen; **Saga11:** Race@D, Gender@D+1, (gap@D+2), HairStyle@D+3, HairColor@D+4, Face uint16@D+5 |
| CSMG_CHAR_DELETE | 0x00A5 | Slot@2; pwLen@3; deletePassword ASCII (pwLen-1)@4 |
| CSMG_CHAR_SELECT | 0x00A7 | Slot byte@2 |
| CSMG_REQUEST_MAP_SERVER | 0x0032 | Slot uint32@2 (praktis tak dipakai; pakai selectedChar) |

### Tabel dispatch

**Validation (:12022):** 0x0001 SEND_VERSION, 0x001F LOGIN, 0x0031 SERVERLET_ASK, 0x000A PING.
**Login (:12023):** 0x0001 SEND_VERSION, 0x001F LOGIN (re-login), 0x000A PING, 0x002A CHAR_STATUS,
0x00A0 CHAR_CREATE, 0x00A5 CHAR_DELETE, 0x00A7 CHAR_SELECT, 0x0032 REQUEST_MAP_SERVER.
(NyaShield 0x0151 opsional milestone — REQUEST_NYA dikirim tapi balasan klien bisa diabaikan dulu.)

## Alur handler

**Validation `OnSendVersion`:** kirim blob 22-byte mentah (`FF FF E8 6A ...`) → VERSION_ACK(OK) →
LOGIN_ALLOWED (front/back = dua uint random per-sesi, simpan di `s.Context`) → REQUEST_NYA.

**`OnLogin`:** ambil akun via `GetAccountByName(user)`. Tak ada → LOGIN_ACK UNKNOWN_ACC.
`VerifyChallenge(acc.PasswordHash, front, back, pass)` gagal → BADPASS. Banned → BFALOCK.
OK → LOGIN_ACK(OK, AccountID). Di listener Login, setelah OK → `SendCharData()` (CHAR_DATA + CHAR_EQUIP).

**`OnServerletAsk`** (Validation): SERVER_LST_START → SERVER_LST_SEND (nama dari config,
IP = `LUMERIS_PUBLIC_IP`) → SERVER_LST_END.

**`OnCharCreate`** (Login): validasi nama unik + slot kosong → `CreateCharacter` dgn starting values
hardcode (Level1, HP/MaxHP=120, MP=120/MaxMP=220, SP=100, Wig=0xFF, QuestRem=3, dir=2, MapID/X/Y/stats
per-race — milestone: satu set default sederhana, refine saat config per-race masuk) → CHAR_CREATE_ACK →
SendCharData. `ErrDuplicate` dari Store tak bisa bedakan nama vs slot (catatan Plan 3) → cek slot dulu
di memori daftar char untuk pesan yang benar.

**`OnCharDelete`:** cocokkan `acc.DeletePass` (default "0000") → `DeleteCharacter` → ACK → SendCharData.

**`OnCharSelect`:** set selectedChar di `s.Context`; CHAR_SELECT_ACK(MapID). Tak pindah map.

**`OnRequestMapServer`:** SEND_TO_MAP_SERVER(ServerID=1, IP=`LUMERIS_PUBLIC_IP`, Port=`PortMap`).

## HTTP register (`internal/register`)

Port `WebServer.Account.cs HandleRegister`: HTTP server, endpoint register membaca header
`username` (4-30 char) + `password` (4-32), simpan `MD5Hex(password)` via `CreateAccount`.
Balas JSON `{"success":true}` / `{"error":"..."}`. Guard input (panjang, duplikat → ErrDuplicate).
Port HTTP dari config (tambah `LUMERIS_PORT_HTTP`, default mis. 8001).

## Testing

- **Unit:** `VerifyChallenge` (vektor SHA1 hand-computed), `MD5Hex`; tiap builder/parser packet vs
  byte hand-computed (terutama CSMG_LOGIN asimetri off++, CHAR_CREATE Saga11 +1 gap, CHAR_EQUIP formula).
- **Integration:** MemStore-backed, drive lewat frame nyata (EncodeFrame/DecodeFrame): register →
  version → login challenge → char create → list → select → request-map. Pastikan tak disconnect.
- **Catatan:** test pakai `db.NewMemStore()` (paritas dijamin contract test Plan 3).

## Definition of Done (Plan 4)

1. Semua unit + integration test lulus (`go test ./...`).
2. `cmd/lumeris-go` build & jalan (Postgres up): dua listener + HTTP register aktif.
3. `go vet` bersih.
4. Klien asli (manual, opsional di Plan 4): register via HTTP → connect :12022 → login → pilih char →
   dapat alamat map. (Verifikasi klien penuh termasuk masuk-map = Plan 5.)

## Non-goals (Plan 4)

- Map listener :12024, spawn, movement, chat (Plan 5).
- Friend list, whisper, gifts, mails, ring, tamaire (opcode ada di dispatch C# tapi di luar cakupan).
- Config per-race startup (StartupSetting) penuh — pakai default sederhana, refine nanti.
- NyaShield enforcement (kirim REQUEST_NYA, abaikan balasan).
- Inventory/equip nyata (CHAR_EQUIP kirim 230-byte kosong/nol).
