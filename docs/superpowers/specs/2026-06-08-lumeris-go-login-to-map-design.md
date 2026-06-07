# Lumeris-Go — Port Server ke Go (Milestone 1: Login → Map)

**Tanggal:** 2026-06-08 (revisi: tambah deployment Docker + config env)
**Status:** Disetujui (siap masuk fase rencana implementasi)
**Lokasi proyek:** `C:\Users\RASYA\Documents\Lumeris-Project\lumeris-go` (repo git terpisah dari Lumeris-Project)

## Ringkasan

Menulis ulang server emulator Emil Chronicle Online (SagaECO) dari C#/.NET Framework
ke **Go** secara bertahap, agar bisa berjalan di Linux. Milestone pertama:
**satu server Go tunggal** yang menggabungkan peran SagaValidation + SagaLogin + SagaMap,
cukup sampai klien `eco.exe` asli (tanpa modifikasi) bisa:

> buat akun → login → pilih karakter → masuk map → karakter muncul, bisa gerak, bisa chat dasar.

Klien resmi tetap dipakai apa adanya; kompatibilitas wire-protocol byte-for-byte adalah syarat mutlak.

## Keputusan kunci (dari sesi brainstorming)

| Topik | Keputusan | Alasan |
|---|---|---|
| Bahasa | Go (tulis ulang dari nol, bertahap) | Target Linux, performa, preferensi user |
| Cakupan M1 | Validation + Login + Map digabung 1 proses | Permintaan eksplisit user |
| Definisi "selesai" | Spawn **+ gerak + chat dasar** | Pilihan C user |
| Database | **PostgreSQL**, skema **baru dari nol** (bukan `sagaeco` lama) | Pilihan user; tak ada migrasi data lama |
| Arsitektur | **Opsi A (monolith berlapis)** dirancang agar mudah migrasi ke **Opsi C (actor model)** di fase mob/AI | Sederhana sekarang, jalan keluar terjaga |
| Port | **12022** Validation, **12023** Login, **12024** Map | Ditentukan user |
| Deployment | **Docker Compose: 1 container app + 1 container PostgreSQL** | Mudah di-maintain di Linux; app monolith jadi 1 image |
| Config | **Environment variable** (bukan XML); ada `.env.example` | Standar Docker, gampang di-override per-lingkungan |
| Handoff Login→Map | **Registry in-memory + token sekali-pakai** (bukan gRPC/Redis) | Karena monolith 1 proses; tetap bisa dipecah nanti |

## Arsitektur tingkat tinggi

Satu binary Go, **tiga listener TCP** dalam satu proses:

```
┌──────────────── lumeris-go (1 proses) ─────────────────┐
  eco.exe ──:12022──▶ ValidationListener ┐
  eco.exe ──:12023──▶ LoginListener      ├─▶ shared state (in-memory)
  eco.exe ──:12024──▶ MapListener        ┘   + PostgreSQL
└─────────────────────────────────────────────────────────┘
```

Perbedaan prinsip dari C# lama: ketiga server tidak lagi berkomunikasi lewat
**INTERN packet** antar-proses. Semuanya jadi panggilan fungsi in-memory lewat
**Registry pusat**.

### Layout paket

```
cmd/lumeris-go/main.go   → entry point: start 3 listener + game loop
internal/protocol/       → kripto (DH + AES-ECB), Packet (SIZE|ID|DATA, big-endian), framing
internal/session/        → Session (1 goroutine baca + channel tulis), Registry pusat
internal/login/          → handler: version, login, char create/select, request-map
internal/game/           → handler: map handshake, spawn, movement, chat + tick loop
internal/db/             → interface Store + impl PostgresStore (pgx)
internal/model/          → Account, Character, Actor, Map
internal/config/         → loader config dari environment variable (port, DSN, IP server)
migrations/              → 001_init.sql, dst.
Dockerfile               → multi-stage build (golang builder → image ramping)
docker-compose.yml       → service app + service postgres + volume + healthcheck
.env.example             → contoh environment variable
```

**Boundary untuk migrasi ke Opsi C nanti:** `Session` sudah punya inbox/outbox channel
(itu bentuk aktor ringan); `Map` punya tick loop + daftar pemain. Saat fase mob/AI,
tiap `Actor` tinggal diberi mailbox sendiri tanpa mengubah lapisan protocol/db.

## Bagian 2 — Protokol & kripto (paling kritis)

Replikasi byte-for-byte dari C# `SagaLib`. Meleset satu byte = klien gagal connect.

**Wire format:**
- Frame: `SIZE (2 byte) | ID (2 byte) | DATA`
- SIZE = plaintext (panjang total termasuk header). ID + DATA terenkripsi setelah AES key siap.
- Integer multi-byte = **big-endian / network byte order**.
- String = **Shift_JIS** via `golang.org/x/text/encoding/japanese` (padanan `Global.Unicode`).

**Handshake kripto (replika `Encryption.cs`):**
1. Klien kirim versi → server balas blob 22-byte hardcoded (`FF FF E8 6A ...`) + `VERSION_ACK`.
2. Server kirim `LOGIN_ALLOWED` dengan `frontWord`/`backWord` random.
3. Diffie-Hellman: modulus 128-byte hardcoded, base = 2, `privateKey`. `modPow` pakai `math/big`.
4. `MakeAESKey`: ambil 16 byte hasil `A^priv mod M`, lalu **tiap nibble > 9 dikurangi 9** (wajib direplikasi).
5. AES-128 **mode ECB, tanpa padding** — diimplementasi manual blok-per-16-byte (persis loop `Decrypt` C#).

**Packet primitive:** helper big-endian `GetByte/GetUShort/GetUInt/GetBytes` + `PutByte/PutUShort/PutUInt/PutBytes`, field `offset`. Tiap packet implement interface:

```go
type Packet interface {
    ID() uint16
    Parse(s *Session) error   // inbound C→S
}
// outbound S→C punya method Build() []byte
```

**Dispatch:** `map[uint16]HandlerFunc` per listener (ganti command-table C#). Tidak ada prototype-clone; pakai closure/func langsung.

**Verifikasi:** unit test feed byte hasil capture `TomatoProxyTool` dan pastikan `decryptGo == plaintext C#` SEBELUM menyentuh klien asli.

## Bagian 3 — Model data & skema PostgreSQL baru

Minimal — cukup untuk milestone, bukan port semua kolom `ActorPC`. Tambah kolom saat fiturnya masuk.

**Lapisan akses (`internal/db`)** — semua di balik interface `Store`, impl `PostgresStore` pakai **pgx**:

```go
type Store interface {
    CreateAccount(ctx, username, passwordHash string) (*Account, error)
    GetAccountByName(ctx, username string) (*Account, error)
    CheckPassword(ctx, username, password string) (bool, error)
    CharsByAccount(ctx, accountID int64) ([]*Character, error)
    CreateCharacter(ctx, *Character) error
    DeleteCharacter(ctx, charID int64) error
    LoadCharacter(ctx, charID int64) (*Character, error)
    SaveCharacter(ctx, *Character) error
}
```

**Skema (3 tabel minimal):**

```sql
accounts(
  id bigserial PK,
  username text UNIQUE NOT NULL,
  password_hash text NOT NULL,          -- bcrypt (BUKAN plaintext)
  gm_level int NOT NULL DEFAULT 0,
  banned bool NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
)

characters(
  id bigserial PK,
  account_id bigint NOT NULL REFERENCES accounts(id),
  slot int NOT NULL,                    -- slot pilih-karakter (0..N)
  name text UNIQUE NOT NULL,
  job int NOT NULL,
  level int NOT NULL DEFAULT 1,
  map_id int NOT NULL,                  -- peta spawn
  x int NOT NULL, y int NOT NULL,       -- koordinat spawn
  hp int NOT NULL, maxhp int NOT NULL,
  sp int NOT NULL, maxsp int NOT NULL,
  str int, dex int, int_ int, vit int, agi int, mnd int,  -- stat dasar
  appearance jsonb NOT NULL,            -- rambut/wajah/warna/equip-look
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(account_id, slot)
)
```

**Model domain (`internal/model`):**
- `Account` = `{ID, Username, GMLevel, Banned}`
- `Character` = data tersimpan (DB)
- `Actor` = entitas hidup di peta (bungkus Character + state live: posisi sekarang, arah hadap, pointer sesi)

Pemisahan **Character (data) vs Actor (runtime)** disengaja: saat fase actor-model nanti, `Actor` inilah unit aktornya.

**Migrasi:** file SQL bernomor di `migrations/`, dijalankan saat startup atau via CLI. Password **bcrypt** (klien kirim plaintext lewat koneksi terenkripsi AES, server hash sebelum simpan) — lebih aman dari skema lemah C# lama.

## Bagian 4 — Login flow (port dari ValidationClient + LoginClient)

**Fase A — Listener :12022 (Validation)**
1. `OnSendVersion`: server kirim blob 22-byte → `VERSION_ACK` → `LOGIN_ALLOWED` (`frontWord`/`backWord` untuk DH).
2. `CSMG_LOGIN` (username+password, ASCII, size 55, offset 8):
   - Balas `LOGIN_ACK = OK` dulu (TCP handshake-flag, sesuai komentar C#).
   - Cek versi klien (whitelist) — **configurable, default longgar** untuk milestone; GM bypass nanti.
   - **Beda dari C# lama:** akun belum ada → **auto-create** (username baru + bcrypt). Sudah ada → `CheckPassword` bcrypt.
   - Banned → `LOGIN_ERR_BFALOCK`.
3. `CSMG_SERVERLET_ASK` → `OnServerLstSend`: `SERVER_LST_START` → `SERVER_LST_SEND` (nama + IP) → `SERVER_LST_END`. Guard "request ke-2 = disconnect" diport apa adanya.

**Fase B — Listener :12023 (Login)**
4. Klien konek → load `CharsByAccount` → kirim daftar slot.
5. `CSMG_CHAR_CREATE` → validasi nama unik → `CreateCharacter` (map kota awal, koordinat, stat base per-job) → balas karakter baru.
6. `CSMG_CHAR_DELETE` → `DeleteCharacter`.
7. `CSMG_CHAR_SELECT` + `CSMG_REQUEST_MAP_SERVER` (punya `Slot`) → `OnRequestMapServer`: tandai slot terpilih, simpan **sesi pending map** di Registry (ganti `INTERN_LOGIN_REGISTER`), kirim alamat map (`IP:12024` + token) ke klien.

**Registry pusat (ganti semua INTERN packet):**
`session.Registry` menyimpan `token → PendingMapEntry{account, character}`. Login menulis entri; Map membacanya saat klien konek :12024. Tidak ada socket antar-server.

**Keamanan:** tiap handoff diberi **token random sekali-pakai** (bukan slot mentah). Map menolak koneksi tanpa token valid → cegah lompat langsung ke :12024.

## Bagian 5 — Map: handshake + spawn + gerak + chat

Klien konek ke **:12024** dengan token dari Fase B.

**1. Handshake & auth token**
- Klien kirim opcode masuk-map (bawa token). Map cek `Registry`. Token valid → ambil Character terpilih, buat `Actor`. Token invalid → disconnect.
- Server kirim paket inisialisasi map (data karakter sendiri, info map, posisi spawn, stat, inventory-look minimum). **Daftar persis opcode diverifikasi dari `MapClient` C# + capture `TomatoProxyTool` sebelum implementasi — tidak ditebak.**

**2. Spawn**
- `Actor` masuk `Map.players`. Broadcast "actor muncul" ke pemain sepeta; kirim pemain yang sudah ada ke klien baru. Milestone: fokus karakter sendiri muncul benar dulu, broadcast multi-pemain menyusul di loop yang sama.

**3. Tick loop (`internal/game`)**
- Tiap peta punya goroutine ticker, cadence diselaraskan dengan timing asli yang tercatat (idle ~1s/step, gerak ~340ms/step — lihat memori `eco_mob_movement_nekogame`).
- Loop: proses antrian kejadian (gerak, chat) → broadcast perubahan ke pemain sepeta. Ini pondasi migrasi ke actor model.

**4. Gerak (movement)**
- Port wire format `0x11F9 ACTOR_MOVE` (memori `eco_mob_movement_nekogame`). Server update posisi `Actor`, broadcast ke Actor lain sepeta. Validasi dasar anti-teleport ringan.

**5. Chat dasar**
- Opcode chat → broadcast ke pemain dalam jangkauan/peta. String round-trip Shift_JIS.
- Cakupan: chat peta normal; whisper/party menyusul.

## Bagian 6 — Deployment Docker & konfigurasi

App monolith (1 proses) dikemas jadi **1 image**. PostgreSQL jalan di container terpisah.
Keduanya dikelola lewat `docker-compose`.

```
┌──────────────── docker-compose ────────────────────┐
  ┌──────────────────┐        ┌─────────────────────┐
  │ lumeris-go (app) │───────▶│ postgres:16         │
  │ :12022/23/24     │  DSN   │ :5432 (jaringan      │
  │ (3 listener)     │        │       internal)     │
  │ 1 binary         │        │ volume: pgdata      │
  └──────────────────┘        └─────────────────────┘
└──────────────────────────────────────────────────────┘
```

**Dockerfile (multi-stage):**
- Stage 1 `golang:1.2x`: `go build` dengan `GOOS=linux` → 1 binary statis.
- Stage 2 image ramping (`alpine`/`distroless`): hanya menyalin binary + file `migrations/`.
- Image akhir kecil, tanpa toolchain build.

**docker-compose.yml:**
- Service `db` = `postgres:16`, volume `pgdata` (data tahan restart), `healthcheck` (`pg_isready`).
- Service `app` = build dari `Dockerfile`, `depends_on: db (condition: service_healthy)`,
  expose port `12022/12023/12024` ke host. Restart policy `unless-stopped`.
- Jaringan internal compose: app konek ke `db:5432` lewat nama service, bukan IP.

**Migrasi otomatis saat start:** app menjalankan file `migrations/*.sql` berurutan saat boot
(cek tabel versi skema dulu, skip yang sudah dijalankan). DB fresh langsung siap tanpa langkah manual.

**Konfigurasi via environment variable** (ganti file XML C#); ada `.env.example`:

| Env var | Contoh | Guna |
|---|---|---|
| `LUMERIS_DB_DSN` | `postgres://user:pass@db:5432/lumeris` | Koneksi PostgreSQL (pgx) |
| `LUMERIS_PORT_VALIDATION` | `12022` | Port listener Validation |
| `LUMERIS_PORT_LOGIN` | `12023` | Port listener Login |
| `LUMERIS_PORT_MAP` | `12024` | Port listener Map |
| `LUMERIS_PUBLIC_IP` | `127.0.0.1` | IP yang dikirim ke klien di `SERVER_LST_SEND` (ganti ke IP VPS saat deploy remote) |
| `LUMERIS_CLIENT_ENCODING` | `Shift_JIS` | Encoding string wire |

**Skenario testing utama:** app di Docker (Linux), `eco.exe` di Windows host konek ke
port yang di-expose Docker. `LUMERIS_PUBLIC_IP` default `127.0.0.1`. Saat pindah ke VPS,
cukup ganti env var ini — tak ada hardcode IP.

**Dev di Windows:** `go run ./cmd/lumeris-go` jalan native di Windows untuk iterasi cepat;
Postgres bisa diambil dari container Docker saja (`localhost:5432`) walau app di-run native.
Docker penuh dipakai saat hendak deploy ke Linux.

## Verifikasi milestone (Definition of Done)

1. Unit test kripto/packet dari capture `TomatoProxyTool` lulus (`decryptGo == plaintext C#`).
2. Klien `eco.exe` asli (tanpa modifikasi): buat akun baru → login → buat karakter → pilih → masuk map → **karakter muncul, bisa jalan, bisa ketik chat yang muncul di layar**, tanpa disconnect/error.
3. Server berjalan di Linux (build `GOOS=linux`).
4. `docker compose up` menyalakan app + PostgreSQL; migrasi jalan otomatis; klien Windows host bisa konek ke port yang di-expose dan menyelesaikan alur DoD #2 dari awal.

## Non-goals (milestone ini)

- Port 2.241 script NPC/quest (butuh pendekatan terpisah — port manual atau scripting tertanam seperti Lua; **diputuskan di milestone berbeda**).
- Mob AI, combat, pathfinding (datang bersama fase actor-model).
- Inventory penuh, skill, party/guild, friend list, whisper lintas-server.
- Migrasi data dari `sagaeco` lama (skema baru, tak ada data lama yang diangkut).
- Horizontal scaling / multi-proses.

## Risiko & catatan

- **Kripto byte-exact** adalah titik kegagalan utama — diverifikasi via test capture sebelum tes klien.
- **Opcode map-init persis** belum 100% dipetakan; diverifikasi dari kode C# + proxy capture saat implementasi, bukan ditebak.
- **Shift_JIS round-trip** harus konsisten; klien JP lama tak bisa UTF-8.
- Scripting NPC (2.241 file) sengaja di luar cakupan — keputusan arsitektur tersendiri nanti.
