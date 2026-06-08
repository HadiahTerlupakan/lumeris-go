# Lumeris-Go Plan 3: Database & Migrasi Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Membangun lapisan data lumeris-go: model domain (`Account`/`Character`/`Actor`), interface `Store` dengan DUA implementasi (`MemStore` in-memory + `PostgresStore` pgx), satu set **contract test** yang menguji kedua impl identik, password bcrypt, skema PostgreSQL baru (`migrations/001_init.sql`), dan runner migrasi idempoten yang jalan saat boot.

**Architecture:** `internal/model` mendefinisikan tipe domain murni (tanpa dependensi DB). `internal/db` mendefinisikan interface `Store` + `MemStore` (map + mutex, untuk test offline & substrate handler Plan 4-5) + `PostgresStore` (pgx/pgxpool). Satu file `contract_test.go` berisi tabel test yang dijalankan terhadap KEDUA impl (MemStore selalu; PostgresStore hanya bila `LUMERIS_TEST_DSN` di-set) — menjamin keduanya berperilaku sama. Migrasi = file SQL bernomor + runner yang mencatat versi terpakai di tabel `schema_migrations`.

**Tech Stack:** Go 1.26, `github.com/jackc/pgx/v5` + `github.com/jackc/pgx/v5/pgxpool`, `golang.org/x/crypto/bcrypt`, `context`, `sync`, testing bawaan. PostgreSQL 16.

**Sumber kebenaran:**
- Spec: `docs/superpowers/specs/2026-06-08-lumeris-go-login-to-map-design.md` Bagian 3 (model & skema).
- Catatan memory `[[plan4-session-extension-points]]` — Plan 4 akan memakai `Store` ini untuk auth + load/save karakter.

## Keputusan desain (dikonfirmasi user sebelum menulis plan)

- **MemStore + PostgresStore keduanya.** Spec hanya menyebut PostgresStore, tapi semua plan sebelumnya bisa di-test offline. MemStore membuat Plan 3 teruji penuh offline DAN jadi substrate test handler login/map di Plan 4-5 tanpa DB nyata. Interface `Store` di spec memang dirancang untuk ini.
- **Contract test ganda.** Satu fungsi test menjalankan kasus yang sama terhadap kedua impl via `Store` interface. PostgresStore di-gate `LUMERIS_TEST_DSN` (skip bila kosong) → suite tetap hijau tanpa Docker; dijalankan nyata saat Postgres siap.
- **bcrypt, bukan skema lemah C# lama.** Password datang plaintext lewat koneksi AES (sudah ada), server hash sebelum simpan.
- **Auto-create akun ditangani di Plan 4 (login handler), BUKAN di Store.** `Store` hanya menyediakan primitif (`CreateAccount`/`GetAccountByName`/`CheckPassword`); kebijakan "akun baru → auto-create" adalah logika login. Menjaga Store tetap dumb.

## Fakta yang HARUS dipatuhi (dari spec Bagian 3)

### Interface Store (spec persis, ditambah konteks)
```go
type Store interface {
    CreateAccount(ctx context.Context, username, passwordHash string) (*model.Account, error)
    GetAccountByName(ctx context.Context, username string) (*model.Account, error)
    CheckPassword(ctx context.Context, username, password string) (bool, error)
    CharsByAccount(ctx context.Context, accountID int64) ([]*model.Character, error)
    CreateCharacter(ctx context.Context, c *model.Character) error
    DeleteCharacter(ctx context.Context, charID int64) error
    LoadCharacter(ctx context.Context, charID int64) (*model.Character, error)
    SaveCharacter(ctx context.Context, c *model.Character) error
}
```
Catatan penting: `CreateAccount` menerima `passwordHash` (sudah di-hash), BUKAN plaintext — hashing dilakukan pemanggil/helper, bukan di dalam CreateAccount, agar Store tak mencampur kebijakan kripto. `CheckPassword` menerima plaintext dan membandingkan dengan hash tersimpan via `bcrypt.CompareHashAndPassword`.

### Skema (spec persis — 3 tabel: schema_migrations + accounts + characters)
```sql
accounts(
  id bigserial PK, username text UNIQUE NOT NULL, password_hash text NOT NULL,
  gm_level int NOT NULL DEFAULT 0, banned bool NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
)
characters(
  id bigserial PK, account_id bigint NOT NULL REFERENCES accounts(id),
  slot int NOT NULL, name text UNIQUE NOT NULL, job int NOT NULL,
  level int NOT NULL DEFAULT 1, map_id int NOT NULL, x int NOT NULL, y int NOT NULL,
  hp int NOT NULL, maxhp int NOT NULL, sp int NOT NULL, maxsp int NOT NULL,
  str int, dex int, int_ int, vit int, agi int, mnd int,
  appearance jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(account_id, slot)
)
```

### Model domain (spec Bagian 3)
- `Account` = data tersimpan akun.
- `Character` = data karakter tersimpan (DB).
- `Actor` = entitas hidup di peta (bungkus `Character` + state live: posisi sekarang, arah hadap, pointer sesi). **Actor hanya struct minimal di Plan 3** — field live diisi Plan 5; sekarang cukup definisikan agar pemisahan Character(data)/Actor(runtime) ada sejak awal.

---

## File Structure

```
lumeris-go/
├── go.mod                          (MODIFIKASI) tambah require pgx/v5 + x/crypto
├── internal/model/
│   ├── account.go                  (BARU) struct Account
│   ├── character.go                (BARU) struct Character + Appearance
│   └── actor.go                    (BARU) struct Actor (bungkus *Character + state live minimal)
├── internal/db/
│   ├── store.go                    (BARU) interface Store + error sentinel (ErrNotFound, ErrDuplicate)
│   ├── password.go                 (BARU) HashPassword (bcrypt) — helper dipakai login Plan 4
│   ├── memstore.go                 (BARU) MemStore: impl Store in-memory (map + sync.RWMutex)
│   ├── postgres.go                 (BARU) PostgresStore: impl Store pakai *pgxpool.Pool
│   ├── migrate.go                  (BARU) RunMigrations(ctx, pool, fs) — runner idempoten
│   ├── password_test.go            (BARU) test HashPassword + verifikasi bcrypt
│   ├── contract_test.go            (BARU) contract test: jalan thd MemStore + (gated) PostgresStore
│   └── migrate_test.go             (BARU) test runner migrasi (gated LUMERIS_TEST_DSN)
└── migrations/
    └── 001_init.sql                (BARU) schema_migrations + accounts + characters
```

Pemisahan: `model` = tipe murni (tak impor `db`); `db` = persistence (impor `model`). `MemStore` & `PostgresStore` di file terpisah, diuji oleh `contract_test.go` yang sama. Migrasi terpisah dari Store (tanggung jawab beda: DDL vs DML).

**Catatan dependensi siklik:** `model` TIDAK mengimpor `db`. `Actor` menyimpan `*model.Character` (data) + nanti pointer sesi (Plan 5, via interface agar `model` tak impor `session`). Di Plan 3 `Actor` belum butuh sesi.

---

## Task 1: Model domain — Account, Character, Actor

**Files:**
- Create: `lumeris-go/internal/model/account.go`
- Create: `lumeris-go/internal/model/character.go`
- Create: `lumeris-go/internal/model/actor.go`
- Test: `lumeris-go/internal/model/model_test.go`

Tipe domain murni, tanpa tag DB (mapping dilakukan di layer `db`). `Character.Appearance` = struct ber-tag JSON (disimpan sebagai jsonb).

- [ ] **Step 1: Tulis test yang gagal**

`internal/model/model_test.go`:
```go
package model

import (
	"encoding/json"
	"testing"
)

func TestAppearanceJSONRoundTrip(t *testing.T) {
	a := Appearance{Hair: 3, HairColor: 7, Face: 1}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Appearance
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != a {
		t.Errorf("round-trip Appearance: got %+v, mau %+v", got, a)
	}
}

func TestActorWrapsCharacter(t *testing.T) {
	c := &Character{ID: 42, Name: "Tester", MapID: 1, X: 10, Y: 20}
	act := &Actor{Character: c, CurX: 10, CurY: 20, Direction: 4}
	if act.Character.ID != 42 {
		t.Errorf("Actor tak membungkus Character dengan benar: %+v", act)
	}
	if act.CurX != 10 || act.CurY != 20 || act.Direction != 4 {
		t.Errorf("state live Actor salah: %+v", act)
	}
}
```

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/model/ -v`
Expected: FAIL — `undefined: Appearance` / `Character` / `Actor`.

- [ ] **Step 3: Tulis implementasi minimal**

`internal/model/account.go`:
```go
// Package model mendefinisikan tipe domain murni lumeris-go (tanpa dependensi DB).
package model

// Account adalah satu akun pemain yang tersimpan di DB.
type Account struct {
	ID           int64
	Username     string
	PasswordHash string
	GMLevel      int
	Banned       bool
}
```

`internal/model/character.go`:
```go
package model

// Appearance menyimpan tampilan karakter (disimpan sebagai jsonb di DB).
type Appearance struct {
	Hair      int `json:"hair"`
	HairColor int `json:"hair_color"`
	Face      int `json:"face"`
}

// Character adalah data karakter tersimpan (lihat tabel characters).
type Character struct {
	ID        int64
	AccountID int64
	Slot      int
	Name      string
	Job       int
	Level     int
	MapID     int
	X, Y      int
	HP, MaxHP int
	SP, MaxSP int
	Str       int
	Dex       int
	Int       int
	Vit       int
	Agi       int
	Mnd       int
	Appearance Appearance
}
```

`internal/model/actor.go`:
```go
package model

// Actor adalah entitas hidup di peta: membungkus data Character + state runtime.
// Field live (posisi sekarang, arah) diisi/dipakai saat fase Map (Plan 5).
// Pemisahan Character (data tersimpan) vs Actor (runtime) disengaja — Actor inilah
// unit aktor saat fase actor-model nanti.
type Actor struct {
	*Character
	CurX, CurY int // posisi runtime (bisa beda dari Character.X/Y saat bergerak)
	Direction  int // arah hadap
}
```

> Catatan: `Character.Int` dipakai untuk kolom `int_` (INT adalah kata kunci SQL; nama Go `Int` dipetakan ke kolom `int_` di layer db). Field stat (`Str..Mnd`) bertipe `int` non-pointer; kolom DB-nya nullable tapi kita selalu isi nilai (default 1 dari job) sehingga aman.

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/model/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/model/
git commit -m "feat(model): Account, Character, Appearance, Actor (tipe domain murni)"
```

---

## Task 2: Interface Store + error sentinel + HashPassword

**Files:**
- Create: `lumeris-go/internal/db/store.go`
- Create: `lumeris-go/internal/db/password.go`
- Test: `lumeris-go/internal/db/password_test.go`
- Modify: `lumeris-go/go.mod` (tambah `golang.org/x/crypto`)

Definisikan kontrak `Store` + error sentinel yang dipakai kedua impl, dan helper `HashPassword` (bcrypt). `CheckPassword` ada di interface (per-impl), tapi hashing untuk membuat akun dilakukan via `HashPassword` helper agar logika login (Plan 4) memanggilnya sebelum `CreateAccount`.

- [ ] **Step 1: Tulis test yang gagal**

`internal/db/password_test.go`:
```go
package db

import (
	"golang.org/x/crypto/bcrypt"
	"testing"
)

func TestHashPasswordVerifiable(t *testing.T) {
	hash, err := HashPassword("rahasia123")
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}
	if hash == "rahasia123" {
		t.Fatal("hash sama dengan plaintext (tidak di-hash)")
	}
	// hash bcrypt harus terverifikasi terhadap plaintext asli.
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("rahasia123")); err != nil {
		t.Errorf("hash tak terverifikasi: %v", err)
	}
	// password salah harus gagal.
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("salah")); err == nil {
		t.Error("password salah malah terverifikasi")
	}
}
```

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/db/ -run TestHashPassword -v`
Expected: FAIL — `undefined: HashPassword` (dan `golang.org/x/crypto` belum ada).

- [ ] **Step 3: Tambah dependensi + tulis implementasi**

Tambah dependensi:
```bash
go get golang.org/x/crypto/bcrypt@latest
```

`internal/db/store.go`:
```go
// Package db menyediakan lapisan persistence: interface Store dan implementasinya
// (MemStore in-memory + PostgresStore pgx).
package db

import (
	"context"
	"errors"

	"lumeris-go/internal/model"
)

// Error sentinel yang dikembalikan kedua impl Store secara konsisten.
var (
	// ErrNotFound dikembalikan saat baris yang diminta tak ada.
	ErrNotFound = errors.New("db: tidak ditemukan")
	// ErrDuplicate dikembalikan saat melanggar UNIQUE (username/nama/slot).
	ErrDuplicate = errors.New("db: duplikat")
)

// Store adalah kontrak persistence lumeris-go. Dua impl: MemStore & PostgresStore.
// CreateAccount menerima passwordHash yang SUDAH di-hash (pakai HashPassword);
// Store tak mencampuri kebijakan kripto. CheckPassword menerima plaintext.
type Store interface {
	CreateAccount(ctx context.Context, username, passwordHash string) (*model.Account, error)
	GetAccountByName(ctx context.Context, username string) (*model.Account, error)
	CheckPassword(ctx context.Context, username, password string) (bool, error)
	CharsByAccount(ctx context.Context, accountID int64) ([]*model.Character, error)
	CreateCharacter(ctx context.Context, c *model.Character) error
	DeleteCharacter(ctx context.Context, charID int64) error
	LoadCharacter(ctx context.Context, charID int64) (*model.Character, error)
	SaveCharacter(ctx context.Context, c *model.Character) error
}
```

`internal/db/password.go`:
```go
package db

import "golang.org/x/crypto/bcrypt"

// HashPassword menghasilkan hash bcrypt dari plaintext. Dipanggil logika login
// (Plan 4) SEBELUM CreateAccount — klien mengirim plaintext lewat koneksi AES,
// server hash sebelum menyimpan.
func HashPassword(plaintext string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
```

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/db/ -run TestHashPassword -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/store.go internal/db/password.go internal/db/password_test.go go.mod go.sum
git commit -m "feat(db): interface Store + error sentinel + HashPassword (bcrypt)"
```

---

## Task 3: MemStore — impl Store in-memory

**Files:**
- Create: `lumeris-go/internal/db/memstore.go`
- Create: `lumeris-go/internal/db/contract_test.go`

`MemStore` menyimpan account & character di map dengan `sync.RWMutex`, auto-increment ID. Ini impl pertama yang lulus contract test. Contract test ditulis generik (`testStore(t, s Store)`) agar Task 4 (PostgresStore) memakai ulang.

- [ ] **Step 1: Tulis contract test yang gagal**

`internal/db/contract_test.go`:
```go
package db

import (
	"context"
	"errors"
	"testing"

	"lumeris-go/internal/model"
)

// testStore menjalankan kontrak Store yang sama terhadap impl apa pun.
// Dipakai oleh MemStore (selalu) dan PostgresStore (gated, Task 4).
func testStore(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()

	// 1. CreateAccount + GetAccountByName.
	hash, _ := HashPassword("pw")
	acc, err := s.CreateAccount(ctx, "alice", hash)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if acc.ID == 0 || acc.Username != "alice" {
		t.Fatalf("akun tak valid: %+v", acc)
	}
	got, err := s.GetAccountByName(ctx, "alice")
	if err != nil {
		t.Fatalf("GetAccountByName: %v", err)
	}
	if got.ID != acc.ID {
		t.Errorf("akun beda: %+v vs %+v", got, acc)
	}

	// 2. username duplikat → ErrDuplicate.
	if _, err := s.CreateAccount(ctx, "alice", hash); !errors.Is(err, ErrDuplicate) {
		t.Errorf("CreateAccount duplikat: err = %v, mau ErrDuplicate", err)
	}

	// 3. GetAccountByName tak ada → ErrNotFound.
	if _, err := s.GetAccountByName(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetAccountByName hilang: err = %v, mau ErrNotFound", err)
	}

	// 4. CheckPassword benar & salah.
	ok, err := s.CheckPassword(ctx, "alice", "pw")
	if err != nil || !ok {
		t.Errorf("CheckPassword benar: ok=%v err=%v", ok, err)
	}
	ok, _ = s.CheckPassword(ctx, "alice", "salah")
	if ok {
		t.Error("CheckPassword salah malah true")
	}

	// 5. CreateCharacter + CharsByAccount + LoadCharacter.
	ch := &model.Character{
		AccountID: acc.ID, Slot: 0, Name: "Hero", Job: 1, Level: 1,
		MapID: 1, X: 5, Y: 6, HP: 100, MaxHP: 100, SP: 10, MaxSP: 10,
		Str: 1, Dex: 1, Int: 1, Vit: 1, Agi: 1, Mnd: 1,
		Appearance: model.Appearance{Hair: 1, HairColor: 2, Face: 3},
	}
	if err := s.CreateCharacter(ctx, ch); err != nil {
		t.Fatalf("CreateCharacter: %v", err)
	}
	if ch.ID == 0 {
		t.Fatal("CreateCharacter tak mengisi ID")
	}
	chars, err := s.CharsByAccount(ctx, acc.ID)
	if err != nil || len(chars) != 1 {
		t.Fatalf("CharsByAccount: len=%d err=%v", len(chars), err)
	}
	loaded, err := s.LoadCharacter(ctx, ch.ID)
	if err != nil {
		t.Fatalf("LoadCharacter: %v", err)
	}
	if loaded.Name != "Hero" || loaded.Appearance.Hair != 1 || loaded.X != 5 {
		t.Errorf("LoadCharacter beda: %+v", loaded)
	}

	// 6. nama karakter duplikat → ErrDuplicate.
	dup := &model.Character{AccountID: acc.ID, Slot: 1, Name: "Hero", Job: 1, MapID: 1, HP: 1, MaxHP: 1, SP: 1, MaxSP: 1}
	if err := s.CreateCharacter(ctx, dup); !errors.Is(err, ErrDuplicate) {
		t.Errorf("CreateCharacter nama duplikat: err = %v, mau ErrDuplicate", err)
	}

	// 7. SaveCharacter (update posisi) → LoadCharacter mencerminkan.
	loaded.X, loaded.Y, loaded.Level = 99, 88, 5
	if err := s.SaveCharacter(ctx, loaded); err != nil {
		t.Fatalf("SaveCharacter: %v", err)
	}
	again, _ := s.LoadCharacter(ctx, ch.ID)
	if again.X != 99 || again.Y != 88 || again.Level != 5 {
		t.Errorf("SaveCharacter tak tersimpan: %+v", again)
	}

	// 8. DeleteCharacter → LoadCharacter ErrNotFound.
	if err := s.DeleteCharacter(ctx, ch.ID); err != nil {
		t.Fatalf("DeleteCharacter: %v", err)
	}
	if _, err := s.LoadCharacter(ctx, ch.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("LoadCharacter setelah delete: err = %v, mau ErrNotFound", err)
	}
}

func TestMemStoreContract(t *testing.T) {
	testStore(t, NewMemStore())
}
```

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/db/ -run TestMemStoreContract -v`
Expected: FAIL — `undefined: NewMemStore`.

- [ ] **Step 3: Tulis implementasi minimal**

`internal/db/memstore.go`:
```go
package db

import (
	"context"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"lumeris-go/internal/model"
)

// MemStore adalah impl Store in-memory (map + RWMutex). Dipakai untuk test offline
// dan sebagai substrate handler login/map (Plan 4-5) tanpa DB nyata.
type MemStore struct {
	mu         sync.RWMutex
	accounts   map[int64]*model.Account
	characters map[int64]*model.Character
	nextAccID  int64
	nextCharID int64
}

// NewMemStore membuat MemStore kosong siap pakai.
func NewMemStore() *MemStore {
	return &MemStore{
		accounts:   make(map[int64]*model.Account),
		characters: make(map[int64]*model.Character),
	}
}

func (m *MemStore) CreateAccount(ctx context.Context, username, passwordHash string) (*model.Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.accounts {
		if a.Username == username {
			return nil, ErrDuplicate
		}
	}
	m.nextAccID++
	acc := &model.Account{ID: m.nextAccID, Username: username, PasswordHash: passwordHash}
	m.accounts[acc.ID] = acc
	return cloneAccount(acc), nil
}

func (m *MemStore) GetAccountByName(ctx context.Context, username string) (*model.Account, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.accounts {
		if a.Username == username {
			return cloneAccount(a), nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemStore) CheckPassword(ctx context.Context, username, password string) (bool, error) {
	acc, err := m.GetAccountByName(ctx, username)
	if err != nil {
		return false, err
	}
	if bcrypt.CompareHashAndPassword([]byte(acc.PasswordHash), []byte(password)) != nil {
		return false, nil
	}
	return true, nil
}

func (m *MemStore) CharsByAccount(ctx context.Context, accountID int64) ([]*model.Character, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*model.Character
	for _, c := range m.characters {
		if c.AccountID == accountID {
			out = append(out, cloneCharacter(c))
		}
	}
	return out, nil
}

func (m *MemStore) CreateCharacter(ctx context.Context, c *model.Character) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ex := range m.characters {
		if ex.Name == c.Name {
			return ErrDuplicate
		}
		if ex.AccountID == c.AccountID && ex.Slot == c.Slot {
			return ErrDuplicate
		}
	}
	m.nextCharID++
	c.ID = m.nextCharID
	m.characters[c.ID] = cloneCharacter(c)
	return nil
}

func (m *MemStore) DeleteCharacter(ctx context.Context, charID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.characters[charID]; !ok {
		return ErrNotFound
	}
	delete(m.characters, charID)
	return nil
}

func (m *MemStore) LoadCharacter(ctx context.Context, charID int64) (*model.Character, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.characters[charID]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneCharacter(c), nil
}

func (m *MemStore) SaveCharacter(ctx context.Context, c *model.Character) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.characters[c.ID]; !ok {
		return ErrNotFound
	}
	m.characters[c.ID] = cloneCharacter(c)
	return nil
}

// clone* mengembalikan salinan agar pemanggil tak bisa memutasi state internal
// lewat pointer bersama (MemStore meniru semantik "DB mengembalikan baris baru").
func cloneAccount(a *model.Account) *model.Account {
	cp := *a
	return &cp
}

func cloneCharacter(c *model.Character) *model.Character {
	cp := *c
	return &cp
}
```

> Guardrail: `clone*` mencegah aliasing — sama seperti `Decrypt`/`Encrypt` di protocol selalu kembalikan slice baru. Tanpa ini, test `SaveCharacter` bisa lulus palsu karena pemanggil memegang pointer yang sama.

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/db/ -run TestMemStoreContract -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/memstore.go internal/db/contract_test.go
git commit -m "feat(db): MemStore in-memory + contract test Store"
```

---

## Task 4: Migrasi SQL + runner idempoten

**Files:**
- Create: `lumeris-go/migrations/001_init.sql`
- Create: `lumeris-go/internal/db/migrate.go`
- Test: `lumeris-go/internal/db/migrate_test.go`

Runner membaca file `*.sql` bernomor dari sebuah `fs.FS` (di-embed atau dari disk), mengeksekusi yang belum tercatat di `schema_migrations`, idempoten (aman dijalankan ulang). Di-test terhadap Postgres nyata (gated `LUMERIS_TEST_DSN`).

- [ ] **Step 1: Tulis file migrasi SQL**

`migrations/001_init.sql`:
```sql
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     int          PRIMARY KEY,
    applied_at  timestamptz  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS accounts (
    id            bigserial    PRIMARY KEY,
    username      text         UNIQUE NOT NULL,
    password_hash text         NOT NULL,
    gm_level      int          NOT NULL DEFAULT 0,
    banned        bool         NOT NULL DEFAULT false,
    created_at    timestamptz  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS characters (
    id          bigserial   PRIMARY KEY,
    account_id  bigint      NOT NULL REFERENCES accounts(id),
    slot        int         NOT NULL,
    name        text        UNIQUE NOT NULL,
    job         int         NOT NULL,
    level       int         NOT NULL DEFAULT 1,
    map_id      int         NOT NULL,
    x           int         NOT NULL,
    y           int         NOT NULL,
    hp          int         NOT NULL,
    maxhp       int         NOT NULL,
    sp          int         NOT NULL,
    maxsp       int         NOT NULL,
    str         int,
    dex         int,
    int_        int,
    vit         int,
    agi         int,
    mnd         int,
    appearance  jsonb       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, slot)
);
```

- [ ] **Step 2: Tulis test yang gagal (gated Postgres)**

`internal/db/migrate_test.go`:
```go
package db

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool membuka pool ke Postgres test bila LUMERIS_TEST_DSN di-set; else skip.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("LUMERIS_TEST_DSN")
	if dsn == "" {
		t.Skip("LUMERIS_TEST_DSN tak di-set; lewati test Postgres")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestRunMigrationsIdempotent(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// Bersihkan agar test deterministik (drop tabel bila ada dari run sebelumnya).
	_, _ = pool.Exec(ctx, `DROP TABLE IF EXISTS characters, accounts, schema_migrations CASCADE`)

	if err := RunMigrations(ctx, pool, MigrationsFS); err != nil {
		t.Fatalf("RunMigrations (1): %v", err)
	}
	// Jalankan lagi → harus no-op, tanpa error.
	if err := RunMigrations(ctx, pool, MigrationsFS); err != nil {
		t.Fatalf("RunMigrations (2, idempoten): %v", err)
	}

	// Verifikasi tabel ada & versi tercatat.
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if n != 1 {
		t.Errorf("schema_migrations punya %d baris, mau 1", n)
	}
}
```

- [ ] **Step 3: Jalankan test, pastikan gagal**

Run: `go test ./internal/db/ -run TestRunMigrations -v`
Expected: FAIL — `undefined: RunMigrations` / `MigrationsFS` (atau SKIP bila DSN kosong; set DSN untuk melihat fail nyata).

- [ ] **Step 4: Tambah dependensi pgx + tulis implementasi**

```bash
go get github.com/jackc/pgx/v5@latest
```

`internal/db/migrate.go`:
```go
package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MigrationsFS meng-embed file SQL migrasi agar binary mandiri (tak perlu file di disk).
//
//go:embed all:../../migrations
var migrationsEmbed embed.FS

// MigrationsFS adalah sub-FS berisi file *.sql (akar = direktori migrations).
var MigrationsFS fs.FS = mustSub(migrationsEmbed, "migrations")

func mustSub(e embed.FS, dir string) fs.FS {
	sub, err := fs.Sub(e, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

// RunMigrations menjalankan tiap file NNN_*.sql (urut nomor) yang belum tercatat
// di schema_migrations. Idempoten: file yang sudah dijalankan dilewati. Tiap file
// dijalankan dalam satu transaksi bersama insert versi-nya.
func RunMigrations(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS) error {
	// Pastikan tabel pencatat ada lebih dulu.
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("buat schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return fmt.Errorf("baca dir migrasi: %w", err)
	}
	type mig struct {
		version int
		name    string
	}
	var migs []mig
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		// nama: NNN_deskripsi.sql → ambil NNN.
		numStr, _, ok := strings.Cut(e.Name(), "_")
		if !ok {
			return fmt.Errorf("nama migrasi tak valid (butuh NNN_...): %s", e.Name())
		}
		v, err := strconv.Atoi(numStr)
		if err != nil {
			return fmt.Errorf("nomor migrasi tak valid di %s: %w", e.Name(), err)
		}
		migs = append(migs, mig{version: v, name: e.Name()})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })

	for _, mg := range migs {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, mg.version).Scan(&exists); err != nil {
			return fmt.Errorf("cek versi %d: %w", mg.version, err)
		}
		if exists {
			continue
		}
		sqlBytes, err := fs.ReadFile(fsys, mg.name)
		if err != nil {
			return fmt.Errorf("baca %s: %w", mg.name, err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin tx %s: %w", mg.name, err)
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("eksekusi %s: %w", mg.name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, mg.version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("catat versi %d: %w", mg.version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit %s: %w", mg.name, err)
		}
	}
	return nil
}
```

> Catatan embed path: `//go:embed all:../../migrations` meng-embed dari akar modul. File ini ada di `internal/db/`, jadi `../../migrations` menunjuk `lumeris-go/migrations`. Bila path embed bermasalah (embed tak bisa naik di atas paket di sebagian setup), alternatif: pindah `migrate.go` embed directive ke file di akar modul, atau terima `fs.FS` dari pemanggil (main) yang meng-embed. Verifikasi di Step 5 — jangan menebak; bila `go build` menolak `../../`, gunakan pola "embed di package main, oper fs.FS ke RunMigrations" (test sudah menerima `MigrationsFS` sebagai parameter, jadi tinggal ganti sumbernya).

- [ ] **Step 5: Jalankan build + test**

Run:
```bash
go build ./...
go test ./internal/db/ -run TestRunMigrations -v
```
Expected: build OK. Test PASS bila `LUMERIS_TEST_DSN` di-set; SKIP bila tidak. Jalankan dengan Postgres nyata untuk verifikasi (lihat Task 6 untuk cara start Postgres Docker).

> Jika build gagal di embed `../../migrations`: terapkan alternatif di catatan Step 4 (embed di main, oper `fs.FS`). Sesuaikan `MigrationsFS` agar test tetap kompilasi (mis. expose dari paket lain atau buat helper test-only yang membaca dari disk relatif). JANGAN biarkan plan menebak — verifikasi perilaku embed dulu.

- [ ] **Step 6: Commit**

```bash
git add migrations/001_init.sql internal/db/migrate.go internal/db/migrate_test.go go.mod go.sum
git commit -m "feat(db): migrasi 001_init + runner idempoten (schema_migrations)"
```

---

## Task 5: PostgresStore — impl Store pakai pgxpool

**Files:**
- Create: `lumeris-go/internal/db/postgres.go`
- Modify: `lumeris-go/internal/db/contract_test.go` (tambah `TestPostgresStoreContract`, gated)

`PostgresStore` mengimplementasi `Store` lewat `*pgxpool.Pool`. Memetakan error pgx (no rows → `ErrNotFound`, unique violation `23505` → `ErrDuplicate`). Lulus contract test yang SAMA dengan MemStore.

- [ ] **Step 1: Tulis test yang gagal (gated, pakai contract test yang ada)**

Tambahkan ke `internal/db/contract_test.go`:
```go
func TestPostgresStoreContract(t *testing.T) {
	pool := testPool(t) // skip bila LUMERIS_TEST_DSN kosong
	ctx := context.Background()

	// Skema bersih + migrasi sebelum contract test.
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS characters, accounts, schema_migrations CASCADE`); err != nil {
		t.Fatalf("bersihkan skema: %v", err)
	}
	if err := RunMigrations(ctx, pool, MigrationsFS); err != nil {
		t.Fatalf("migrasi: %v", err)
	}

	testStore(t, NewPostgresStore(pool))
}
```

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/db/ -run TestPostgresStoreContract -v`
Expected: FAIL — `undefined: NewPostgresStore` (atau SKIP bila DSN kosong).

- [ ] **Step 3: Tulis implementasi minimal**

`internal/db/postgres.go`:
```go
package db

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
	"lumeris-go/internal/model"
)

// PostgresStore mengimplementasi Store di atas PostgreSQL via pgxpool.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore membungkus pool yang sudah dibuka.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// isUniqueViolation true bila err adalah pelanggaran UNIQUE Postgres (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (p *PostgresStore) CreateAccount(ctx context.Context, username, passwordHash string) (*model.Account, error) {
	acc := &model.Account{Username: username, PasswordHash: passwordHash}
	err := p.pool.QueryRow(ctx,
		`INSERT INTO accounts(username, password_hash) VALUES($1,$2) RETURNING id, gm_level, banned`,
		username, passwordHash,
	).Scan(&acc.ID, &acc.GMLevel, &acc.Banned)
	if isUniqueViolation(err) {
		return nil, ErrDuplicate
	}
	if err != nil {
		return nil, err
	}
	return acc, nil
}

func (p *PostgresStore) GetAccountByName(ctx context.Context, username string) (*model.Account, error) {
	acc := &model.Account{Username: username}
	err := p.pool.QueryRow(ctx,
		`SELECT id, password_hash, gm_level, banned FROM accounts WHERE username=$1`,
		username,
	).Scan(&acc.ID, &acc.PasswordHash, &acc.GMLevel, &acc.Banned)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return acc, nil
}

func (p *PostgresStore) CheckPassword(ctx context.Context, username, password string) (bool, error) {
	acc, err := p.GetAccountByName(ctx, username)
	if err != nil {
		return false, err
	}
	if bcrypt.CompareHashAndPassword([]byte(acc.PasswordHash), []byte(password)) != nil {
		return false, nil
	}
	return true, nil
}

func (p *PostgresStore) CharsByAccount(ctx context.Context, accountID int64) ([]*model.Character, error) {
	rows, err := p.pool.Query(ctx, selectCharCols+` WHERE account_id=$1 ORDER BY slot`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Character
	for rows.Next() {
		c, err := scanCharacter(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *PostgresStore) CreateCharacter(ctx context.Context, c *model.Character) error {
	err := p.pool.QueryRow(ctx,
		`INSERT INTO characters
		 (account_id, slot, name, job, level, map_id, x, y, hp, maxhp, sp, maxsp, str, dex, int_, vit, agi, mnd, appearance)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		 RETURNING id`,
		c.AccountID, c.Slot, c.Name, c.Job, c.Level, c.MapID, c.X, c.Y, c.HP, c.MaxHP, c.SP, c.MaxSP,
		c.Str, c.Dex, c.Int, c.Vit, c.Agi, c.Mnd, c.Appearance,
	).Scan(&c.ID)
	if isUniqueViolation(err) {
		return ErrDuplicate
	}
	return err
}

func (p *PostgresStore) DeleteCharacter(ctx context.Context, charID int64) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM characters WHERE id=$1`, charID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStore) LoadCharacter(ctx context.Context, charID int64) (*model.Character, error) {
	rows, err := p.pool.Query(ctx, selectCharCols+` WHERE id=$1`, charID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return nil, rows.Err()
		}
		return nil, ErrNotFound
	}
	return scanCharacter(rows)
}

func (p *PostgresStore) SaveCharacter(ctx context.Context, c *model.Character) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE characters SET
		 slot=$2, name=$3, job=$4, level=$5, map_id=$6, x=$7, y=$8, hp=$9, maxhp=$10, sp=$11, maxsp=$12,
		 str=$13, dex=$14, int_=$15, vit=$16, agi=$17, mnd=$18, appearance=$19
		 WHERE id=$1`,
		c.ID, c.Slot, c.Name, c.Job, c.Level, c.MapID, c.X, c.Y, c.HP, c.MaxHP, c.SP, c.MaxSP,
		c.Str, c.Dex, c.Int, c.Vit, c.Agi, c.Mnd, c.Appearance,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// selectCharCols = daftar kolom karakter, urut sesuai scanCharacter.
const selectCharCols = `SELECT id, account_id, slot, name, job, level, map_id, x, y, hp, maxhp, sp, maxsp, str, dex, int_, vit, agi, mnd, appearance FROM characters`

// scanCharacter membaca satu baris karakter (urut kolom = selectCharCols).
// pgx men-scan jsonb langsung ke struct Appearance (encoding/json di belakang layar).
func scanCharacter(rows pgx.Rows) (*model.Character, error) {
	c := &model.Character{}
	err := rows.Scan(
		&c.ID, &c.AccountID, &c.Slot, &c.Name, &c.Job, &c.Level, &c.MapID, &c.X, &c.Y,
		&c.HP, &c.MaxHP, &c.SP, &c.MaxSP, &c.Str, &c.Dex, &c.Int, &c.Vit, &c.Agi, &c.Mnd, &c.Appearance,
	)
	if err != nil {
		return nil, err
	}
	return c, nil
}
```

> **Catatan jsonb ↔ Appearance:** pgx v5 men-scan kolom `jsonb` ke sebuah struct Go bila tipenya didukung — namun perilaku default pgx untuk struct arbitrer lewat `jsonb` perlu diverifikasi (pgx mungaku butuh tipe terdaftar atau `[]byte` + `json.Unmarshal` manual). Di Step 4 verifikasi: bila `rows.Scan(&c.Appearance)` gagal untuk jsonb, ganti pola ke scan `[]byte` lalu `json.Unmarshal`, dan saat insert oper `c.Appearance` sebagai hasil `json.Marshal`. JANGAN menebak — jalankan contract test Postgres dan sesuaikan berdasarkan error nyata.

- [ ] **Step 4: Jalankan test thd Postgres nyata**

Pastikan Postgres jalan + `LUMERIS_TEST_DSN` di-set (lihat Task 6), lalu:
```bash
go test ./internal/db/ -run TestPostgresStoreContract -v
```
Expected: PASS. Bila scan jsonb gagal, terapkan perbaikan di catatan Step 3 dan ulang.

- [ ] **Step 5: Jalankan SELURUH suite db (Mem + Postgres) + vet**

Run:
```bash
go test ./internal/db/ -v
go vet ./internal/db/
```
Expected: TestMemStoreContract + TestPostgresStoreContract + migrasi + password semua PASS; vet bersih. Ini membuktikan KEDUA impl lulus kontrak identik.

- [ ] **Step 6: Commit**

```bash
git add internal/db/postgres.go internal/db/contract_test.go
git commit -m "feat(db): PostgresStore (pgxpool) lulus contract test sama dgn MemStore"
```

---

## Task 6: Konfig DSN + verifikasi end-to-end dengan Postgres Docker

**Files:**
- Modify: `lumeris-go/internal/config/config.go` (DSN sudah ada; tambah komentar/validasi bila perlu — cek dulu)
- Reference: tak ada file baru wajib; ini task verifikasi + dokumentasi cara start Postgres.

Memastikan seluruh lapisan db berfungsi end-to-end terhadap Postgres nyata, dan `config.Load()` sudah menyediakan DSN yang dipakai. (Config sudah punya `DBDSN` dari Plan 1.)

- [ ] **Step 1: Start Postgres via Docker**

```bash
docker run --rm -d --name lumeris-pg -e POSTGRES_USER=lumeris -e POSTGRES_PASSWORD=lumeris -e POSTGRES_DB=lumeris -p 5432:5432 postgres:16
```
Tunggu ~3 detik sampai siap (cek: `docker exec lumeris-pg pg_isready -U lumeris`).

- [ ] **Step 2: Jalankan SELURUH test db terhadap Postgres**

PowerShell:
```powershell
$env:LUMERIS_TEST_DSN = "postgres://lumeris:lumeris@localhost:5432/lumeris?sslmode=disable"
go test ./internal/db/ -v
```
Expected: TestMemStoreContract PASS, TestPostgresStoreContract PASS, TestRunMigrationsIdempotent PASS, TestHashPassword PASS. Tidak ada SKIP.

- [ ] **Step 3: Verifikasi config.Load menyediakan DSN**

Konfirmasi `internal/config/config.go` `Config.DBDSN` memuat `LUMERIS_DB_DSN` (sudah ada dari Plan 1). Bila default DSN-nya cocok untuk Docker compose (`postgres://lumeris:lumeris@db:5432/lumeris`), tak ada perubahan. Bila perlu sesuaikan default agar konsisten dengan compose Plan 6, lakukan edit minimal + jalankan `go test ./internal/config/`.

> Jangan tambah field config baru kecuali test/komponen Plan 3 membutuhkannya. DSN sudah cukup. `LUMERIS_TEST_DSN` adalah env test-only (tak masuk struct Config) — hanya dibaca di test.

- [ ] **Step 4: Stop Postgres test (bersih-bersih)**

```bash
docker stop lumeris-pg
```

- [ ] **Step 5: Jalankan seluruh repo suite (tanpa DSN → Postgres test SKIP) + vet**

```bash
go test ./...
go vet ./...
```
Expected: semua PASS; test Postgres SKIP (karena DSN tak di-set) tapi MemStore tetap menguji lapisan db. Membuktikan suite hijau di lingkungan tanpa DB.

- [ ] **Step 6: Commit (bila ada perubahan config)**

```bash
git add internal/config/
git commit -m "chore(config): selaraskan default DSN untuk lapisan db"
```
(Bila tak ada perubahan config, lewati commit ini.)

---

## Self-Review (dijalankan saat menulis plan)

- **Spec coverage:** Plan 3 menutup Bagian 3 spec (model data & skema PostgreSQL): interface `Store` persis 8 method, model `Account`/`Character`/`Actor`, skema 2 tabel + `schema_migrations`, bcrypt, migrasi otomatis. Tambahan di luar spec (disetujui user): `MemStore` + contract test ganda. Wiring `Store` ke server (`main`/handler) = Plan 4. Docker compose penuh = Plan 6 (Plan 3 cuma start Postgres manual untuk test).
- **Placeholder scan:** Tidak ada `TBD`/`TODO`. Dua catatan "verifikasi, jangan tebak" DISENGAJA dan benar: (a) path embed `../../migrations` (Task 4 Step 4-5) — embed Go punya batasan path; plan beri jalur alternatif konkret bila gagal. (b) scan jsonb → struct Appearance (Task 5 Step 3-4) — perilaku pgx v5 untuk jsonb↔struct arbitrer harus diuji thd DB nyata; plan beri perbaikan konkret (`[]byte`+json.Marshal/Unmarshal). Keduanya punya test nyata (gated Postgres) sebagai sumber kebenaran, bukan tebakan.
- **Type consistency:** `Store` interface (Task 2) dipakai identik oleh `MemStore` (Task 3) & `PostgresStore` (Task 5); `testStore(t, Store)` (Task 3) dipakai ulang Task 5. `model.Account`/`Character`/`Appearance`/`Actor` (Task 1) dipakai konsisten. `ErrNotFound`/`ErrDuplicate` (Task 2) dikembalikan kedua impl & diuji via `errors.Is`. `HashPassword` (Task 2) dipakai contract test & (nanti) login Plan 4. `RunMigrations(ctx, *pgxpool.Pool, fs.FS)` + `MigrationsFS` (Task 4) dipakai migrate_test & TestPostgresStoreContract (Task 5). `NewMemStore()`/`NewPostgresStore(pool)` konsisten. Kolom `int_` ↔ field Go `Int` konsisten antara skema (Task 4), INSERT/UPDATE/SELECT (Task 5).
- **Guardrails:** MemStore `clone*` cegah aliasing. Migrasi pakai transaksi per-file (atomic) + idempoten (cek `schema_migrations`). pgx error dipetakan ke sentinel. `LUMERIS_TEST_DSN` gating → suite hijau offline. Tak ada secret di kode (DSN dari env). bcrypt cost default (bukan plaintext).

---

## Lingkup Plan berikutnya (BUKAN Plan 3)

- **Plan 4 — Login flow:** listener Validation(:12022) + Login(:12023), handler opcode (version/login/char-create/select/request-map), `session.Registry` token sekali-pakai, wiring `Store` + `config` ke `cmd/lumeris-go/main.go`, auto-create akun (panggil `HashPassword`+`CreateAccount`). Pakai hook dari memory `[[plan4-session-extension-points]]`.
- **Plan 5 — Map:** spawn + movement + chat, tick loop; isi field live `Actor`.
- **Plan 6 — Docker:** Dockerfile multi-stage + docker-compose (app + postgres), `RunMigrations` saat boot.
