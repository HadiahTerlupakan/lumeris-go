# Lumeris-Go Plan 1: Fondasi (Skeleton + Config + Packet + Kripto) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Membangun fondasi terisolasi & teruji untuk lumeris-go: skeleton modul Go, loader config dari environment, packet primitive big-endian (replika `SagaLib/Packet.cs`), dan lapisan kripto DH + AES-128-ECB (replika `SagaLib/Encryption.cs`) — semuanya diverifikasi unit test, tanpa perlu klien/Docker/opcode map.

**Architecture:** Monolith berlapis (1 proses Go, nanti 3 listener TCP). Plan 1 hanya menyiapkan lapisan paling bawah yang dipakai semua lapisan di atasnya: `internal/config`, `internal/protocol` (packet + crypto). Tidak ada jaringan/DB di plan ini. Tiap unit punya tanggung jawab tunggal dan diuji terpisah.

**Tech Stack:** Go 1.26, `math/big` (DH modPow), `crypto/aes` + `crypto/cipher` (AES block), `golang.org/x/text/encoding/japanese` (Shift_JIS), testing bawaan Go.

**Sumber kebenaran byte-exact (WAJIB dibaca saat ragu):**
- `C:\Users\RASYA\Documents\Lumeris-Project\SagaLib\Packet.cs` — primitif integer/string.
- `C:\Users\RASYA\Documents\Lumeris-Project\SagaLib\Encryption.cs` — DH + AES.

**Fakta byte-exact yang HARUS direplikasi (jangan ditebak):**
1. Integer multi-byte = **big-endian** (`PutUShort/PutUInt/PutShort/PutInt/PutLong/PutULong` membalik byte via `Array.Reverse`).
2. **PENGECUALIAN: `float` = little-endian** — `PutFloat` TIDAK membalik byte (`BitConverter.GetBytes(s).CopyTo` langsung). Jangan samakan dengan integer.
3. `offset` awal sebuah packet = **4** (2 byte size + 2 byte ID dilewati).
4. String = **Shift_JIS** (`Global.Unicode`). Format `PutString`: 1 byte panjang + bytes(`s` + `\0`). `PutTSTR`: 1 byte panjang + bytes(`s`) tanpa null.
5. DH: modulus 128-byte hex (lihat Task 6), base = **2**, privateKey default = **2** (`MakePrivateKey` jarang dipakai). `GetKeyExchangeBytes = 2^priv mod M`. `MakeAESKey(A) = (A^priv mod M)`, ambil **16 byte pertama**, lalu tiap nibble (atas & bawah tiap byte) **jika > 9 dikurangi 9**.
6. AES = **AES-128, mode ECB, padding None**, IV diabaikan (ECB). Enkrip/dekrip dilakukan **manual per-blok 16 byte** mulai dari `offset` (sisa < 16 byte di-transform apa adanya — lihat loop C# `Decrypt`).
7. `SetLength`: tulis `(data.Length - 4)` sebagai **big-endian uint** ke 4 byte pertama. (CATATAN: di C# size disimpan di 4 byte, tapi wire SIZE = 2 byte; ditangani di framing plan berikutnya — Plan 1 cukup replika fungsi apa adanya + uji.)

---

## File Structure

```
lumeris-go/
├── go.mod                              → module lumeris-go, go 1.26
├── internal/
│   ├── config/
│   │   ├── config.go                   → struct Config + Load() dari env var
│   │   └── config_test.go
│   └── protocol/
│       ├── packet.go                   → type Packet + Get/Put primitives (big-endian, float LE)
│       ├── packet_test.go
│       ├── crypto.go                   → type Crypto (DH + AES-ECB), modulus, MakeAESKey, Encrypt/Decrypt
│       └── crypto_test.go
```

Pemisahan: `config` (input lingkungan) vs `protocol` (wire). `packet.go` dan `crypto.go` dipisah karena tanggung jawab beda (serialisasi vs enkripsi) dan diuji terpisah.

---

## Task 1: Inisialisasi modul Go

**Files:**
- Create: `lumeris-go/go.mod`

- [ ] **Step 1: Inisialisasi modul**

Run (dari folder `lumeris-go`):
```bash
go mod init lumeris-go
```
Expected: membuat `go.mod` berisi `module lumeris-go` dan baris `go 1.26`.

- [ ] **Step 2: Verifikasi**

Run: `go mod verify`
Expected: `all modules verified` (atau tidak ada error; belum ada dependensi).

- [ ] **Step 3: Commit**

```bash
git add go.mod
git commit -m "chore: init go module lumeris-go"
```

---

## Task 2: Config loader dari environment variable

**Files:**
- Create: `lumeris-go/internal/config/config.go`
- Test: `lumeris-go/internal/config/config_test.go`

- [ ] **Step 1: Tulis test yang gagal**

`internal/config/config_test.go`:
```go
package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	t.Setenv("LUMERIS_DB_DSN", "")
	t.Setenv("LUMERIS_PORT_VALIDATION", "")
	t.Setenv("LUMERIS_PORT_LOGIN", "")
	t.Setenv("LUMERIS_PORT_MAP", "")
	t.Setenv("LUMERIS_PUBLIC_IP", "")
	t.Setenv("LUMERIS_CLIENT_ENCODING", "")

	c := Load()

	if c.PortValidation != 12022 {
		t.Errorf("PortValidation = %d, mau 12022", c.PortValidation)
	}
	if c.PortLogin != 12023 {
		t.Errorf("PortLogin = %d, mau 12023", c.PortLogin)
	}
	if c.PortMap != 12024 {
		t.Errorf("PortMap = %d, mau 12024", c.PortMap)
	}
	if c.PublicIP != "127.0.0.1" {
		t.Errorf("PublicIP = %q, mau 127.0.0.1", c.PublicIP)
	}
	if c.ClientEncoding != "Shift_JIS" {
		t.Errorf("ClientEncoding = %q, mau Shift_JIS", c.ClientEncoding)
	}
}

func TestLoadOverride(t *testing.T) {
	t.Setenv("LUMERIS_PORT_MAP", "13024")
	t.Setenv("LUMERIS_PUBLIC_IP", "10.0.0.5")
	t.Setenv("LUMERIS_DB_DSN", "postgres://u:p@db:5432/lumeris")

	c := Load()

	if c.PortMap != 13024 {
		t.Errorf("PortMap = %d, mau 13024", c.PortMap)
	}
	if c.PublicIP != "10.0.0.5" {
		t.Errorf("PublicIP = %q, mau 10.0.0.5", c.PublicIP)
	}
	if c.DBDSN != "postgres://u:p@db:5432/lumeris" {
		t.Errorf("DBDSN = %q salah", c.DBDSN)
	}
}
```

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/config/ -run TestLoad -v`
Expected: FAIL — `undefined: Load` / package tidak compile.

- [ ] **Step 3: Tulis implementasi minimal**

`internal/config/config.go`:
```go
package config

import (
	"os"
	"strconv"
)

// Config menampung seluruh konfigurasi server yang dibaca dari environment.
type Config struct {
	DBDSN          string
	PortValidation int
	PortLogin      int
	PortMap        int
	PublicIP       string
	ClientEncoding string
}

// Load membaca konfigurasi dari environment variable, memakai default bila kosong.
func Load() Config {
	return Config{
		DBDSN:          envStr("LUMERIS_DB_DSN", "postgres://lumeris:lumeris@localhost:5432/lumeris?sslmode=disable"),
		PortValidation: envInt("LUMERIS_PORT_VALIDATION", 12022),
		PortLogin:      envInt("LUMERIS_PORT_LOGIN", 12023),
		PortMap:        envInt("LUMERIS_PORT_MAP", 12024),
		PublicIP:       envStr("LUMERIS_PUBLIC_IP", "127.0.0.1"),
		ClientEncoding: envStr("LUMERIS_CLIENT_ENCODING", "Shift_JIS"),
	}
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
```

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/config/ -run TestLoad -v`
Expected: PASS (TestLoadDefaults, TestLoadOverride).

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): loader config dari environment variable"
```

---

## Task 3: Packet primitive — byte tunggal & konstruksi dasar

**Files:**
- Create: `lumeris-go/internal/protocol/packet.go`
- Test: `lumeris-go/internal/protocol/packet_test.go`

- [ ] **Step 1: Tulis test yang gagal**

`internal/protocol/packet_test.go`:
```go
package protocol

import "testing"

func TestNewPacketOffsetIs4(t *testing.T) {
	p := NewPacket(10)
	if p.Offset != 4 {
		t.Errorf("Offset awal = %d, mau 4", p.Offset)
	}
	if len(p.Data) != 10 {
		t.Errorf("len(Data) = %d, mau 10", len(p.Data))
	}
}

func TestPutGetByte(t *testing.T) {
	p := NewPacket(8)
	p.PutByteAt(0xAB, 4)
	if got := p.GetByteAt(4); got != 0xAB {
		t.Errorf("GetByteAt(4) = %#x, mau 0xab", got)
	}
	if p.Offset != 5 {
		t.Errorf("Offset setelah PutByteAt = %d, mau 5", p.Offset)
	}
}
```

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/protocol/ -run TestNewPacket -v`
Expected: FAIL — `undefined: NewPacket`.

- [ ] **Step 3: Tulis implementasi minimal**

`internal/protocol/packet.go`:
```go
package protocol

// Packet adalah unit serialisasi wire ECO: SIZE(2) | ID(2) | DATA.
// Integer multi-byte big-endian; float little-endian (lihat PutFloat).
// Offset awal = 4 (lewati 2 byte size + 2 byte id), replika SagaLib/Packet.cs.
type Packet struct {
	Data   []byte
	Offset int
}

// NewPacket membuat packet dengan Data sepanjang length, Offset di 4.
func NewPacket(length int) *Packet {
	return &Packet{Data: make([]byte, length), Offset: 4}
}

// ensureLen memperbesar Data agar minimal sepanjang n.
func (p *Packet) ensureLen(n int) {
	if len(p.Data) < n {
		buf := make([]byte, n)
		copy(buf, p.Data)
		p.Data = buf
	}
}

// GetByteAt membaca 1 byte di index dan menyetel Offset ke index+1.
func (p *Packet) GetByteAt(index int) byte {
	p.Offset = index + 1
	return p.Data[index]
}

// PutByteAt menulis 1 byte di index dan menyetel Offset ke index+1.
func (p *Packet) PutByteAt(b byte, index int) {
	p.ensureLen(index + 1)
	p.Data[index] = b
	p.Offset = index + 1
}
```

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/protocol/ -run "TestNewPacket|TestPutGetByte" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/protocol/packet.go internal/protocol/packet_test.go
git commit -m "feat(protocol): Packet primitive byte + konstruksi (offset=4)"
```

---

## Task 4: Packet primitive — integer big-endian + float little-endian

**Files:**
- Modify: `lumeris-go/internal/protocol/packet.go`
- Test: `lumeris-go/internal/protocol/packet_test.go`

- [ ] **Step 1: Tulis test yang gagal**

Tambahkan ke `internal/protocol/packet_test.go`:
```go
func TestPutUShortBigEndian(t *testing.T) {
	p := NewPacket(8)
	p.PutUShortAt(0x1234, 4)
	// big-endian: byte tinggi dulu
	if p.Data[4] != 0x12 || p.Data[5] != 0x34 {
		t.Errorf("bytes = %#x %#x, mau 0x12 0x34", p.Data[4], p.Data[5])
	}
	if got := p.GetUShortAt(4); got != 0x1234 {
		t.Errorf("GetUShortAt = %#x, mau 0x1234", got)
	}
}

func TestPutUIntBigEndian(t *testing.T) {
	p := NewPacket(12)
	p.PutUIntAt(0x11223344, 4)
	if p.Data[4] != 0x11 || p.Data[5] != 0x22 || p.Data[6] != 0x33 || p.Data[7] != 0x44 {
		t.Errorf("bytes = %#x %#x %#x %#x, mau 11 22 33 44", p.Data[4], p.Data[5], p.Data[6], p.Data[7])
	}
	if got := p.GetUIntAt(4); got != 0x11223344 {
		t.Errorf("GetUIntAt = %#x, mau 0x11223344", got)
	}
}

func TestPutFloatLittleEndian(t *testing.T) {
	// PENTING: float TIDAK dibalik (little-endian), beda dari integer.
	p := NewPacket(12)
	p.PutFloatAt(1.0, 4) // IEEE754 1.0f = 0x3F800000; LE byte = 00 00 80 3F
	if p.Data[4] != 0x00 || p.Data[5] != 0x00 || p.Data[6] != 0x80 || p.Data[7] != 0x3F {
		t.Errorf("bytes = %#x %#x %#x %#x, mau 00 00 80 3F (little-endian)", p.Data[4], p.Data[5], p.Data[6], p.Data[7])
	}
	if got := p.GetFloatAt(4); got != 1.0 {
		t.Errorf("GetFloatAt = %v, mau 1.0", got)
	}
}
```

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/protocol/ -run "BigEndian|Float" -v`
Expected: FAIL — `undefined: PutUShortAt` dll.

- [ ] **Step 3: Tulis implementasi minimal**

Tambahkan ke `internal/protocol/packet.go`:
```go
import (
	"encoding/binary"
	"math"
)

// --- ushort (big-endian) ---

func (p *Packet) PutUShortAt(v uint16, index int) {
	p.ensureLen(index + 2)
	binary.BigEndian.PutUint16(p.Data[index:], v)
	p.Offset = index + 2
}

func (p *Packet) GetUShortAt(index int) uint16 {
	p.Offset = index + 2
	return binary.BigEndian.Uint16(p.Data[index:])
}

// --- uint (big-endian) ---

func (p *Packet) PutUIntAt(v uint32, index int) {
	p.ensureLen(index + 4)
	binary.BigEndian.PutUint32(p.Data[index:], v)
	p.Offset = index + 4
}

func (p *Packet) GetUIntAt(index int) uint32 {
	p.Offset = index + 4
	return binary.BigEndian.Uint32(p.Data[index:])
}

// --- float (LITTLE-endian — replika BitConverter tanpa Reverse di Packet.cs) ---

func (p *Packet) PutFloatAt(v float32, index int) {
	p.ensureLen(index + 4)
	binary.LittleEndian.PutUint32(p.Data[index:], math.Float32bits(v))
	p.Offset = index + 4
}

func (p *Packet) GetFloatAt(index int) float32 {
	p.Offset = index + 4
	return math.Float32frombits(binary.LittleEndian.Uint32(p.Data[index:]))
}
```

> Catatan import: gabungkan blok `import` ini dengan file yang sudah ada (Go hanya boleh satu blok import per file). Jika `packet.go` belum punya import, jadikan satu blok berisi `encoding/binary` dan `math`.

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/protocol/ -run "BigEndian|Float" -v`
Expected: PASS (3 test).

- [ ] **Step 5: Commit**

```bash
git add internal/protocol/packet.go internal/protocol/packet_test.go
git commit -m "feat(protocol): integer big-endian + float little-endian primitives"
```

---

## Task 5: Packet primitive — string Shift_JIS + SetLength

**Files:**
- Modify: `lumeris-go/internal/protocol/packet.go`
- Test: `lumeris-go/internal/protocol/packet_test.go`
- Add dependency: `golang.org/x/text`

- [ ] **Step 1: Tambah dependensi Shift_JIS**

Run (dari `lumeris-go`):
```bash
go get golang.org/x/text/encoding/japanese
```
Expected: `go.mod`/`go.sum` ter-update dengan `golang.org/x/text`.

- [ ] **Step 2: Tulis test yang gagal**

Tambahkan ke `internal/protocol/packet_test.go`:
```go
func TestPutGetStringASCII(t *testing.T) {
	p := NewPacket(0)
	p.Data = make([]byte, 32)
	p.PutStringAt("Hi", 4)
	// format: [len][bytes "Hi\0"]; len = panjang "Hi\0" = 3
	if p.Data[4] != 3 {
		t.Errorf("len prefix = %d, mau 3", p.Data[4])
	}
	if p.Data[5] != 'H' || p.Data[6] != 'i' || p.Data[7] != 0 {
		t.Errorf("bytes string salah: %v", p.Data[5:8])
	}
}

func TestSetLengthBigEndian(t *testing.T) {
	p := NewPacket(10) // data.Length=10 -> tLen = 10-4 = 6
	p.SetLength()
	// big-endian uint32 dari 6 di 4 byte pertama
	if p.Data[0] != 0 || p.Data[1] != 0 || p.Data[2] != 0 || p.Data[3] != 6 {
		t.Errorf("SetLength bytes = %v, mau [0 0 0 6]", p.Data[0:4])
	}
}

func TestShiftJISRoundTrip(t *testing.T) {
	p := NewPacket(0)
	p.Data = make([]byte, 64)
	jp := "ロト" // katakana, hanya ada di Shift_JIS multi-byte
	p.PutStringAt(jp, 4)
	got := p.GetStringAt(4)
	if got != jp {
		t.Errorf("round-trip Shift_JIS = %q, mau %q", got, jp)
	}
}
```

- [ ] **Step 3: Jalankan test, pastikan gagal**

Run: `go test ./internal/protocol/ -run "String|SetLength|ShiftJIS" -v`
Expected: FAIL — `undefined: PutStringAt` dll.

- [ ] **Step 4: Tulis implementasi minimal**

Tambahkan ke `internal/protocol/packet.go` (tambahkan import yang diperlukan ke blok import yang ada):
```go
import (
	"golang.org/x/text/encoding/japanese"
)

// sjis adalah encoder/decoder Shift_JIS (padanan Global.Unicode di C#).
var sjis = japanese.ShiftJIS

func encodeSJIS(s string) []byte {
	b, err := sjis.NewEncoder().Bytes([]byte(s))
	if err != nil {
		return []byte(s) // fallback: kirim apa adanya bila tak terkonversi
	}
	return b
}

func decodeSJIS(b []byte) string {
	out, err := sjis.NewDecoder().Bytes(b)
	if err != nil {
		return string(b)
	}
	return string(out)
}

// PutStringAt menulis string ber-prefix panjang: [1 byte len][Shift_JIS(s+"\0")].
func (p *Packet) PutStringAt(s string, index int) {
	buf := encodeSJIS(s + "\x00")
	p.ensureLen(index + 1 + len(buf))
	p.Data[index] = byte(len(buf))
	copy(p.Data[index+1:], buf)
	p.Offset = index + 1 + len(buf)
}

// GetStringAt membaca string yang berakhir pada terminator 2-byte nol,
// mengikuti logika Packet.GetString di C# (Shift_JIS).
func (p *Packet) GetStringAt(index int) string {
	end := index
	for end < len(p.Data)-1 {
		if p.Data[end] == 0 && p.Data[end+1] == 0 {
			if (end-index)%2 != 0 {
				end++
			}
			break
		}
		end++
	}
	p.Offset = end + 2
	// Catatan: PutStringAt menaruh 1 byte len di depan; GetStringAt di sini
	// membaca dari index yang menunjuk ke awal BYTE STRING (bukan byte len).
	return decodeSJIS(trimTrailingNul(p.Data[index:end]))
}

func trimTrailingNul(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}

// SetLength menulis (len(Data)-4) sebagai big-endian uint32 ke 4 byte pertama.
func (p *Packet) SetLength() {
	tLen := uint32(len(p.Data) - 4)
	binary.BigEndian.PutUint32(p.Data[0:], tLen)
}
```

> **Penjelasan test string:** `PutStringAt` menulis `[len]` di `index`, lalu byte string mulai `index+1`. Test `TestPutGetStringASCII` memeriksa byte mentah langsung. `TestShiftJISRoundTrip` memanggil `GetStringAt(4)` — tapi `PutStringAt` menaruh byte-len di index 4, string mulai index 5. Karena itu pada test round-trip, panggil `p.GetStringAt(5)` bukan `4`. PERBAIKI test `TestShiftJISRoundTrip` agar membaca dari `5`:
> ```go
> got := p.GetStringAt(5)
> ```
> (byte len di index 4, payload Shift_JIS mulai index 5.)

- [ ] **Step 5: Perbaiki offset baca di test round-trip**

Edit `TestShiftJISRoundTrip` di `packet_test.go`: ganti `p.GetStringAt(4)` menjadi `p.GetStringAt(5)`.

- [ ] **Step 6: Jalankan test, pastikan lulus**

Run: `go test ./internal/protocol/ -run "String|SetLength|ShiftJIS" -v`
Expected: PASS (3 test).

- [ ] **Step 7: Jalankan SELURUH test protocol**

Run: `go test ./internal/protocol/ -v`
Expected: PASS semua (byte, integer, float, string, setlength).

- [ ] **Step 8: Commit**

```bash
git add go.mod go.sum internal/protocol/packet.go internal/protocol/packet_test.go
git commit -m "feat(protocol): string Shift_JIS round-trip + SetLength big-endian"
```

---

## Task 6: Kripto — Diffie-Hellman key exchange

**Files:**
- Create: `lumeris-go/internal/protocol/crypto.go`
- Test: `lumeris-go/internal/protocol/crypto_test.go`

- [ ] **Step 1: Tulis test yang gagal**

`internal/protocol/crypto_test.go`:
```go
package protocol

import (
	"bytes"
	"testing"
)

func TestKeyExchangeDefaultPriv(t *testing.T) {
	// privateKey default = 2, base = 2 => GetKeyExchangeBytes = 2^2 mod M = 4.
	c := NewCrypto()
	kx := c.GetKeyExchangeBytes()
	// 4 sebagai BigInteger.getBytes() (big-endian, minimal) = [0x04].
	if len(kx) == 0 || kx[len(kx)-1] != 0x04 {
		t.Errorf("key exchange terakhir = %v, mau diakhiri 0x04", kx)
	}
}

func TestMakeAESKeyNibbleReduction(t *testing.T) {
	c := NewCrypto()
	// Susun aesKey langsung untuk menguji reduksi nibble (>9 -> -9).
	// 0xFA: nibble atas F(15)>9 ->6, bawah A(10)>9 ->1 => 0x61
	in := []byte{0xFA, 0x09, 0x90, 0x00}
	out := reduceNibbles(in)
	want := []byte{0x61, 0x09, 0x90, 0x00}
	if !bytes.Equal(out, want) {
		t.Errorf("reduceNibbles = %v, mau %v", out, want)
	}
}
```

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/protocol/ -run "KeyExchange|Nibble" -v`
Expected: FAIL — `undefined: NewCrypto` / `reduceNibbles`.

- [ ] **Step 3: Tulis implementasi minimal**

`internal/protocol/crypto.go`:
```go
package protocol

import (
	"math/big"
)

// modulusHex adalah modulus DH 128-byte (replika persis Encryption.Module di C#).
const modulusHex = "f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6" +
	"f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212c" +
	"b52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fab" +
	"d00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e92f78c7"

// Crypto memegang state kripto satu koneksi: kunci DH + kunci AES.
type Crypto struct {
	modulus    *big.Int
	base       *big.Int
	privateKey *big.Int
	aesKey     []byte // 16 byte saat siap, nil sebelum handshake
}

// NewCrypto membuat state dengan base=2 dan privateKey default=2 (seperti C#).
func NewCrypto() *Crypto {
	m, _ := new(big.Int).SetString(modulusHex, 16)
	return &Crypto{
		modulus:    m,
		base:       big.NewInt(2),
		privateKey: big.NewInt(2),
	}
}

// GetKeyExchangeBytes = base^privateKey mod modulus, big-endian (seperti getBytes()).
func (c *Crypto) GetKeyExchangeBytes() []byte {
	r := new(big.Int).Exp(c.base, c.privateKey, c.modulus)
	return r.Bytes()
}

// reduceNibbles: untuk tiap byte, jika nibble atas/bawah > 9 maka dikurangi 9.
func reduceNibbles(in []byte) []byte {
	out := make([]byte, len(in))
	for i, b := range in {
		hi := b >> 4
		lo := b & 0x0F
		if hi > 9 {
			hi -= 9
		}
		if lo > 9 {
			lo -= 9
		}
		out[i] = (hi << 4) | lo
	}
	return out
}

// MakeAESKey menghitung kunci AES dari blob key-exchange milik lawan bicara.
// R = A^privateKey mod modulus; ambil 16 byte pertama; reduksi nibble.
func (c *Crypto) MakeAESKey(peerKeyExchange []byte) {
	a := new(big.Int).SetBytes(peerKeyExchange)
	r := new(big.Int).Exp(a, c.privateKey, c.modulus).Bytes()
	key := make([]byte, 16)
	copy(key, r) // 16 byte pertama (big.Int.Bytes big-endian)
	c.aesKey = reduceNibbles(key)
}

// IsReady true bila kunci AES sudah dibuat.
func (c *Crypto) IsReady() bool { return c.aesKey != nil }
```

> **Catatan akurasi `MakeAESKey`:** di C# `Array.Copy(R, aesKey, 16)` menyalin 16 byte pertama dari `R` (hasil `getBytes()` big-endian, panjang ~128 byte). `copy(key, r)` di Go menyalin dari awal slice `r` — setara selama `len(r) >= 16`. Validasi byte-exact-nya dilakukan di Task 8 lewat capture; bila meleset, sumber paling mungkin adalah perbedaan panjang `getBytes()` (C# Mono.BigInteger) vs `big.Int.Bytes()` saat ada leading zero — tangani di Task 8 dengan padding kiri bila perlu.

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/protocol/ -run "KeyExchange|Nibble" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/protocol/crypto.go internal/protocol/crypto_test.go
git commit -m "feat(protocol): DH key exchange + nibble reduction (replika Encryption.cs)"
```

---

## Task 7: Kripto — AES-128-ECB Encrypt/Decrypt manual per-blok

**Files:**
- Modify: `lumeris-go/internal/protocol/crypto.go`
- Test: `lumeris-go/internal/protocol/crypto_test.go`

- [ ] **Step 1: Tulis test yang gagal**

Tambahkan ke `internal/protocol/crypto_test.go`:
```go
func TestAESRoundTripFromOffset(t *testing.T) {
	c := NewCrypto()
	c.aesKey = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	// Data 4 byte header (tidak dienkripsi) + 32 byte payload.
	src := make([]byte, 36)
	for i := range src {
		src[i] = byte(i)
	}
	const off = 4

	enc := c.Encrypt(src, off)
	// 4 byte pertama tidak berubah (di bawah offset)
	for i := 0; i < off; i++ {
		if enc[i] != src[i] {
			t.Errorf("header byte %d berubah", i)
		}
	}
	dec := c.Decrypt(enc, off)
	if !bytes.Equal(dec, src) {
		t.Errorf("round-trip AES gagal:\n  src=%v\n  dec=%v", src, dec)
	}
}

func TestAESNoKeyIsPassthrough(t *testing.T) {
	c := NewCrypto() // aesKey nil
	src := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if got := c.Encrypt(src, 4); !bytes.Equal(got, src) {
		t.Errorf("tanpa kunci, Encrypt harus passthrough")
	}
}

func TestAESPartialTrailingBlock(t *testing.T) {
	// Sisa < 16 byte: C# tetap men-transform blok pendek apa adanya.
	c := NewCrypto()
	c.aesKey = []byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	src := make([]byte, 4+20) // payload 20 byte = 1 blok 16 + 1 blok 4
	for i := range src {
		src[i] = byte(i * 3)
	}
	dec := c.Decrypt(c.Encrypt(src, 4), 4)
	if !bytes.Equal(dec, src) {
		t.Errorf("round-trip blok parsial gagal")
	}
}
```

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/protocol/ -run "AES" -v`
Expected: FAIL — `undefined: (*Crypto).Encrypt`.

- [ ] **Step 3: Tulis implementasi minimal**

Tambahkan ke `internal/protocol/crypto.go` (gabungkan import `crypto/aes`):
```go
import (
	"crypto/aes"
)

// Encrypt mengenkripsi src mulai dari offset memakai AES-128-ECB tanpa padding,
// blok-per-blok 16 byte; sisa < 16 byte ditransform apa adanya (replika C#).
func (c *Crypto) Encrypt(src []byte, offset int) []byte {
	if c.aesKey == nil || offset >= len(src) {
		return src
	}
	block, err := aes.NewCipher(c.aesKey)
	if err != nil {
		return src
	}
	out := make([]byte, len(src))
	copy(out, src)
	transformECB(block.Encrypt, src, out, offset)
	return out
}

// Decrypt kebalikan dari Encrypt.
func (c *Crypto) Decrypt(src []byte, offset int) []byte {
	if c.aesKey == nil || offset >= len(src) {
		return src
	}
	block, err := aes.NewCipher(c.aesKey)
	if err != nil {
		return src
	}
	out := make([]byte, len(src))
	copy(out, src)
	transformECB(block.Decrypt, src, out, offset)
	return out
}

// transformECB menjalankan fn (Encrypt/Decrypt blok 16-byte) atas src[offset:],
// menyalin hasil ke out[offset:]. Untuk blok penuh 16 byte panggil fn langsung.
// Untuk sisa < 16 byte, salin ke buffer 16-byte, transform, ambil sebanyak sisa
// (meniru perilaku TransformBlock C# pada blok pendek).
func transformECB(fn func(dst, src []byte), src, out []byte, offset int) {
	for i := offset; i < len(src); i += 16 {
		n := 16
		if len(src)-i < 16 {
			n = len(src) - i
		}
		if n == 16 {
			fn(out[i:i+16], src[i:i+16])
		} else {
			tmp := make([]byte, 16)
			copy(tmp, src[i:i+n])
			fn(tmp, tmp)
			copy(out[i:i+n], tmp[:n])
		}
	}
}
```

> **Catatan blok parsial:** AES beroperasi pada blok 16 byte; `block.Encrypt` butuh tepat 16 byte. C# `TransformBlock` pada sisa pendek tetap memproses 16-byte internal lalu menyalin `n` byte. Replika di atas memakai buffer 16-byte yang di-pad nol. **Apakah ini byte-exact dengan C#** untuk blok parsial diverifikasi di Task 8 (capture). Bila ECO tidak pernah mengirim payload non-kelipatan-16 setelah offset, jalur ini tak terpakai — namun tetap diuji round-trip agar konsisten internal.

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/protocol/ -run "AES" -v`
Expected: PASS (3 test).

- [ ] **Step 5: Jalankan SELURUH test protocol + vet**

Run:
```bash
go test ./... -v
go vet ./...
```
Expected: semua PASS, `go vet` tanpa keluhan.

- [ ] **Step 6: Commit**

```bash
git add internal/protocol/crypto.go internal/protocol/crypto_test.go
git commit -m "feat(protocol): AES-128-ECB encrypt/decrypt manual per-blok"
```

---

## Task 8: Verifikasi byte-exact dari capture TomatoProxyTool

**Files:**
- Create: `lumeris-go/internal/protocol/vectors_test.go`
- Reference: capture proxy di `C:\Users\RASYA\Documents\Lumeris-Project\ProxyTool\TomatoProxyTool\bin\Debug\proxy_packets.log*` (lihat memori `eco_proxy_tool`)

> **Tujuan:** Plan 1 dianggap selesai hanya jika kripto/packet cocok byte-for-byte dengan trafik C# nyata. Task ini mengubah "kelihatannya benar" menjadi "terbukti benar" sebelum satu baris pun kode jaringan ditulis.

- [ ] **Step 1: Ambil 1 pasang vektor uji dari capture**

Buka log capture proxy terbaru. Cari frame handshake awal (key-exchange) ATAU satu packet S→C yang plaintext-nya diketahui. Catat sebagai hex: (a) `aesKey` yang dipakai sesi itu (atau blob key-exchange untuk menurunkannya), (b) bytes terenkripsi di wire, (c) plaintext yang diharapkan.

Jika belum ada capture yang cocok, jalankan proxy mengikuti memori `eco_proxy_tool` untuk merekam satu sesi login.

- [ ] **Step 2: Tulis test vektor (isi dengan hex NYATA dari Step 1)**

`internal/protocol/vectors_test.go` (template — ganti `__HEX__` dengan byte hasil capture):
```go
package protocol

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex tidak valid: %v", err)
	}
	return b
}

// Vektor dari capture TomatoProxyTool sesi nyata (Plan 1 Task 8 Step 1).
func TestDecryptMatchesCapture(t *testing.T) {
	aesKey := mustHex(t, "__HEX_AES_KEY_16_BYTE__")
	wire := mustHex(t, "__HEX_WIRE_BYTES__")       // termasuk header sampai offset
	want := mustHex(t, "__HEX_PLAINTEXT_BYTES__")  // plaintext yang diharapkan
	const offset = 4

	c := NewCrypto()
	c.aesKey = aesKey
	got := c.Decrypt(wire, offset)

	if !bytes.Equal(got[offset:], want[offset:]) {
		t.Errorf("decrypt != capture\n  got =%x\n  want=%x", got[offset:], want[offset:])
	}
}
```

- [ ] **Step 3: Jalankan test vektor**

Run: `go test ./internal/protocol/ -run TestDecryptMatchesCapture -v`
Expected: PASS. Jika FAIL, akar masalah paling mungkin (urut periksa): (1) panjang `big.Int.Bytes()` vs C# `getBytes()` saat ada leading-zero pada `MakeAESKey` — tambahkan left-pad ke 128 byte sebelum ambil 16 byte pertama; (2) offset salah; (3) byte order. Perbaiki di `crypto.go`, ulangi.

- [ ] **Step 4: (Bila Step 3 perlu perbaikan padding) sesuaikan MakeAESKey**

Jika capture mengharuskan, ubah `MakeAESKey` agar menormalkan panjang hasil modPow:
```go
func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
// di MakeAESKey: r := leftPad(new(big.Int).Exp(...).Bytes(), 128); copy(key, r)
```
Hanya terapkan bila Step 3 menunjukkan ketidakcocokan; jangan menebak.

- [ ] **Step 5: Commit**

```bash
git add internal/protocol/vectors_test.go internal/protocol/crypto.go
git commit -m "test(protocol): verifikasi kripto byte-exact dari capture proxy"
```

---

## Self-Review (sudah dijalankan saat menulis plan)

- **Spec coverage:** Plan 1 menutup bagian spec "Protokol & kripto" (primitif + DH + AES + Shift_JIS) dan "Config via env". Bagian Login/Map/DB/Docker = plan berikutnya (Plan 2+), sengaja di luar Plan 1.
- **Placeholder scan:** Satu-satunya placeholder yang DISENGAJA adalah `__HEX__` di Task 8 — itu memang harus diisi dari capture nyata saat eksekusi (tidak bisa ditebak; menebak = salah). Semua kode lain konkret.
- **Type consistency:** `Packet{Data, Offset}`, `Crypto{modulus, base, privateKey, aesKey}`, `NewPacket`, `NewCrypto`, `reduceNibbles`, `transformECB`, `Encrypt/Decrypt(src, offset)` konsisten di semua task. Nama method `*At` (PutUShortAt, dst.) konsisten.
- **Catatan byte-exact yang sengaja ditandai untuk verifikasi capture:** float little-endian (Task 4), blok AES parsial (Task 7), panjang getBytes/leftPad (Task 8).

---

## Lingkup Plan berikutnya (BUKAN bagian Plan 1)

- **Plan 2 — Framing & NetIO:** baca/tulis frame `SIZE|ID|DATA` dari TCP, dispatch `map[uint16]Handler`, integrasi `Crypto` per-koneksi, handshake versi 22-byte.
- **Plan 3 — DB & migrasi:** `internal/db` (interface Store + PostgresStore pgx), `migrations/001_init.sql`, bcrypt.
- **Plan 4 — Login flow:** listener 12022/12023, auto-create akun, char list/create/select, Registry handoff + token.
- **Plan 5 — Map:** listener 12024, handshake token, spawn, movement (0x11F9), chat.
- **Plan 6 — Docker:** Dockerfile multi-stage, docker-compose (app + postgres), migrasi otomatis, `.env.example`.
