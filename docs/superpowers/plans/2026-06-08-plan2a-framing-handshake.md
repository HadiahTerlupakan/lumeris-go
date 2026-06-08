# Lumeris-Go Plan 2A: Framing & Handshake-Crypto Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Menambah lapisan framing wire ECO (membongkar/menyusun frame `OUTER|INNER|sub-message terenkripsi`) dan kelengkapan handshake DH (MakePrivateKey + MakeAESKey berbasis hex-string) di `internal/protocol`, semuanya teruji offline dengan unit test + round-trip Go-ke-Go, tanpa jaringan.

**Architecture:** Lanjutan langsung Plan 1. Plan 1 memberi `Packet` (primitif) + `Crypto` (DH/AES blok). Plan 2A menambah: (1) `MakePrivateKey` & `MakeAESKey(hexString)` yang byte-exact dengan `Encryption.cs`, (2) `frame.go` — encode/decode satu frame wire penuh (outer 4-byte BE len, inner 4-byte BE len, lalu N sub-message `[len 2-byte BE][ID 2][data]` di region terenkripsi AES dari offset 8). Jaringan/Session/listener = Plan 2B (di luar plan ini).

**Tech Stack:** Go 1.26, `math/big` (DH), `crypto/aes` (sudah dipakai), `crypto/rand` + `crypto/sha1` (MakePrivateKey), testing bawaan.

**Sumber kebenaran byte-exact (WAJIB dibaca saat ragu):**
- `C:\Users\RASYA\Documents\Lumeris-Project\SagaLib\NetIO.cs` — framing (`ReceiveData` ~:449-560, `SendPacket` ~:655-752), handshake (`ReceiveKeyExchange` ~:240-294).
- `C:\Users\RASYA\Documents\Lumeris-Project\SagaLib\Encryption.cs` — `MakePrivateKey` (:30-36), `MakeAESKey(string)` (:45-61), `GetKeyExchangeBytes` (:38-43).

## Fakta byte-exact yang HARUS direplikasi (hasil RE, jangan ditebak)

### Framing wire (normal packet, post-handshake)
```
byte:  0  1  2  3 | 4  5  6  7 | 8 .................................
      [ OUTER N ]   [ INNER M ]  [ region terenkripsi AES-ECB, dari offset 8 ]
      BE uint32     BE uint32     berisi 1+ sub-message:
      plaintext     plaintext       [ len: 2-byte BE ][ ID: 2-byte ][ data... ]
```
- **OUTER N** (byte 0-3, BE uint32) = `len(frame) - 8` (jumlah byte di region terenkripsi). Di C# dihitung `data.Length-8` lalu `PutUInt(...,0)` (`NetIO.cs:691`). Saat baca: server baca 4 byte ini dulu, `Array.Reverse`→BE, `size = N+4`, lalu baca `N+...` byte sisanya (`NetIO.cs:387-430`).
- **INNER M** (byte 4-7, BE uint32) = panjang total semua sub-message (`= len(region)` setelah dekripsi, sebelum padding). Dibaca via `GetUInt(4)` (`NetIO.cs:526`).
- **Region terenkripsi** dimulai byte 8. Dekripsi: `Decrypt(raw, 8)`. Isi region = beberapa sub-message berturut-turut, DITAMBAH padding nol agar kelipatan 16 (untuk AES-ECB).
- **Sub-message**: prefix panjang **2-byte BE** (`firstLevelLength=2` untuk login & map — `LoginClient.cs:36`, `MapClient.cs:63`), lalu `[ID 2 byte][data]`. Loop baca: `offset` dari 0; `size = GetUShort(8+offset)`; `offset += 2`; `subData = GetBytes(size, 8+offset)`; `offset += size`; ulang selama `offset < M` (`NetIO.cs:530-559`).
- **Padding (kirim)**: `mod = 16 - ((len(data)-8) % 16)`; selalu tambah `mod` byte nol — artinya bila region SUDAH kelipatan 16, tetap ditambah 16 byte penuh (`mod` tak pernah 0) (`NetIO.cs:684-690`). Padding ditambahkan SEBELUM `PutUInt(N,0)` dan SEBELUM enkripsi.
- **Urutan kirim** (`SendPacket` `NetIO.cs:665-710`): mulai dari `[ID][data]` →(a) prepend 2 byte, tulis `len = (panjang ID+data)` sebagai sub-message len → (b) prepend 4 byte, tulis INNER M = `len-4` via SetLength → (c) prepend 4 byte (slot OUTER) → (d) padding → (e) `PutUInt(len-8, 0)` (OUTER) → (f) `Encrypt(data, 8)`. Enkripsi LANGKAH TERAKHIR.

### Handshake DH (server-side, plaintext, sebelum enkripsi)
Urutan (`NetIO.cs:240-294`, mode Server):
1. Klien connect → kirim **8 byte** (isi diabaikan server; hanya `len==8` yang penting).
2. Server kirim blob **529 byte** (`Packet(529)`), dikirim TANPA length-wrap & TANPA enkripsi:
   - `[0..3]` = `00 00 00 00` (slot, tak diisi)
   - `[4..7]` = BE uint32 `1` (`PutUInt(1,4)`)
   - `[8]` = `0x32` (`PutByte(0x32,8)`)
   - `[9..12]` = BE uint32 `0x100` (=256)
   - `[13..268]` = 256 char ASCII hex dari `Module` (128 byte), **huruf kecil** (`.ToLower()`)
   - `[269..272]` = BE uint32 `0x100`
   - `[273..528]` = 256 char ASCII hex dari `GetKeyExchangeBytes()` (pubkey server = `2^priv mod M`), **huruf besar** (`bytes2HexString` = `X2`)
   - **Catatan case asimetris**: modulus lowercase, pubkey uppercase. WAJIB direplikasi.
   - Sebelum bangun blob ini, server panggil `MakePrivateKey()` (`NetIO.cs:246`) → priv jadi angka acak besar (bukan 2), sehingga `GetKeyExchangeBytes()` menghasilkan 128 byte penuh.
3. Klien balas **260 byte**: `[0..3]` = BE `0x100`, `[4..259]` = 256 char ASCII hex pubkey klien.
4. Server: `keyBuf = GetBytes(256, 4)` (256 byte ASCII hex), `MakeAESKey(ASCII.GetString(keyBuf))` (`NetIO.cs:277-278`) → AES key siap → `StartPacketParsing()` (enkripsi nyala).

### MakeAESKey & MakePrivateKey (Encryption.cs)
- `MakeAESKey(string keyExchangeBytes)` (`:45-61`): `A = new BigInteger(keyExchangeBytes)` — **string 256-char hex di-parse sebagai BigInteger HEKSADESIMAL** (Mono.Math `BigInteger(string)` default mem-parse basis 10, TAPI input di sini hex; perilaku persis HARUS diverifikasi — lihat Task 5 verifikasi). `R = A.modPow(priv, M).getBytes()`; ambil 16 byte pertama; reduksi nibble (>9 → −9). **BERBEDA dari Plan 1** yang memakai `SetBytes([]byte)`.
- `MakePrivateKey()` (`:30-36`): isi `tmp[40]` lalu `privateKey = new BigInteger(tmp)`. Detail SHA1-nya tidak relevan untuk byte-exact ANTAR-SISI: tiap sisi punya priv sendiri; yang harus cocok hanya AES key turunan (simetris secara DH). Go boleh memakai priv acak besar (mis. 320-bit dari `crypto/rand`) — yang penting `1 < priv < M` dan stabil per koneksi.

---

## File Structure

```
lumeris-go/internal/protocol/
├── crypto.go          (MODIFIKASI) tambah MakePrivateKey + MakeAESKeyHex(hexString); pertahankan API lama
├── crypto_test.go     (MODIFIKASI) test MakePrivateKey + round-trip DH Go-ke-Go
├── frame.go           (BARU) DecodeFrame (region->sub-messages) + EncodeFrame (sub-messages->wire)
├── frame_test.go      (BARU) test framing dgn vektor + round-trip
└── handshake_vectors_test.go (BARU) verifikasi handshake byte-exact dari capture (Task 6)
```

Pemisahan: `crypto.go` = DH/AES (urusan kunci & blok), `frame.go` = struktur wire (urusan panjang & sub-message). Keduanya tanggung jawab beda, diuji terpisah.

---

## Task 1: MakePrivateKey — priv acak besar per koneksi

**Files:**
- Modify: `lumeris-go/internal/protocol/crypto.go`
- Test: `lumeris-go/internal/protocol/crypto_test.go`

- [ ] **Step 1: Tulis test yang gagal**

Tambahkan ke `internal/protocol/crypto_test.go`:
```go
func TestMakePrivateKeyProducesLargeDistinctKeys(t *testing.T) {
	c1 := NewCrypto()
	c1.MakePrivateKey()
	c2 := NewCrypto()
	c2.MakePrivateKey()

	// priv harus berubah dari default 2, dan acak (dua instance beda).
	if c1.privateKey.Cmp(big.NewInt(2)) == 0 {
		t.Errorf("privateKey masih 2 setelah MakePrivateKey")
	}
	if c1.privateKey.Cmp(c2.privateKey) == 0 {
		t.Errorf("dua MakePrivateKey menghasilkan priv identik (tidak acak)")
	}
	// pubkey sekarang harus 128 byte penuh (priv besar), bukan 1 byte.
	pub := c1.GetKeyExchangeBytes()
	if len(pub) < 100 {
		t.Errorf("pubkey hanya %d byte; priv tampak terlalu kecil", len(pub))
	}
}
```

Catatan: test ini memakai field `privateKey` (huruf kecil) langsung — boleh karena test berada di package `protocol` yang sama. Perlu import `math/big` di test (tambahkan bila belum ada).

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/protocol/ -run TestMakePrivateKey -v`
Expected: FAIL — `c1.MakePrivateKey undefined`.

- [ ] **Step 3: Tulis implementasi minimal**

Tambahkan ke `internal/protocol/crypto.go` (tambahkan `crypto/rand` ke import block yang ada):
```go
// MakePrivateKey mengacak privateKey menjadi bilangan besar (~320-bit) agar
// pubkey (base^priv mod M) berukuran penuh, seperti Encryption.MakePrivateKey di C#.
// Nilai persis priv tidak perlu cocok dengan C#: tiap sisi DH punya priv sendiri,
// hanya AES key turunan (simetris) yang harus sama.
func (c *Crypto) MakePrivateKey() {
	buf := make([]byte, 40)
	if _, err := rand.Read(buf); err != nil {
		// fallback deterministik sangat tak mungkin terpakai; tetap > 2.
		buf[0] = 0x6F
	}
	c.privateKey = new(big.Int).SetBytes(buf)
}
```

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/protocol/ -run TestMakePrivateKey -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/protocol/crypto.go internal/protocol/crypto_test.go
git commit -m "feat(protocol): MakePrivateKey (priv acak besar untuk handshake DH)"
```

---

## Task 2: MakeAESKeyHex — turunkan AES key dari pubkey hex peer

**Files:**
- Modify: `lumeris-go/internal/protocol/crypto.go`
- Test: `lumeris-go/internal/protocol/crypto_test.go`

C# `MakeAESKey(string)` menerima 256 char hex (pubkey peer), mem-parse sebagai BigInteger hex, lalu `A^priv mod M`, ambil 16 byte, reduksi nibble. Kita namai `MakeAESKeyHex` agar tegas bahwa inputnya hex-string. (Helper `reduceNibbles` dari Plan 1 dipakai ulang.)

- [ ] **Step 1: Tulis test yang gagal (round-trip DH Go-ke-Go)**

Tambahkan ke `internal/protocol/crypto_test.go`:
```go
import "strings" // tambahkan ke import block bila belum ada

// hexUpper menghasilkan pubkey peer sebagai string hex uppercase (seperti wire).
func pubHex(c *Crypto) string {
	return strings.ToUpper(hexEncode(c.GetKeyExchangeBytes()))
}

func TestDHSharedKeyMatchesBothSides(t *testing.T) {
	// Dua pihak DH: server & client. Masing-masing priv acak.
	server := NewCrypto()
	server.MakePrivateKey()
	client := NewCrypto()
	client.MakePrivateKey()

	// Saling tukar pubkey (hex) lalu turunkan AES key.
	server.MakeAESKeyHex(pubHex(client))
	client.MakeAESKeyHex(pubHex(server))

	if !bytes.Equal(server.aesKey, client.aesKey) {
		t.Errorf("AES key kedua sisi beda:\n  server=%x\n  client=%x", server.aesKey, client.aesKey)
	}
	if len(server.aesKey) != 16 {
		t.Errorf("aesKey len = %d, mau 16", len(server.aesKey))
	}
	// nibble tereduksi: tiap nibble <= 9
	for i, b := range server.aesKey {
		if b>>4 > 9 || b&0x0F > 9 {
			t.Errorf("byte %d (%#x) punya nibble > 9", i, b)
		}
	}
}
```

Test memakai helper `hexEncode` (lihat Step 3) dan `strings.ToUpper`.

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/protocol/ -run TestDHSharedKey -v`
Expected: FAIL — `MakeAESKeyHex` / `hexEncode` undefined.

- [ ] **Step 3: Tulis implementasi minimal**

Tambahkan ke `internal/protocol/crypto.go` (tambah `encoding/hex` ke import block):
```go
// hexEncode = byte -> string hex (huruf kecil), padanan Conversions.bytes2HexString
// tetapi lowercase; pemanggil yang butuh uppercase memakai strings.ToUpper.
func hexEncode(b []byte) string {
	return hex.EncodeToString(b)
}

// MakeAESKeyHex menurunkan kunci AES dari pubkey peer dalam bentuk STRING HEX
// (256 char), persis seperti C# MakeAESKey(string): A = parse-hex(s); R = A^priv mod M;
// ambil 16 byte pertama; reduksi nibble (>9 -> -9).
func (c *Crypto) MakeAESKeyHex(peerPubHex string) {
	a, ok := new(big.Int).SetString(peerPubHex, 16)
	if !ok {
		c.aesKey = nil
		return
	}
	r := new(big.Int).Exp(a, c.privateKey, c.modulus).Bytes()
	key := make([]byte, 16)
	copy(key, r)
	c.aesKey = reduceNibbles(key)
}
```

> **Catatan basis parse:** C# `new BigInteger(string)` (Mono.Math) menerima string. Implementasi kita mem-parse sebagai **hex (basis 16)** karena wire mengirim 256 char hex. Apakah ini byte-exact dengan C# diverifikasi di Task 6 (capture handshake). Round-trip Go-ke-Go di Step 1 hanya membuktikan konsistensi internal (kedua sisi memakai parse yang sama).

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/protocol/ -run TestDHSharedKey -v`
Expected: PASS.

- [ ] **Step 5: Jalankan seluruh test protocol**

Run: `go test ./internal/protocol/ -v`
Expected: PASS semua (termasuk test Plan 1).

- [ ] **Step 6: Commit**

```bash
git add internal/protocol/crypto.go internal/protocol/crypto_test.go
git commit -m "feat(protocol): MakeAESKeyHex (turunan AES dari pubkey hex peer)"
```

---

## Task 3: DecodeFrame — region terdekripsi -> daftar sub-message

**Files:**
- Create: `lumeris-go/internal/protocol/frame.go`
- Test: `lumeris-go/internal/protocol/frame_test.go`

`DecodeFrame` menerima frame wire LENGKAP yang BELUM didekripsi + `Crypto` siap, lalu: dekripsi region dari offset 8, baca INNER M di byte 4-7, lalu pisah jadi sub-message `[]SubMessage{ID, Data}`. Tiap sub-message: prefix 2-byte BE len, lalu 2-byte ID, lalu data.

- [ ] **Step 1: Tulis test yang gagal**

`internal/protocol/frame_test.go`:
```go
package protocol

import (
	"bytes"
	"testing"
)

func TestDecodeFrameSingleSubMessage(t *testing.T) {
	c := NewCrypto()
	c.aesKey = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	// Sub-message: ID=0x0001, data="AB" (2 byte) => isi = 00 01 41 42 (4 byte).
	// Prefix len 2-byte BE = panjang (ID+data) = 4 => 00 04.
	// Region (pra-pad) = 00 04 00 01 41 42 (6 byte). INNER M = 6.
	// Region di-pad ke kelipatan 16 (selalu +mod): 6 -> +10 = 16 byte.
	sub := []byte{0x00, 0x04, 0x00, 0x01, 0x41, 0x42}
	region := make([]byte, 16)
	copy(region, sub)

	// Bangun frame: [OUTER 4][INNER 4][region terenkripsi].
	frame := make([]byte, 8+len(region))
	// INNER M (byte 4-7) = 6 (panjang sub-message valid, pra-pad)
	frame[4], frame[5], frame[6], frame[7] = 0x00, 0x00, 0x00, 0x06
	// region terenkripsi mulai byte 8
	enc := c.Encrypt(append(make([]byte, 8), region...), 8)
	copy(frame[8:], enc[8:])
	// OUTER N (byte 0-3) = len region = 16
	frame[0], frame[1], frame[2], frame[3] = 0x00, 0x00, 0x00, 0x10

	subs, err := DecodeFrame(c, frame)
	if err != nil {
		t.Fatalf("DecodeFrame error: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("jumlah sub-message = %d, mau 1", len(subs))
	}
	if subs[0].ID != 0x0001 {
		t.Errorf("ID = %#x, mau 0x0001", subs[0].ID)
	}
	if !bytes.Equal(subs[0].Data, []byte{0x41, 0x42}) {
		t.Errorf("Data = %v, mau [41 42]", subs[0].Data)
	}
}
```

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/protocol/ -run TestDecodeFrame -v`
Expected: FAIL — `undefined: DecodeFrame` / `SubMessage`.

- [ ] **Step 3: Tulis implementasi minimal**

`internal/protocol/frame.go`:
```go
package protocol

import (
	"encoding/binary"
	"errors"
)

// SubMessage adalah satu pesan aplikasi di dalam frame: ID opcode + data payload.
type SubMessage struct {
	ID   uint16
	Data []byte
}

// firstLevelLen = lebar prefix panjang sub-message (2 byte untuk login & map ECO).
const firstLevelLen = 2

// maxSubMessages membatasi jumlah sub-message per frame (guard anti-runaway).
const maxSubMessages = 1024

// DecodeFrame mendekripsi region (dari offset 8) lalu memisahkan sub-message.
// frame = [OUTER 4][INNER 4][region terenkripsi]. Mengembalikan daftar sub-message.
func DecodeFrame(c *Crypto, frame []byte) ([]SubMessage, error) {
	if len(frame) < 8 {
		return nil, errors.New("frame < 8 byte")
	}
	dec := c.Decrypt(frame, 8)
	inner := int(binary.BigEndian.Uint32(dec[4:8])) // INNER M
	if inner < 0 || 8+inner > len(dec) {
		return nil, errors.New("INNER length di luar batas frame")
	}
	var subs []SubMessage
	off := 0
	for off < inner {
		if len(subs) >= maxSubMessages {
			return nil, errors.New("melebihi batas sub-message")
		}
		if off+firstLevelLen > inner {
			return nil, errors.New("prefix sub-message terpotong")
		}
		size := int(binary.BigEndian.Uint16(dec[8+off:]))
		off += firstLevelLen
		if size < 2 || off+size > inner {
			return nil, errors.New("ukuran sub-message di luar batas")
		}
		id := binary.BigEndian.Uint16(dec[8+off:])
		data := make([]byte, size-2)
		copy(data, dec[8+off+2:8+off+size])
		subs = append(subs, SubMessage{ID: id, Data: data})
		off += size
	}
	return subs, nil
}
```

> Guardrails CLAUDE.md: INNER divalidasi terhadap panjang buffer nyata; loop dibatasi `maxSubMessages`; tiap `size` dicek terhadap `inner` sebelum slice. Tidak ada dekompresi.

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/protocol/ -run TestDecodeFrame -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/protocol/frame.go internal/protocol/frame_test.go
git commit -m "feat(protocol): DecodeFrame (region terdekripsi -> sub-message)"
```

---

## Task 4: EncodeFrame — sub-message -> frame wire siap kirim

**Files:**
- Modify: `lumeris-go/internal/protocol/frame.go`
- Test: `lumeris-go/internal/protocol/frame_test.go`

`EncodeFrame` kebalikan `DecodeFrame`: dari `(ID, data)` bangun frame wire lengkap (wrap sub-message + INNER + OUTER + padding ke kelipatan 16 + enkripsi dari offset 8). Untuk milestone ini fokus SATU sub-message per frame (cukup untuk login/handshake; multi-sub batch menyusul bila perlu).

- [ ] **Step 1: Tulis test yang gagal (round-trip Encode->Decode)**

Tambahkan ke `internal/protocol/frame_test.go`:
```go
func TestEncodeDecodeRoundTrip(t *testing.T) {
	c := NewCrypto()
	c.aesKey = []byte{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}

	frame := EncodeFrame(c, 0x001E, []byte{0x4D, 0x58, 0x4D, 0x49})

	// Region (byte 8+) harus kelipatan 16 (padding AES).
	region := len(frame) - 8
	if region%16 != 0 {
		t.Errorf("region = %d byte, bukan kelipatan 16", region)
	}
	// OUTER N (byte 0-3) = len region.
	if got := int(frame[0])<<24 | int(frame[1])<<16 | int(frame[2])<<8 | int(frame[3]); got != region {
		t.Errorf("OUTER = %d, mau %d", got, region)
	}

	subs, err := DecodeFrame(c, frame)
	if err != nil {
		t.Fatalf("DecodeFrame error: %v", err)
	}
	if len(subs) != 1 || subs[0].ID != 0x001E {
		t.Fatalf("round-trip ID gagal: %+v", subs)
	}
	if !bytes.Equal(subs[0].Data, []byte{0x4D, 0x58, 0x4D, 0x49}) {
		t.Errorf("round-trip data gagal: %v", subs[0].Data)
	}
}
```

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/protocol/ -run TestEncodeDecodeRoundTrip -v`
Expected: FAIL — `undefined: EncodeFrame`.

- [ ] **Step 3: Tulis implementasi minimal**

Tambahkan ke `internal/protocol/frame.go`:
```go
// EncodeFrame membangun frame wire lengkap dari satu sub-message (ID+data),
// lalu mengenkripsi region dari offset 8. Layout hasil:
// [OUTER 4 BE][INNER 4 BE][ region: (len2|ID2|data) + padding-nol-ke-16 ].
func EncodeFrame(c *Crypto, id uint16, data []byte) []byte {
	// sub-message: [len 2-byte BE = 2+len(data)][ID 2-byte][data]
	subLen := 2 + len(data)
	region := make([]byte, firstLevelLen+subLen)
	binary.BigEndian.PutUint16(region[0:], uint16(subLen))
	binary.BigEndian.PutUint16(region[firstLevelLen:], id)
	copy(region[firstLevelLen+2:], data)

	inner := len(region) // INNER M = panjang sub-message valid (pra-pad)

	// padding ke kelipatan 16 (selalu tambah; mod tak pernah 0) — replika NetIO.cs:684.
	mod := 16 - (len(region) % 16)
	region = append(region, make([]byte, mod)...)

	// frame: 8 byte header + region
	frame := make([]byte, 8+len(region))
	copy(frame[8:], region)
	binary.BigEndian.PutUint32(frame[4:], uint32(inner)) // INNER M
	binary.BigEndian.PutUint32(frame[0:], uint32(len(region))) // OUTER N = len region (pasca-pad)

	return c.Encrypt(frame, 8)
}
```

> **Catatan padding**: `mod = 16 - (len%16)`; bila `len` kelipatan 16, `mod=16` (selalu menambah satu blok penuh), persis perilaku C# `NetIO.cs:684`. OUTER = panjang region SETELAH padding; INNER = panjang sub-message valid SEBELUM padding (region berisi sub-message + nol). DecodeFrame berhenti di `inner`, jadi byte padding terabaikan.

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/protocol/ -run TestEncodeDecodeRoundTrip -v`
Expected: PASS.

- [ ] **Step 5: Jalankan seluruh test protocol + vet**

Run:
```bash
go test ./... -v
go vet ./...
```
Expected: semua PASS, vet bersih.

- [ ] **Step 6: Commit**

```bash
git add internal/protocol/frame.go internal/protocol/frame_test.go
git commit -m "feat(protocol): EncodeFrame (sub-message -> frame wire + padding + enkripsi)"
```

---

## Task 5: Builder blob handshake 529-byte (server)

**Files:**
- Modify: `lumeris-go/internal/protocol/crypto.go`
- Test: `lumeris-go/internal/protocol/crypto_test.go`

Server harus membangun blob 529-byte berisi modulus (hex lowercase) + pubkey server (hex uppercase). Ini fungsi murni di `Crypto` (butuh priv sudah dibuat). Verifikasi byte-exact terhadap layout `NetIO.cs:242-251`.

- [ ] **Step 1: Tulis test yang gagal**

Tambahkan ke `internal/protocol/crypto_test.go`:
```go
func TestBuildServerHandshake529(t *testing.T) {
	c := NewCrypto()
	c.MakePrivateKey()

	blob := c.BuildServerHandshake()
	if len(blob) != 529 {
		t.Fatalf("blob = %d byte, mau 529", len(blob))
	}
	// [4..7] = BE 1
	if blob[4] != 0 || blob[5] != 0 || blob[6] != 0 || blob[7] != 1 {
		t.Errorf("byte 4-7 = %v, mau 00 00 00 01", blob[4:8])
	}
	// [8] = 0x32
	if blob[8] != 0x32 {
		t.Errorf("byte 8 = %#x, mau 0x32", blob[8])
	}
	// [9..12] = BE 0x100
	if blob[9] != 0 || blob[10] != 0 || blob[11] != 1 || blob[12] != 0 {
		t.Errorf("byte 9-12 = %v, mau 00 00 01 00", blob[9:13])
	}
	// [13..268] = modulus hex LOWERCASE (256 char). Cek prefix modulus.
	modHexLower := []byte("f488fd584e49dbcd")
	if !bytes.Equal(blob[13:13+len(modHexLower)], modHexLower) {
		t.Errorf("modulus hex (lowercase) salah: %s", blob[13:13+16])
	}
	// [269..272] = BE 0x100
	if blob[269] != 0 || blob[270] != 0 || blob[271] != 1 || blob[272] != 0 {
		t.Errorf("byte 269-272 = %v, mau 00 00 01 00", blob[269:273])
	}
	// [273..528] = pubkey hex UPPERCASE (256 char) — harus uppercase, panjang 256.
	pub := blob[273:529]
	if len(pub) != 256 {
		t.Errorf("pubkey hex len = %d, mau 256", len(pub))
	}
	for _, ch := range pub {
		if ch >= 'a' && ch <= 'f' {
			t.Errorf("pubkey hex mengandung huruf kecil (harus uppercase): %s", pub)
			break
		}
	}
}
```

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/protocol/ -run TestBuildServerHandshake -v`
Expected: FAIL — `c.BuildServerHandshake undefined`.

- [ ] **Step 3: Tulis implementasi minimal**

Tambahkan ke `internal/protocol/crypto.go` (butuh `strings` di import block):
```go
// BuildServerHandshake membangun blob 529-byte handshake DH server (plaintext),
// replika NetIO.cs:242-251. Panggil SETELAH MakePrivateKey.
// Layout: [0..3]=0, [4..7]=BE 1, [8]=0x32, [9..12]=BE 0x100,
// [13..268]=modulus hex LOWERCASE (256), [269..272]=BE 0x100,
// [273..528]=pubkey server hex UPPERCASE (256).
func (c *Crypto) BuildServerHandshake() []byte {
	blob := make([]byte, 529)
	binary.BigEndian.PutUint32(blob[4:], 1)
	blob[8] = 0x32
	binary.BigEndian.PutUint32(blob[9:], 0x100)
	modHex := strings.ToLower(hexEncode(c.modulus.Bytes()))
	copy(blob[13:], []byte(padHexLeft(modHex, 256)))
	binary.BigEndian.PutUint32(blob[269:], 0x100)
	pubHex := strings.ToUpper(hexEncode(c.GetKeyExchangeBytes()))
	copy(blob[273:], []byte(padHexLeft(pubHex, 256)))
	return blob
}

// padHexLeft memastikan string hex berukuran tepat n char dengan menambah '0' di kiri
// (modulus & pubkey selalu 128 byte = 256 char; guard bila ada leading-zero hilang).
func padHexLeft(s string, n int) string {
	if len(s) >= n {
		return s[len(s)-n:]
	}
	return strings.Repeat("0", n-len(s)) + s
}
```

Tambahkan import `encoding/binary` ke `crypto.go` bila belum ada (frame.go sudah pakai, tapi crypto.go terpisah).

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/protocol/ -run TestBuildServerHandshake -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/protocol/crypto.go internal/protocol/crypto_test.go
git commit -m "feat(protocol): BuildServerHandshake blob 529-byte (modulus+pubkey)"
```

---

## Task 6: Verifikasi handshake byte-exact dari capture

**Files:**
- Create: `lumeris-go/internal/protocol/handshake_vectors_test.go`
- Reference: capture handshake (blob 529 server, blob 260 client, aesKey hasil) — direkam via gate di SagaLib seperti Plan 1 Task 8.

> **Tujuan:** Membuktikan `MakeAESKeyHex` byte-exact dengan C#. Round-trip Go-ke-Go (Task 2) hanya menguji konsistensi internal; ini menguji terhadap C# nyata.

- [ ] **Step 1: Rekam vektor handshake**

Mirip Plan 1 Task 8, tambahkan capture TER-GATE di `SagaLib/NetIO.cs` pada cabang `raw.Length == 260` (server menerima pubkey klien): catat ke `handshake_vector.log`: (a) pubkey klien 256-hex (`ASCII.GetString(GetBytes(256,4))`), (b) priv server (`Crypt` — tambah getter sementara atau dump `Crypt.AESKey` SETELAH MakeAESKey), (c) aesKey hasil (`Crypt.AESKey` hex setelah `MakeAESKey`).

Karena priv server acak & tak diekspos, vektor yang CUKUP untuk menguji `MakeAESKeyHex` adalah: **(priv server, pubkey klien hex, aesKey hasil)**. Tambahkan dump `privateKey` lewat getter sementara di Encryption.cs (mis. `public string PrivHex => privateKey.getBytes()` di-hex) HANYA selama capture, lalu revert.

Gate dengan env var `LUMERIS_HS_VECTOR=1`, one-shot, file terpisah — sama disiplin seperti Plan 1 Task 8. Build proxy, jalankan satu sesi login lewat proxy, ambil vektor, lalu REVERT semua perubahan SagaLib + rebuild bersih.

- [ ] **Step 2: Tulis test vektor (isi hex NYATA dari Step 1)**

`internal/protocol/handshake_vectors_test.go`:
```go
package protocol

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// Vektor handshake dari capture C# (SagaLib.Encryption), gate LUMERIS_HS_VECTOR.
// Membuktikan MakeAESKeyHex Go == MakeAESKey C# byte-for-byte.
func TestMakeAESKeyHexMatchesCapture(t *testing.T) {
	privHex := "__PRIV_SERVER_HEX__"      // privateKey server saat sesi capture
	peerPubHex := "__CLIENT_PUBKEY_256HEX__" // 256 char hex pubkey klien
	wantAES := "__AESKEY_16BYTE_HEX__"    // aesKey hasil C#

	c := NewCrypto()
	priv, ok := new(big.Int).SetString(privHex, 16)
	if !ok {
		t.Fatalf("priv hex invalid")
	}
	c.privateKey = priv
	c.MakeAESKeyHex(peerPubHex)

	got := hex.EncodeToString(c.aesKey)
	if got != wantAES {
		t.Errorf("aesKey = %s, mau %s", got, wantAES)
	}
}
```

- [ ] **Step 3: Jalankan test vektor**

Run: `go test ./internal/protocol/ -run TestMakeAESKeyHexMatchesCapture -v`
Expected: PASS. Jika FAIL: akar paling mungkin = basis parse `MakeAESKeyHex` (hex vs desimal) ATAU panjang `getBytes()` C# vs `big.Int.Bytes()` (leading zero). Sesuaikan `MakeAESKeyHex` (mis. left-pad ke 128 byte sebelum ambil 16) berdasarkan temuan, jangan menebak.

- [ ] **Step 4: Commit**

```bash
git add internal/protocol/handshake_vectors_test.go internal/protocol/crypto.go
git commit -m "test(protocol): verifikasi MakeAESKeyHex byte-exact dari capture handshake"
```

---

## Self-Review (dijalankan saat menulis plan)

- **Spec coverage:** Plan 2A menutup bagian framing wire + handshake DH dari spec. Listener/Session/dispatch + login flow = Plan 2B/Plan 4 (di luar). MakePrivateKey & MakeAESKey-hex (ditunda dari Plan 1) sekarang masuk.
- **Placeholder scan:** Satu-satunya placeholder DISENGAJA = `__..__` di Task 6 (vektor capture nyata, tak boleh ditebak). Semua kode lain konkret.
- **Type consistency:** `Crypto{modulus, base, privateKey, aesKey}` (Plan 1) dipakai konsisten. Method baru: `MakePrivateKey()`, `MakeAESKeyHex(string)`, `BuildServerHandshake()`, helper `hexEncode`, `padHexLeft`. `SubMessage{ID uint16, Data []byte}`, `DecodeFrame(c, frame)`, `EncodeFrame(c, id, data)`, `firstLevelLen=2`. Konsisten antar task.
- **Catatan diverifikasi capture:** basis parse MakeAESKeyHex (Task 6), case hex modulus/pubkey (Task 5).

---

## Lingkup Plan berikutnya (BUKAN Plan 2A)

- **Plan 2B — Session & Listener:** `internal/net` (TCP listener + accept loop, replika `LoginClientManager.NetworkLoop`), `internal/session` (Session = goroutine baca + channel tulis, pegang Crypto, jalankan handshake 8→529→260, lalu loop baca frame → DecodeFrame → dispatch). Test integrasi TCP lokal Go-ke-Go: klien Go connect → handshake → kirim 1 packet terenkripsi → server decode benar.
- **Plan 3 — DB & migrasi**, **Plan 4 — Login flow**, **Plan 5 — Map**, **Plan 6 — Docker** (lihat spec).
