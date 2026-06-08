# Lumeris-Go Plan 2B: Session & Listener Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Membungkus lapisan protocol (Plan 1 + 2A) dengan jaringan: `Session` per-koneksi (handshake DH server, baca frame → dispatch, tulis lewat channel) dan `Listener` TCP (accept loop), terverifikasi via test integrasi TCP/pipe Go-ke-Go tanpa klien asli.

**Architecture:** Dua paket baru. `internal/session` = satu koneksi: pegang `*protocol.Crypto`, jalankan handshake server (8→529→260), lalu loop baca frame (`ReadFrame` → `DecodeFrame`) dan kirim (`Send` → `EncodeFrame` → channel → writer goroutine); dispatch opcode via `map[uint16]HandlerFunc`. `internal/netio` = `Listener` yang menerima koneksi dan menjalankan satu `Session` per koneksi. Handler login/map (Registry, DB, opcode nyata) = Plan 4/5, di luar plan ini.

**Tech Stack:** Go 1.26, stdlib `net`, `io`, `encoding/binary`, `sync`; bergantung pada `lumeris-go/internal/protocol` (modul = `lumeris-go`).

**Sumber kebenaran byte-exact (WAJIB dibaca saat ragu):**
- `C:\Users\RASYA\Documents\Lumeris-Project\SagaLib\NetIO.cs` — handshake server (`ReceiveKeyExchange` ~:240-294), baca size (`ReceiveSize` ~:351-443), baca data + pisah sub-message (`ReceiveData` ~:449-579).

## Fakta byte-exact yang HARUS direplikasi (hasil RE, jangan ditebak)

### Handshake server (mode Server, plaintext, `NetIO.cs:240-279`)
1. Klien connect → kirim **8 byte** (isi diabaikan; hanya `len==8` penting).
2. Server: `MakePrivateKey()` → kirim blob **529 byte** (`BuildServerHandshake`, sudah ada di Plan 2A) **raw**: tanpa length-wrap, tanpa enkripsi.
3. Klien balas **260 byte**: `[0..3]` = BE `0x100`, `[4..259]` = 256 char ASCII hex pubkey klien (uppercase).
4. Server: `keyBuf = reply[4:260]` (256 char ASCII hex) → `MakeAESKeyHex(string(keyBuf))` → AES siap → masuk loop frame.

### Baca frame (post-handshake, `NetIO.cs:351-559`)
- Baca **4 byte OUTER** (plaintext), `Array.Reverse` → BE uint32 `N`. C# set `size = N + 4`, lalu baca `N+4` byte berikutnya = `[INNER 4][region N]`. (4 byte OUTER dipakai habis sebagai size-prefix; di buffer C# slot `[0:4]` jadi nol.)
- Rekonstruksi buffer untuk `DecodeFrame`: `frame = [0,0,0,0] ++ [INNER 4] ++ [region N]` (panjang `8+N`). `DecodeFrame` (Plan 2A) **mengabaikan** `[0:4]` (OUTER) dan membaca INNER di `[4:8]` lalu region terenkripsi dari offset 8 — jadi OUTER nol tak masalah.
- Guard panjang: C# menolak `length >= 1024000` (`NetIO.cs:528`). Kita batasi `N <= 1024000` (jauh di bawah cap 64MB CLAUDE.md).

### Kirim frame (post-handshake)
- `EncodeFrame(crypto, id, data)` (Plan 2A) sudah menghasilkan wire lengkap `[OUTER 4][INNER 4][region terenkripsi]` dengan OUTER nyata = panjang region. Tulis byte itu apa adanya; OUTER jadi size-prefix yang dibaca klien.

---

## File Structure

```
lumeris-go/internal/session/
├── frame_io.go        (BARU) ReadFrame(r, crypto) -> []SubMessage (baca OUTER+INNER+region, DecodeFrame)
├── handshake.go       (BARU) serverHandshake(conn, crypto) + ClientHandshake(conn) (8->529->260)
├── session.go         (BARU) Session{conn, crypto, dispatch, outbound, done}: New/Run/Send/Close + read/write loop
├── frame_io_test.go   (BARU) round-trip ReadFrame in-memory
├── handshake_test.go  (BARU) server<->client handshake net.Pipe: kunci AES cocok (bukti fungsional)
└── session_test.go    (BARU) integrasi net.Pipe: handshake + dispatch inbound + Send outbound

lumeris-go/internal/netio/
├── listener.go        (BARU) Listener{addr, dispatch}: New/Start/Addr/Close + acceptLoop -> Session per koneksi
└── listener_test.go   (BARU) integrasi TCP 127.0.0.1:0: dial -> handshake -> kirim frame -> handler terpanggil
```

Pemisahan: `session` = satu koneksi (protokol+dispatch), `netio` = banyak koneksi (accept). Tanggung jawab beda, diuji terpisah. Paket diberi nama `netio` (bukan `net`) agar tak bentrok dengan stdlib `net`; ini lapisan yang di spec disebut `internal/net`.

**Catatan test:** `aesKey` di paket `protocol` tak diekspor, jadi test TIDAK menyetelnya langsung. Test memakai helper `readyDHPair()` yang menjalankan DH Go-ke-Go nyata (`MakePrivateKey` + `MakeAESKeyHex` dua sisi) untuk mendapatkan `*protocol.Crypto` yang sudah siap. Simetri kunci sudah diverifikasi di Plan 2A (`TestDHSharedKeyMatchesBothSides`). Test paket `session` ditulis **white-box** (`package session`) agar bisa memanggil `serverHandshake` yang tak diekspor; test `netio` ditulis external (`package netio_test`).

---

## Task 1: ReadFrame — baca satu frame wire dari io.Reader

**Files:**
- Create: `lumeris-go/internal/session/frame_io.go`
- Test: `lumeris-go/internal/session/frame_io_test.go`

`ReadFrame` membaca 4 byte OUTER (BE) = panjang region `N`, lalu `N+4` byte (`[INNER 4][region]`), merakit buffer `8+N` byte, dan memanggil `protocol.DecodeFrame`. Dipakai oleh read-loop Session dan oleh sisi-klien di test.

- [ ] **Step 1: Tulis test yang gagal**

`internal/session/frame_io_test.go`:
```go
package session

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"lumeris-go/internal/protocol"
)

// readyDHPair menjalankan DH Go-ke-Go nyata dan mengembalikan dua Crypto yang
// AES key-nya sudah siap & identik (simetri DH diverifikasi di Plan 2A).
func readyDHPair() (server, client *protocol.Crypto) {
	server = protocol.NewCrypto()
	server.MakePrivateKey()
	client = protocol.NewCrypto()
	client.MakePrivateKey()
	server.MakeAESKeyHex(strings.ToUpper(hex.EncodeToString(client.GetKeyExchangeBytes())))
	client.MakeAESKeyHex(strings.ToUpper(hex.EncodeToString(server.GetKeyExchangeBytes())))
	return server, client
}

func TestReadFrameRoundTrip(t *testing.T) {
	c, _ := readyDHPair()
	frame := protocol.EncodeFrame(c, 0x001E, []byte("MXMI"))

	subs, err := ReadFrame(bytes.NewReader(frame), c)
	if err != nil {
		t.Fatalf("ReadFrame error: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("jumlah sub = %d, mau 1", len(subs))
	}
	if subs[0].ID != 0x001E {
		t.Errorf("ID = %#x, mau 0x001E", subs[0].ID)
	}
	if !bytes.Equal(subs[0].Data, []byte("MXMI")) {
		t.Errorf("Data = %q, mau MXMI", subs[0].Data)
	}
}

func TestReadFrameRejectsOversizeOuter(t *testing.T) {
	c, _ := readyDHPair()
	// OUTER = 2_000_000 (> batas 1024000) → harus error sebelum alokasi region.
	bad := []byte{0x00, 0x1E, 0x84, 0x80} // BE 2_000_000
	_, err := ReadFrame(bytes.NewReader(bad), c)
	if err == nil {
		t.Fatal("ReadFrame menerima OUTER di luar batas; mau error")
	}
}
```

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/session/ -run TestReadFrame -v`
Expected: FAIL — `undefined: ReadFrame`.

- [ ] **Step 3: Tulis implementasi minimal**

`internal/session/frame_io.go`:
```go
package session

import (
	"encoding/binary"
	"fmt"
	"io"

	"lumeris-go/internal/protocol"
)

// maxRegion membatasi panjang region (OUTER) sejalan batas length C# (NetIO.cs:528),
// jauh di bawah cap 64MB CLAUDE.md — guard anti-alokasi-raksasa dari size attacker.
const maxRegion = 1024000

// ReadFrame membaca satu frame wire dari r: 4 byte OUTER (BE = panjang region),
// lalu (INNER 4 + region N) byte. Merakit buffer [0000][INNER][region] dan
// memanggil protocol.DecodeFrame (yang mengabaikan OUTER, memakai INNER di [4:8]).
func ReadFrame(r io.Reader, c *protocol.Crypto) ([]protocol.SubMessage, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(head[:]) // OUTER = panjang region
	if n == 0 || n > maxRegion {
		return nil, fmt.Errorf("OUTER length %d di luar batas (1..%d)", n, maxRegion)
	}
	rest := make([]byte, int(n)+4) // [INNER 4][region n]
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	frame := make([]byte, 8+int(n))
	copy(frame[4:], rest) // frame[0:4]=0 (OUTER diabaikan DecodeFrame)
	return protocol.DecodeFrame(c, frame)
}
```

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/session/ -run TestReadFrame -v`
Expected: PASS (kedua test).

- [ ] **Step 5: Commit**

```bash
git add internal/session/frame_io.go internal/session/frame_io_test.go
git commit -m "feat(session): ReadFrame (baca frame wire OUTER+INNER+region -> sub-message)"
```

---

## Task 2: Handshake — serverHandshake + ClientHandshake

**Files:**
- Create: `lumeris-go/internal/session/handshake.go`
- Test: `lumeris-go/internal/session/handshake_test.go`

`serverHandshake` mereplikasi `NetIO.cs:240-279` (mode Server): baca 8 → kirim 529 → baca 260 → `MakeAESKeyHex`. `ClientHandshake` adalah pasangannya (mode Client, `NetIO.cs:281-294`): kirim 8 → baca 529 → kirim 260 (pubkey sendiri) → `MakeAESKeyHex` dari pubkey server. `ClientHandshake` diekspor karena dipakai test integrasi (Task 3/4) dan koneksi keluar nanti.

- [ ] **Step 1: Tulis test yang gagal**

`internal/session/handshake_test.go`:
```go
package session

import (
	"net"
	"testing"

	"lumeris-go/internal/protocol"
)

func TestServerClientHandshakeKeyMatch(t *testing.T) {
	sc, cc := net.Pipe()
	defer sc.Close()
	defer cc.Close()

	done := make(chan error, 1)
	sCrypto := protocol.NewCrypto()
	go func() { done <- serverHandshake(sc, sCrypto) }()

	cCrypto, err := ClientHandshake(cc)
	if err != nil {
		t.Fatalf("ClientHandshake error: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("serverHandshake error: %v", err)
	}
	if !sCrypto.IsReady() || !cCrypto.IsReady() {
		t.Fatal("crypto belum siap setelah handshake")
	}

	// Bukti kunci cocok byte-exact: frame yang dienkripsi klien terbaca server.
	// net.Pipe sinkron → tulis di goroutine agar tak deadlock.
	frame := protocol.EncodeFrame(cCrypto, 0x0042, []byte("KEY"))
	go func() { _, _ = cc.Write(frame) }()
	subs, err := ReadFrame(sc, sCrypto)
	if err != nil {
		t.Fatalf("ReadFrame error: %v", err)
	}
	if len(subs) != 1 || subs[0].ID != 0x0042 || string(subs[0].Data) != "KEY" {
		t.Fatalf("frame salah: %+v", subs)
	}
}
```

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/session/ -run TestServerClientHandshake -v`
Expected: FAIL — `undefined: serverHandshake` / `ClientHandshake`.

- [ ] **Step 3: Tulis implementasi minimal**

`internal/session/handshake.go`:
```go
package session

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"

	"lumeris-go/internal/protocol"
)

const (
	helloLen      = 8   // byte pembuka dari klien (isi diabaikan)
	serverBlobLen = 529 // blob handshake server (modulus + pubkey)
	replyLen      = 260 // balasan klien: [0:4]=BE 0x100, [4:260]=256 hex pubkey
)

// serverHandshake menjalankan sisi-server handshake DH (NetIO.cs:240-279):
// baca 8 byte → MakePrivateKey + kirim blob 529 (raw) → baca 260 → MakeAESKeyHex.
func serverHandshake(conn net.Conn, c *protocol.Crypto) error {
	hello := make([]byte, helloLen)
	if _, err := io.ReadFull(conn, hello); err != nil {
		return err
	}
	c.MakePrivateKey()
	if _, err := conn.Write(c.BuildServerHandshake()); err != nil {
		return err
	}
	reply := make([]byte, replyLen)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	c.MakeAESKeyHex(string(reply[4:replyLen])) // reply[4:260] = 256 char hex pubkey klien
	if !c.IsReady() {
		return errors.New("serverHandshake: AES key gagal dibuat")
	}
	return nil
}

// ClientHandshake menjalankan sisi-klien handshake DH (NetIO.cs:281-294):
// kirim 8 byte → baca blob 529 → kirim 260 (pubkey sendiri, hex uppercase) →
// turunkan AES key dari pubkey server (hex di [273:529] blob).
func ClientHandshake(conn net.Conn) (*protocol.Crypto, error) {
	if _, err := conn.Write(make([]byte, helloLen)); err != nil {
		return nil, err
	}
	blob := make([]byte, serverBlobLen)
	if _, err := io.ReadFull(conn, blob); err != nil {
		return nil, err
	}
	serverPubHex := string(blob[273:serverBlobLen]) // pubkey server (uppercase, 256 char)

	c := protocol.NewCrypto()
	c.MakePrivateKey()

	reply := make([]byte, replyLen)
	binary.BigEndian.PutUint32(reply[0:], 0x100)
	pubHex := padHexLeft256(strings.ToUpper(hex.EncodeToString(c.GetKeyExchangeBytes())))
	copy(reply[4:], []byte(pubHex))
	if _, err := conn.Write(reply); err != nil {
		return nil, err
	}

	c.MakeAESKeyHex(serverPubHex)
	if !c.IsReady() {
		return nil, errors.New("ClientHandshake: AES key gagal dibuat")
	}
	return c, nil
}

// padHexLeft256 memastikan string hex tepat 256 char (128 byte pubkey) dengan
// menambah '0' di kiri bila leading-zero hilang dari big.Int.Bytes().
func padHexLeft256(s string) string {
	if len(s) >= 256 {
		return s[len(s)-256:]
	}
	return strings.Repeat("0", 256-len(s)) + s
}
```

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/session/ -run TestServerClientHandshake -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/session/handshake.go internal/session/handshake_test.go
git commit -m "feat(session): serverHandshake + ClientHandshake (DH 8->529->260)"
```

---

## Task 3: Session — Run (handshake + read/write loop) + Send/Close + dispatch

**Files:**
- Create: `lumeris-go/internal/session/session.go`
- Test: `lumeris-go/internal/session/session_test.go`

`Session` membungkus satu koneksi: `Run()` jalankan `serverHandshake` lalu spawn writer goroutine + masuk read-loop (`ReadFrame` → dispatch per opcode). `Send(id, data)` meng-`EncodeFrame` dan antri ke channel; writer menulis ke `conn`. `Close()` aman dipanggil berulang.

- [ ] **Step 1: Tulis test yang gagal**

`internal/session/session_test.go`:
```go
package session

import (
	"net"
	"testing"
	"time"

	"lumeris-go/internal/protocol"
)

func TestSessionRunDispatchAndSend(t *testing.T) {
	sc, cc := net.Pipe()
	defer sc.Close()
	defer cc.Close()

	got := make(chan []byte, 1)
	dispatch := map[uint16]HandlerFunc{
		0x0001: func(s *Session, data []byte) error {
			got <- data
			s.Send(0x0002, []byte("PONG"))
			return nil
		},
	}
	s := New(sc, dispatch)
	go func() { _ = s.Run() }()

	// Sisi klien: handshake lalu kirim frame ID=0x0001 data=PING.
	cCrypto, err := ClientHandshake(cc)
	if err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	go func() { _, _ = cc.Write(protocol.EncodeFrame(cCrypto, 0x0001, []byte("PING"))) }()

	select {
	case data := <-got:
		if string(data) != "PING" {
			t.Errorf("handler data = %q, mau PING", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler tidak terpanggil dalam 2 detik")
	}

	// Balasan server (PONG) harus terbaca di klien.
	subs, err := ReadFrame(cc, cCrypto)
	if err != nil {
		t.Fatalf("ReadFrame (klien) error: %v", err)
	}
	if len(subs) != 1 || subs[0].ID != 0x0002 || string(subs[0].Data) != "PONG" {
		t.Fatalf("balasan server salah: %+v", subs)
	}
}
```

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/session/ -run TestSessionRun -v`
Expected: FAIL — `undefined: HandlerFunc` / `New` / `Session.Send`.

- [ ] **Step 3: Tulis implementasi minimal**

`internal/session/session.go`:
```go
package session

import (
	"net"
	"sync"

	"lumeris-go/internal/protocol"
)

// HandlerFunc menangani satu sub-message inbound (ID sudah dipetakan ke handler).
type HandlerFunc func(s *Session, data []byte) error

// Session = satu koneksi klien: kripto, dispatch opcode, dan antrian tulis.
type Session struct {
	conn      net.Conn
	crypto    *protocol.Crypto
	dispatch  map[uint16]HandlerFunc
	outbound  chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

// New membuat Session siap-jalan (kripto baru, belum handshake).
func New(conn net.Conn, dispatch map[uint16]HandlerFunc) *Session {
	return &Session{
		conn:     conn,
		crypto:   protocol.NewCrypto(),
		dispatch: dispatch,
		outbound: make(chan []byte, 64),
		done:     make(chan struct{}),
	}
}

// Run menjalankan handshake server lalu writer goroutine + read-loop (blocking).
// Mengembalikan error penyebab koneksi berakhir (handshake gagal / EOF / dll).
func (s *Session) Run() error {
	if err := serverHandshake(s.conn, s.crypto); err != nil {
		s.Close()
		return err
	}
	go s.writeLoop()
	return s.readLoop()
}

func (s *Session) readLoop() error {
	for {
		subs, err := ReadFrame(s.conn, s.crypto)
		if err != nil {
			s.Close()
			return err
		}
		for _, sub := range subs {
			if h := s.dispatch[sub.ID]; h != nil {
				_ = h(s, sub.Data) // error handler tidak memutus koneksi (milestone)
			}
		}
	}
}

func (s *Session) writeLoop() {
	for {
		select {
		case <-s.done:
			return
		case b := <-s.outbound:
			if _, err := s.conn.Write(b); err != nil {
				s.Close()
				return
			}
		}
	}
}

// Send meng-encode (ID, data) jadi frame wire dan mengantri untuk ditulis.
// Aman dipanggil dari banyak goroutine; tak memblok bila session sudah ditutup.
func (s *Session) Send(id uint16, data []byte) {
	frame := protocol.EncodeFrame(s.crypto, id, data)
	select {
	case s.outbound <- frame:
	case <-s.done:
	}
}

// Close menutup koneksi & menghentikan loop; idempoten.
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.conn.Close()
	})
}
```

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/session/ -run TestSessionRun -v`
Expected: PASS.

- [ ] **Step 5: Jalankan seluruh test session + vet**

Run:
```bash
go test ./internal/session/ -v
go vet ./internal/session/
```
Expected: semua PASS, vet bersih.

- [ ] **Step 6: Commit**

```bash
git add internal/session/session.go internal/session/session_test.go
git commit -m "feat(session): Session Run/Send/Close + dispatch (handshake + read/write loop)"
```

---

## Task 4: Listener — accept loop TCP (internal/netio)

**Files:**
- Create: `lumeris-go/internal/netio/listener.go`
- Test: `lumeris-go/internal/netio/listener_test.go`

`Listener` membuka socket TCP, menerima koneksi, dan menjalankan satu `Session` per koneksi dengan dispatch yang sama. `Start()` non-blocking (accept loop di goroutine); `Addr()` mengembalikan alamat nyata (berguna saat bind `:0` di test); `Close()` menghentikan accept loop.

- [ ] **Step 1: Tulis test yang gagal**

`internal/netio/listener_test.go`:
```go
package netio_test

import (
	"net"
	"testing"
	"time"

	"lumeris-go/internal/netio"
	"lumeris-go/internal/protocol"
	"lumeris-go/internal/session"
)

func TestListenerAcceptsHandshakeAndDispatch(t *testing.T) {
	got := make(chan []byte, 1)
	dispatch := map[uint16]session.HandlerFunc{
		0x0001: func(s *session.Session, data []byte) error {
			got <- data
			return nil
		},
	}

	l := netio.New("127.0.0.1:0", dispatch)
	if err := l.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer l.Close()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Dial error: %v", err)
	}
	defer conn.Close()

	cCrypto, err := session.ClientHandshake(conn)
	if err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	if _, err := conn.Write(protocol.EncodeFrame(cCrypto, 0x0001, []byte("HELLO"))); err != nil {
		t.Fatalf("Write frame: %v", err)
	}

	select {
	case data := <-got:
		if string(data) != "HELLO" {
			t.Errorf("data = %q, mau HELLO", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler tidak terpanggil dalam 2 detik")
	}
}
```

- [ ] **Step 2: Jalankan test, pastikan gagal**

Run: `go test ./internal/netio/ -run TestListenerAccepts -v`
Expected: FAIL — `undefined: netio.New`.

- [ ] **Step 3: Tulis implementasi minimal**

`internal/netio/listener.go`:
```go
package netio

import (
	"net"

	"lumeris-go/internal/session"
)

// Listener menerima koneksi TCP dan menjalankan satu Session per koneksi.
type Listener struct {
	addr     string
	dispatch map[uint16]session.HandlerFunc
	ln       net.Listener
}

// New membuat Listener untuk addr (mis. "127.0.0.1:12023") dengan tabel dispatch.
func New(addr string, dispatch map[uint16]session.HandlerFunc) *Listener {
	return &Listener{addr: addr, dispatch: dispatch}
}

// Start membuka socket dan memulai accept loop di goroutine (non-blocking).
func (l *Listener) Start() error {
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return err
	}
	l.ln = ln
	go l.acceptLoop()
	return nil
}

func (l *Listener) acceptLoop() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return // listener ditutup → keluar
		}
		s := session.New(conn, l.dispatch)
		go func() { _ = s.Run() }()
	}
}

// Addr mengembalikan alamat nyata listener (berguna saat bind ":0").
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Close menghentikan accept loop dengan menutup socket.
func (l *Listener) Close() error {
	if l.ln != nil {
		return l.ln.Close()
	}
	return nil
}
```

- [ ] **Step 4: Jalankan test, pastikan lulus**

Run: `go test ./internal/netio/ -run TestListenerAccepts -v`
Expected: PASS.

- [ ] **Step 5: Jalankan seluruh test repo + vet**

Run:
```bash
go test ./... -v
go vet ./...
```
Expected: semua PASS (config, protocol, session, netio), vet bersih.

- [ ] **Step 6: Commit**

```bash
git add internal/netio/listener.go internal/netio/listener_test.go
git commit -m "feat(netio): Listener accept loop TCP (Session per koneksi)"
```

---

## Self-Review (dijalankan saat menulis plan)

- **Spec coverage:** Plan 2B menutup "Plan 2B — Session & Listener" dari lingkup yang disebut di akhir Plan 2A: `internal/net` (listener accept loop) + `internal/session` (Session = goroutine baca + channel tulis, pegang Crypto, jalankan handshake 8→529→260, lalu loop baca frame → DecodeFrame → dispatch) + test integrasi TCP lokal Go-ke-Go. Registry/token handoff, handler login/map, DB = Plan 3/4/5 (di luar, sesuai spec Bagian 4-5). Wiring `cmd/lumeris-go/main.go` menyusul saat handler nyata ada.
- **Placeholder scan:** Tidak ada `TBD`/`TODO`/"implement later". Semua step berisi kode konkret. Tak ada vektor capture yang dibutuhkan (handshake byte-exact sudah diverifikasi di Plan 2A Task 6; Plan 2B hanya merangkai jaringan + membuktikan kunci cocok secara fungsional via round-trip).
- **Type consistency:** `ReadFrame(io.Reader, *protocol.Crypto) ([]protocol.SubMessage, error)` dipakai konsisten di Task 1/2/3 (server) dan test klien. `serverHandshake(net.Conn, *protocol.Crypto) error` + `ClientHandshake(net.Conn) (*protocol.Crypto, error)` (Task 2) dipakai Task 3/4. `HandlerFunc func(*Session, []byte) error`, `New(net.Conn, map[uint16]HandlerFunc) *Session`, `Session.Send(uint16, []byte)`, `Session.Run() error`, `Session.Close()` (Task 3) dipakai konsisten di `netio.New(string, map[uint16]session.HandlerFunc)` (Task 4). Konstanta `helloLen=8`, `serverBlobLen=529`, `replyLen=260`, `maxRegion=1024000` selaras dengan layout Plan 2A (`BuildServerHandshake` = 529 byte; pubkey/modulus 256 char hex). Memakai API protocol yang sudah ada: `NewCrypto`, `MakePrivateKey`, `MakeAESKeyHex`, `GetKeyExchangeBytes`, `BuildServerHandshake`, `IsReady`, `EncodeFrame`, `DecodeFrame`, `SubMessage{ID, Data}` — semua cocok dengan `crypto.go`/`frame.go` Plan 2A.
- **Guardrails CLAUDE.md:** `ReadFrame` memvalidasi OUTER terhadap `maxRegion` sebelum alokasi (size field tak dipercaya); `DecodeFrame` (Plan 2A) sudah membatasi sub-message & bounds-check INNER. Tidak ada dekompresi. `io.ReadFull` memastikan baca penuh; EOF/short-read → error → `Close`.

---

## Lingkup Plan berikutnya (BUKAN Plan 2B)

- **Plan 3 — DB & migrasi:** `internal/db` (interface `Store` + `PostgresStore` pgx), `internal/model` (Account/Character/Actor), `migrations/001_init.sql`, runner migrasi saat boot.
- **Plan 4 — Login flow:** listener Validation(:12022) + Login(:12023), handler opcode (version/login/char-create/select/request-map), `session.Registry` (token sekali-pakai), wiring `cmd/lumeris-go/main.go`.
- **Plan 5 — Map:** listener Map(:12024), handshake token, spawn + movement (`0x11F9`) + chat, tick loop per peta.
- **Plan 6 — Docker:** Dockerfile multi-stage + docker-compose (app + postgres).
