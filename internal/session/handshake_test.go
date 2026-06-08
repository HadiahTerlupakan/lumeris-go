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
