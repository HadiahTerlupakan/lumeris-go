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

	// Balasan server (PONG) harus terbaca di klien (time-boxed agar gagal cepat
	// bila reply tak pernah datang, bukan menggantung sampai timeout global).
	_ = cc.SetReadDeadline(time.Now().Add(2 * time.Second))
	subs, err := ReadFrame(cc, cCrypto)
	if err != nil {
		t.Fatalf("ReadFrame (klien) error: %v", err)
	}
	if len(subs) != 1 || subs[0].ID != 0x0002 || string(subs[0].Data) != "PONG" {
		t.Fatalf("balasan server salah: %+v", subs)
	}
}
