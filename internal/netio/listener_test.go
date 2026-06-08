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
