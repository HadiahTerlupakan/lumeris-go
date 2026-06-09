package netio

import (
	"log"
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
		go func() {
			if err := s.Run(); err != nil {
				log.Printf("[netio %s] session ended: %v", l.addr, err)
			}
		}()
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
