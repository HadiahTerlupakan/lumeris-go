package session

import (
	"log"
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
	// Context menyimpan state aplikasi per-session (front/back word, akun auth, char list).
	// Handler login men-cast ini ke struct konkret sesuai fase (Validation vs Login).
	Context any
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
			} else {
				// Log packet yang tidak dikenali
				log.Printf("[Session] Unhandled packet: ID=0x%04X, len=%d, data=%02x", sub.ID, len(sub.Data), sub.Data)
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

// SendRaw mengirim raw bytes langsung tanpa encryption/framing.
// Digunakan untuk packet khusus seperti mystery packet di ValidationClient.cs:191-195.
func (s *Session) SendRaw(raw []byte) {
	select {
	case s.outbound <- raw:
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
