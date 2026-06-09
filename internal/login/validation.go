package login

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"

	"lumeris-go/internal/auth"
	"lumeris-go/internal/db"
	"lumeris-go/internal/model"
	"lumeris-go/internal/session"
)

// ValidationContext menyimpan state per-session untuk Validation server.
type ValidationContext struct {
	FrontWord uint32
	BackWord  uint32
	Account   *model.Account // Diisi setelah login berhasil
}

// ValidationHandler adalah dispatcher untuk Validation server (:12022).
type ValidationHandler struct {
	store      db.Store
	devMode    bool
	publicIP   string
	serverName string
	loginPort  int
}

// NewValidationHandler membuat handler baru.
func NewValidationHandler(store db.Store, devMode bool, publicIP, serverName string, loginPort int) *ValidationHandler {
	return &ValidationHandler{store: store, devMode: devMode, publicIP: publicIP, serverName: serverName, loginPort: loginPort}
}

// Dispatch mengembalikan dispatch table untuk Validation server.
func (h *ValidationHandler) Dispatch() map[uint16]session.HandlerFunc {
	return map[uint16]session.HandlerFunc{
		CSMG_SEND_VERSION:  h.OnSendVersion,
		CSMG_LOGIN:         h.OnLogin,
		CSMG_SERVERLET_ASK: h.OnServerletAsk,
		CSMG_PING:          h.OnPing,
		0x002F:             h.OnUnknown002F, // Unknown packet after login
	}
}

// OnSendVersion menangani CSMG_SEND_VERSION: kirim VERSION_ACK -> LOGIN_ALLOWED -> REQUEST_NYA.
func (h *ValidationHandler) OnSendVersion(s *session.Session, data []byte) error {
	parsed, err := ParseSendVersion(data)
	if err != nil {
		log.Printf("[Validation] ParseSendVersion error: %v", err)
		return err
	}

	log.Printf("[Validation] Client version bytes: %02x", parsed.VersionBytes)

	// CATATAN: TIDAK ada mystery packet 0xFFFF di sini.
	// Capture klien asli (proxy_packets.log) menunjukkan urutan:
	//   C->S 0x0001 -> S->C 0x0002 VERSION_ACK -> S->C 0x001E LOGIN_ALLOWED
	// Tidak ada paket 0xFFFF di mana pun. Paket itu quirk C# SagaECO yang
	// membuat klien eco.exe (NekogameECO) tidak melanjutkan ke 0x002F setelah
	// login. Sempat dihapus (commit 93de...) lalu tak sengaja muncul lagi.

	// 1. Kirim VERSION_ACK
	ackData := BuildVersionACK(0, parsed.VersionBytes[:])
	log.Printf("[Validation] Sending VERSION_ACK (len=%d): %02x", len(ackData), ackData)
	s.Send(SSMG_VERSION_ACK, ackData)

	// 2. Generate front & back word untuk challenge
	vctx := &ValidationContext{}
	binary.Read(rand.Reader, binary.BigEndian, &vctx.FrontWord)
	binary.Read(rand.Reader, binary.BigEndian, &vctx.BackWord)
	s.Context = vctx

	allowedPacket := BuildLoginAllowed(vctx.FrontWord, vctx.BackWord)
	log.Printf("[Validation] LOGIN_ALLOWED packet body (%d bytes): %02x", len(allowedPacket), allowedPacket)
	s.Send(SSMG_LOGIN_ALLOWED, allowedPacket)
	// NOTE: C# TIDAK mengirim REQUEST_NYA setelah LOGIN_ALLOWED!

	log.Printf("[Validation] Version OK, challenge sent (front=%08x, back=%08x)", vctx.FrontWord, vctx.BackWord)
	return nil
}

// OnLogin menangani CSMG_LOGIN di fase Validation: verifikasi SHA1 challenge.
func (h *ValidationHandler) OnLogin(s *session.Session, data []byte) error {
	log.Printf("[Validation] OnLogin received %d bytes: %02x", len(data), data)

	parsed, err := ParseLogin(data)
	if err != nil {
		log.Printf("[Validation] ParseLogin error: %v", err)
		return err
	}

	vctx, ok := s.Context.(*ValidationContext)
	if !ok || vctx == nil {
		log.Printf("[Validation] Context invalid untuk login")
		s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_UNKNOWN_ACC, 0))
		return nil
	}

	// IMPORTANT: Kirim LOGIN_ACK OK dulu (line 53-55 ValidationClient.cs)
	// Ini TCP handshake flag, bukan final result
	s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_OK, 0))

	// Fetch account
	acc, err := h.store.GetAccountByName(context.Background(), parsed.Username)
	if err == db.ErrNotFound {
		log.Printf("[Validation] Login gagal: akun tidak ditemukan (%s)", parsed.Username)
		s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_UNKNOWN_ACC, 0))
		return nil
	}
	if err != nil {
		log.Printf("[Validation] GetAccountByName error: %v", err)
		s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_UNKNOWN_ACC, 0))
		return nil
	}

	// Verifikasi SHA1 challenge (bypass in dev mode)
	if h.devMode {
		log.Printf("[Validation] DEV MODE: Password check BYPASSED for %s", parsed.Username)
	} else {
		log.Printf("[Validation] VerifyChallenge: storedMD5=%s, front=%d, back=%d, response=%02x",
			acc.PasswordHash, vctx.FrontWord, vctx.BackWord, parsed.Password)
		if !auth.VerifyChallenge(acc.PasswordHash, vctx.FrontWord, vctx.BackWord, parsed.Password) {
			log.Printf("[Validation] Login gagal: password salah (%s)", parsed.Username)
			s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_BADPASS, 0))
			return nil
		}
	}

	// Check banned
	if acc.Banned {
		log.Printf("[Validation] Login gagal: banned (%s)", parsed.Username)
		s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_BFALOCK, 0))
		return nil
	}

	// Login berhasil - tidak perlu kirim LOGIN_ACK lagi karena sudah dikirim di awal
	vctx.Account = acc
	log.Printf("[Validation] Login berhasil: %s (ID=%d)", acc.Username, acc.ID)
	return nil
}

// OnServerletAsk menangani CSMG_SERVERLET_ASK: kirim daftar server (LOGIN server).
func (h *ValidationHandler) OnServerletAsk(s *session.Session, data []byte) error {
	log.Printf("[Validation] OnServerletAsk called - sending server list")

	// Format IP sesuai capture klien asli (proxy_packets.log baris 11):
	//   [nameLen][name\0][ipLen][ip\0]  dengan ip = "host:port,host:port,host:port,host:port"
	// 0x50 di capture adalah BYTE panjang string IP (80), BUKAN prefix "P".
	// Client butuh PORT Login server di sini agar bisa reconnect (TANPA port = stuck).
	addr := fmt.Sprintf("%s:%d", h.publicIP, h.loginPort)
	ipFormat := addr + "," + addr + "," + addr + "," + addr

	s.Send(SSMG_SERVER_LST_START, BuildServerListStart())
	s.Send(SSMG_SERVER_LST_SEND, BuildServerListSend(h.serverName, ipFormat))
	s.Send(SSMG_SERVER_LST_END, BuildServerListEnd())
	log.Printf("[Validation] Server list sent (addr=%s)", addr)
	return nil
}

// OnPing menangani CSMG_PING: balas PONG.
func (h *ValidationHandler) OnPing(s *session.Session, data []byte) error {
	s.Send(SSMG_PONG, BuildPong())
	return nil
}

// OnUnknown002F menangani packet 0x002F (unknown packet setelah login).
// Dari capture NekogameECO: Client kirim 0x002F, server balas 0x0030 (6 bytes: 00 30 00 00 00 00)
func (h *ValidationHandler) OnUnknown002F(s *session.Session, data []byte) error {
	log.Printf("[Validation] Received 0x002F (%d bytes), sending 0x0030 response", len(data))
	// Response 0x0030: 6 bytes nol (dari capture: 00 30 00 00 00 00, tapi ID sudah otomatis jadi body = 00 00 00 00)
	s.Send(0x0030, make([]byte, 4)) // 4 bytes body (nol semua)
	return nil
}
