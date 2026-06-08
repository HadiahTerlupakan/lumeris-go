package login

import (
	"context"
	"crypto/rand"
	"encoding/binary"
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
	store db.Store
}

// NewValidationHandler membuat handler baru.
func NewValidationHandler(store db.Store) *ValidationHandler {
	return &ValidationHandler{store: store}
}

// Dispatch mengembalikan dispatch table untuk Validation server.
func (h *ValidationHandler) Dispatch() map[uint16]session.HandlerFunc {
	return map[uint16]session.HandlerFunc{
		CSMG_SEND_VERSION:  h.OnSendVersion,
		CSMG_LOGIN:         h.OnLogin,
		CSMG_SERVERLET_ASK: h.OnServerletAsk,
		CSMG_PING:          h.OnPing,
	}
}

// OnSendVersion menangani CSMG_SEND_VERSION: kirim VERSION_ACK -> LOGIN_ALLOWED -> REQUEST_NYA.
func (h *ValidationHandler) OnSendVersion(s *session.Session, data []byte) error {
	parsed, err := ParseSendVersion(data)
	if err != nil {
		log.Printf("[Validation] ParseSendVersion error: %v", err)
		return err
	}

	// Milestone: terima versi apa saja
	s.Send(SSMG_VERSION_ACK, BuildVersionACK(0, parsed.VersionBytes[:]))

	// Generate front & back word
	vctx := &ValidationContext{}
	binary.Read(rand.Reader, binary.BigEndian, &vctx.FrontWord)
	binary.Read(rand.Reader, binary.BigEndian, &vctx.BackWord)
	s.Context = vctx

	s.Send(SSMG_LOGIN_ALLOWED, BuildLoginAllowed(vctx.FrontWord, vctx.BackWord))
	s.Send(SSMG_REQUEST_NYA, BuildRequestNya())

	log.Printf("[Validation] Version OK, challenge sent (front=%08x, back=%08x)", vctx.FrontWord, vctx.BackWord)
	return nil
}

// OnLogin menangani CSMG_LOGIN di fase Validation: verifikasi SHA1 challenge.
func (h *ValidationHandler) OnLogin(s *session.Session, data []byte) error {
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

	// Verifikasi SHA1 challenge
	if !auth.VerifyChallenge(acc.PasswordHash, vctx.FrontWord, vctx.BackWord, parsed.Password) {
		log.Printf("[Validation] Login gagal: password salah (%s)", parsed.Username)
		s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_BADPASS, 0))
		return nil
	}

	// Check banned
	if acc.Banned {
		log.Printf("[Validation] Login gagal: banned (%s)", parsed.Username)
		s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_BFALOCK, 0))
		return nil
	}

	// Login berhasil
	vctx.Account = acc
	s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_OK, uint32(acc.ID)))
	log.Printf("[Validation] Login berhasil: %s (ID=%d)", acc.Username, acc.ID)
	return nil
}

// OnServerletAsk menangani CSMG_SERVERLET_ASK: kirim daftar server (LOGIN server).
func (h *ValidationHandler) OnServerletAsk(s *session.Session, data []byte) error {
	// Milestone: hardcode satu server "SagaECO" -> IP dari env (nanti via config)
	s.Send(SSMG_SERVER_LST_START, BuildServerListStart())
	s.Send(SSMG_SERVER_LST_SEND, BuildServerListSend("SagaECO", "127.0.0.1")) // TODO: dari config
	s.Send(SSMG_SERVER_LST_END, BuildServerListEnd())
	log.Printf("[Validation] Server list sent")
	return nil
}

// OnPing menangani CSMG_PING: balas PONG.
func (h *ValidationHandler) OnPing(s *session.Session, data []byte) error {
	s.Send(SSMG_PONG, BuildPong())
	return nil
}
