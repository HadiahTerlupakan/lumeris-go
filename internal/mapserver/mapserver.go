package mapserver

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

// MapContext menyimpan state per-session untuk Map server.
type MapContext struct {
	FrontWord uint32
	BackWord  uint32
	Account   *model.Account
	Character *model.Character
}

// MapHandler adalah dispatcher untuk Map server (:12024).
type MapHandler struct {
	store db.Store
}

// NewMapHandler membuat handler baru.
func NewMapHandler(store db.Store) *MapHandler {
	return &MapHandler{store: store}
}

// Dispatch mengembalikan dispatch table untuk Map server.
func (h *MapHandler) Dispatch() map[uint16]session.HandlerFunc {
	return map[uint16]session.HandlerFunc{
		CSMG_SEND_VERSION: h.OnSendVersion,
		CSMG_LOGIN:        h.OnLogin,
		CSMG_PING:         h.OnPing,
		CSMG_CHAR_SLOT:    h.OnCharSlot,
	}
}

// OnSendVersion menangani CSMG_SEND_VERSION di Map server.
func (h *MapHandler) OnSendVersion(s *session.Session, data []byte) error {
	parsed, err := ParseSendVersion(data)
	if err != nil {
		log.Printf("[Map] ParseSendVersion error: %v", err)
		return err
	}

	log.Printf("[Map] Client version: %s", parsed.Version)

	// Send VERSION_ACK
	s.Send(SSMG_VERSION_ACK, BuildVersionACK(0, parsed.VersionBytes[:]))

	// Generate challenge
	mctx := &MapContext{}
	binary.Read(rand.Reader, binary.BigEndian, &mctx.FrontWord)
	binary.Read(rand.Reader, binary.BigEndian, &mctx.BackWord)
	s.Context = mctx

	// Send LOGIN_ALLOWED
	s.Send(SSMG_LOGIN_ALLOWED, BuildLoginAllowed(mctx.FrontWord, mctx.BackWord))

	log.Printf("[Map] Version OK, challenge sent (front=%d, back=%d)", mctx.FrontWord, mctx.BackWord)
	return nil
}

// OnLogin menangani CSMG_LOGIN di Map server: re-auth.
func (h *MapHandler) OnLogin(s *session.Session, data []byte) error {
	parsed, err := ParseLogin(data)
	if err != nil {
		log.Printf("[Map] ParseLogin error: %v", err)
		return err
	}

	mctx, ok := s.Context.(*MapContext)
	if !ok || mctx == nil {
		log.Printf("[Map] Context invalid")
		s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_UNKNOWN_ACC, 0, 0))
		return nil
	}

	// Fetch account
	acc, err := h.store.GetAccountByName(context.Background(), parsed.Username)
	if err == db.ErrNotFound {
		log.Printf("[Map] Login gagal: akun tidak ditemukan (%s)", parsed.Username)
		s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_UNKNOWN_ACC, 0, 0))
		return nil
	}
	if err != nil {
		log.Printf("[Map] GetAccountByName error: %v", err)
		s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_UNKNOWN_ACC, 0, 0))
		return nil
	}

	// Verifikasi SHA1 challenge
	if !auth.VerifyChallenge(acc.PasswordHash, mctx.FrontWord, mctx.BackWord, parsed.Password[:]) {
		log.Printf("[Map] Login gagal: password salah (%s)", parsed.Username)
		s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_BADPASS, 0, 0))
		return nil
	}

	if acc.Banned {
		log.Printf("[Map] Login gagal: banned (%s)", parsed.Username)
		s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_BFALOCK, 0, 0))
		return nil
	}

	// Login OK
	mctx.Account = acc
	// C# line 106: TimeStamp = Unix timestamp
	timestamp := uint32(1717851600) // Milestone: fixed timestamp
	s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_OK, 0x100, timestamp))

	log.Printf("[Map] Login berhasil: %s (ID=%d)", acc.Username, acc.ID)
	return nil
}

// OnCharSlot menangani CSMG_CHAR_SLOT: client pilih slot untuk masuk map.
func (h *MapHandler) OnCharSlot(s *session.Session, data []byte) error {
	parsed, err := ParseCharSlot(data)
	if err != nil {
		log.Printf("[Map] ParseCharSlot error: %v", err)
		return err
	}

	mctx, ok := s.Context.(*MapContext)
	if !ok || mctx == nil || mctx.Account == nil {
		log.Printf("[Map] CHAR_SLOT: context invalid")
		return nil
	}

	// Cari character di slot
	chars, err := h.store.CharsByAccount(context.Background(), mctx.Account.ID)
	if err != nil {
		log.Printf("[Map] CharsByAccount error: %v", err)
		return nil
	}

	for _, char := range chars {
		if char.Slot == int(parsed.Slot) {
			mctx.Character = char
			log.Printf("[Map] Char selected for map entry: %s (slot %d, MapID=%d)", char.Name, char.Slot, char.MapID)

			// Milestone: send minimal packets untuk spawn character
			// TODO: Implement full map entry sequence (ACTOR_APPEAR, MAP_INFO, etc.)
			// Untuk sekarang, client akan stuck di loading screen, tapi ini milestone

			return nil
		}
	}

	log.Printf("[Map] CHAR_SLOT: slot %d kosong", parsed.Slot)
	return nil
}

// OnPing menangani CSMG_PING: balas PONG.
func (h *MapHandler) OnPing(s *session.Session, data []byte) error {
	s.Send(SSMG_PONG, BuildPong())
	return nil
}
