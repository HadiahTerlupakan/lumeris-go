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

// LoginContext menyimpan state per-session untuk Login server.
type LoginContext struct {
	FrontWord      uint32
	BackWord       uint32
	Account        *model.Account
	Characters     []*model.Character
	SelectedCharID int64 // ID karakter yang dipilih via CHAR_SELECT
}

// LoginHandler adalah dispatcher untuk Login server (:12023).
type LoginHandler struct {
	store   db.Store
	devMode bool
}

// NewLoginHandler membuat handler baru.
func NewLoginHandler(store db.Store, devMode bool) *LoginHandler {
	return &LoginHandler{store: store, devMode: devMode}
}

// Dispatch mengembalikan dispatch table untuk Login server.
func (h *LoginHandler) Dispatch() map[uint16]session.HandlerFunc {
	return map[uint16]session.HandlerFunc{
		CSMG_SEND_VERSION:       h.OnSendVersion,
		CSMG_LOGIN:              h.OnLogin,
		CSMG_PING:               h.OnPing,
		CSMG_CHAR_STATUS:        h.OnCharStatus,
		CSMG_CHAR_CREATE:        h.OnCharCreate,
		CSMG_CHAR_DELETE:        h.OnCharDelete,
		CSMG_CHAR_SELECT:        h.OnCharSelect,
		CSMG_REQUEST_MAP_SERVER: h.OnRequestMapServer,
	}
}

// OnSendVersion menangani CSMG_SEND_VERSION di Login server (re-handshake).
func (h *LoginHandler) OnSendVersion(s *session.Session, data []byte) error {
	parsed, err := ParseSendVersion(data)
	if err != nil {
		log.Printf("[Login] ParseSendVersion error: %v", err)
		return err
	}

	// CATATAN: TIDAK ada mystery packet 0xFFFF dan TIDAK ada REQUEST_NYA (0x0150).
	// Capture klien asli (proxy_packets.log fase Login) menunjukkan:
	//   C->S 0x0001 -> S->C 0x0002 VERSION_ACK -> S->C 0x001E LOGIN_ALLOWED
	//   -> C->S 0x001F LOGIN -> S->C 0x0020 LOGIN_ACK -> S->C 0x0028 CHAR_DATA
	// Tidak ada 0xFFFF maupun 0x0150 di antaranya.
	s.Send(SSMG_VERSION_ACK, BuildVersionACK(0, parsed.VersionBytes[:]))

	// Generate new front & back word
	lctx := &LoginContext{}
	binary.Read(rand.Reader, binary.BigEndian, &lctx.FrontWord)
	binary.Read(rand.Reader, binary.BigEndian, &lctx.BackWord)
	s.Context = lctx

	s.Send(SSMG_LOGIN_ALLOWED, BuildLoginAllowed(lctx.FrontWord, lctx.BackWord))

	log.Printf("[Login] Version OK, challenge sent")
	return nil
}

// OnLogin menangani CSMG_LOGIN di Login server: re-auth + kirim char list.
func (h *LoginHandler) OnLogin(s *session.Session, data []byte) error {
	parsed, err := ParseLogin(data)
	if err != nil {
		log.Printf("[Login] ParseLogin error: %v", err)
		return err
	}

	lctx, ok := s.Context.(*LoginContext)
	if !ok || lctx == nil {
		log.Printf("[Login] Context invalid")
		s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_UNKNOWN_ACC, 0))
		return nil
	}

	// Fetch account
	acc, err := h.store.GetAccountByName(context.Background(), parsed.Username)
	if err == db.ErrNotFound {
		log.Printf("[Login] Login gagal: akun tidak ditemukan (%s)", parsed.Username)
		s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_UNKNOWN_ACC, 0))
		return nil
	}
	if err != nil {
		log.Printf("[Login] GetAccountByName error: %v", err)
		s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_UNKNOWN_ACC, 0))
		return nil
	}

	// Verifikasi SHA1 challenge (bypass in dev mode)
	if h.devMode {
		log.Printf("[Login] DEV MODE: Password check BYPASSED for %s", parsed.Username)
	} else {
		if !auth.VerifyChallenge(acc.PasswordHash, lctx.FrontWord, lctx.BackWord, parsed.Password) {
			log.Printf("[Login] Login gagal: password salah (%s)", parsed.Username)
			s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_BADPASS, 0))
			return nil
		}
	}

	if acc.Banned {
		log.Printf("[Login] Login gagal: banned (%s)", parsed.Username)
		s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_BFALOCK, 0))
		return nil
	}

	// Login OK
	lctx.Account = acc
	s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_OK, uint32(acc.ID)))

	// Kirim char list
	h.sendCharData(s, lctx)

	log.Printf("[Login] Login berhasil + char list sent: %s", acc.Username)
	return nil
}

// sendCharData mengirim CHAR_DATA + CHAR_EQUIP untuk semua karakter akun.
func (h *LoginHandler) sendCharData(s *session.Session, lctx *LoginContext) {
	chars, err := h.store.CharsByAccount(context.Background(), lctx.Account.ID)
	if err != nil {
		log.Printf("[Login] CharsByAccount error: %v", err)
		return
	}
	lctx.Characters = chars

	// Saga18: CHAR_DATA berisi SEMUA slot (array-4) dalam SATU paket, diikuti CHAR_EQUIP.
	s.Send(SSMG_CHAR_DATA, BuildCharData(chars))
	s.Send(SSMG_CHAR_EQUIP, BuildCharEquip())
}

// OnCharStatus menangani CSMG_CHAR_STATUS (0x002A).
// Capture klien asli: setelah map LOGIN_ACK, klien kirim 0x002A di koneksi Login
// dan MENUNGGU balasan 0x002B (body kosong) sebelum mengirim CHAR_SLOT ke map.
// Tanpa balasan ini klien berhenti di loading map (gejala: layar hitam).
func (h *LoginHandler) OnCharStatus(s *session.Session, data []byte) error {
	s.Send(SSMG_CHAR_STATUS_ACK, []byte{})
	return nil
}

// OnCharCreate menangani CSMG_CHAR_CREATE: buat karakter baru.
func (h *LoginHandler) OnCharCreate(s *session.Session, data []byte) error {
	parsed, err := ParseCharCreate(data)
	if err != nil {
		log.Printf("[Login] ParseCharCreate error: %v", err)
		return err
	}

	lctx, ok := s.Context.(*LoginContext)
	if !ok || lctx == nil || lctx.Account == nil {
		s.Send(SSMG_CHAR_CREATE_ACK, BuildCharCreateACK(CHAR_CREATE_NAME_BADCHAR))
		return nil
	}

	// Validasi: slot sudah terisi?
	for _, char := range lctx.Characters {
		if char.Slot == int(parsed.Slot) {
			log.Printf("[Login] Char create gagal: slot %d sudah terisi", parsed.Slot)
			s.Send(SSMG_CHAR_CREATE_ACK, BuildCharCreateACK(CHAR_CREATE_ALREADY_SLOT))
			return nil
		}
	}

	// Buat karakter dengan starting values (milestone: default sederhana)
	char := &model.Character{
		AccountID:      lctx.Account.ID,
		Slot:           int(parsed.Slot),
		Name:           parsed.Name,
		Race:           parsed.Race,
		Gender:         parsed.Gender,
		Job:            1, // Job default
		Level:          1,
		MapID:          30204000, // Start map Emil/Titania/Dominion (SagaLogin.xml StartupSetting)
		X:              15,       // StartX dari config C# asli
		Y:              16,       // StartY dari config C# asli
		HP:             120,
		MaxHP:          120,
		SP:             100,
		MaxSP:          100,
		Str:            5,
		Dex:            5,
		Int:            5,
		Vit:            5,
		Agi:            5,
		Mnd:            5,
		Appearance:     model.Appearance{Hair: int(parsed.HairStyle), HairColor: int(parsed.HairColor), Face: int(parsed.Face)},
		Face:           int(parsed.Face),
		Form:           0,
		Wig:            0xFF,
		QuestRemaining: 3,
		JobLevel1:      1,
		JobLevel2X:     0,
		JobLevel2T:     0,
		JobLevel3:      0,
		Rebirth:        false,
	}

	if err := h.store.CreateCharacter(context.Background(), char); err == db.ErrDuplicate {
		log.Printf("[Login] Char create gagal: nama duplikat (%s)", char.Name)
		s.Send(SSMG_CHAR_CREATE_ACK, BuildCharCreateACK(CHAR_CREATE_NAME_CONFLICT))
		return nil
	} else if err != nil {
		log.Printf("[Login] CreateCharacter error: %v", err)
		s.Send(SSMG_CHAR_CREATE_ACK, BuildCharCreateACK(CHAR_CREATE_NAME_BADCHAR))
		return nil
	}

	// Berhasil
	s.Send(SSMG_CHAR_CREATE_ACK, BuildCharCreateACK(CHAR_CREATE_OK))
	// Refresh char list
	h.sendCharData(s, lctx)

	log.Printf("[Login] Char created: %s (slot %d)", char.Name, char.Slot)
	return nil
}

// OnCharDelete menangani CSMG_CHAR_DELETE: hapus karakter.
func (h *LoginHandler) OnCharDelete(s *session.Session, data []byte) error {
	parsed, err := ParseCharDelete(data)
	if err != nil {
		log.Printf("[Login] ParseCharDelete error: %v", err)
		return err
	}

	lctx, ok := s.Context.(*LoginContext)
	if !ok || lctx == nil || lctx.Account == nil {
		return nil
	}

	// Verifikasi delete password
	if parsed.DeletePassword != lctx.Account.DeletePass {
		log.Printf("[Login] Char delete gagal: password salah (slot %d)", parsed.Slot)
		// Milestone: tidak ada ACK khusus untuk delete fail di spec, abaikan atau kirim char list ulang
		return nil
	}

	// Cari char di slot
	var targetID int64
	for _, char := range lctx.Characters {
		if char.Slot == int(parsed.Slot) {
			targetID = char.ID
			break
		}
	}
	if targetID == 0 {
		log.Printf("[Login] Char delete: slot %d kosong", parsed.Slot)
		return nil
	}

	if err := h.store.DeleteCharacter(context.Background(), targetID); err != nil {
		log.Printf("[Login] DeleteCharacter error: %v", err)
		return nil
	}

	// Refresh char list
	h.sendCharData(s, lctx)

	log.Printf("[Login] Char deleted: slot %d", parsed.Slot)
	return nil
}

// OnCharSelect menangani CSMG_CHAR_SELECT: pilih karakter.
func (h *LoginHandler) OnCharSelect(s *session.Session, data []byte) error {
	parsed, err := ParseCharSelect(data)
	if err != nil {
		return err
	}

	lctx, ok := s.Context.(*LoginContext)
	if !ok || lctx == nil || lctx.Account == nil {
		return nil
	}

	// Cari char di slot
	for _, char := range lctx.Characters {
		if char.Slot == int(parsed.Slot) {
			lctx.SelectedCharID = char.ID
			s.Send(SSMG_CHAR_SELECT_ACK, BuildCharSelectACK(uint32(char.MapID)))
			log.Printf("[Login] Char selected: %s (ID=%d, MapID=%d)", char.Name, char.ID, char.MapID)
			return nil
		}
	}

	log.Printf("[Login] Char select: slot %d kosong", parsed.Slot)
	return nil
}

// OnRequestMapServer menangani CSMG_REQUEST_MAP_SERVER: kirim alamat map server.
func (h *LoginHandler) OnRequestMapServer(s *session.Session, data []byte) error {
	lctx, ok := s.Context.(*LoginContext)
	if !ok || lctx == nil || lctx.SelectedCharID == 0 {
		log.Printf("[Login] REQUEST_MAP_SERVER tanpa char selected")
		return nil
	}

	// Milestone: hardcode map server
	s.Send(SSMG_SEND_TO_MAP_SERVER, BuildSendToMapServer(1, "127.0.0.1", 12024)) // TODO: dari config
	log.Printf("[Login] Map server address sent")
	return nil
}

// OnPing menangani CSMG_PING: balas PONG.
func (h *LoginHandler) OnPing(s *session.Session, data []byte) error {
	s.Send(SSMG_PONG, BuildPong())
	return nil
}
