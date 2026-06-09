package mapserver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"log"
	"time"

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
		CSMG_SEND_VERSION:     h.OnSendVersion,
		CSMG_LOGIN:            h.OnLogin,
		CSMG_PING:             h.OnPing,
		CSMG_CHAR_SLOT:        h.OnCharSlot,
		CSMG_PLAYER_MAP_LOADED: h.OnMapLoaded,
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
	timestamp := uint32(time.Now().Unix())
	s.Send(SSMG_LOGIN_ACK, BuildLoginACK(LOGIN_OK, 0x0100, timestamp))

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
			actorID := uint32(char.ID)
			log.Printf("[Map] Char selected: %s (slot %d, MapID=%d), sending spawn sequence", char.Name, char.Slot, char.MapID)

			hp := uint32(char.HP)
			maxHP := uint32(char.MaxHP)
			sp := uint32(char.SP)
			maxSP := uint32(char.MaxSP)

			// Urutan paket = C# PCEventHandler.OnCreate first-login (diverifikasi
			// dengan capture klien asli). ACTOR_SPEED (SendActorID) wajib pertama
			// agar klien mengenali ActorID sendiri; PLAYER_INFO menyusul; lalu rantai
			// stat personal; ditutup populasi dunia (mob) sebelum klien kirim 0x11FE.
			s.Send(SSMG_ACTOR_SPEED, BuildActorSpeed(actorID, 10))
			s.Send(SSMG_ACTOR_MODE, BuildActorMode(actorID))
			s.Send(SSMG_PLAYER_INFO, BuildPlayerInfo(char, actorID))
			s.Send(SSMG_PLAYER_STATS_BREAK, BuildPlayerStatsBreak())
			s.Send(SSMG_PLAYER_GOLD_UPDATE, BuildPlayerGoldUpdate(0))
			s.Send(SSMG_PLAYER_MAX_HPMPSP, BuildPlayerMaxHPMPSP(actorID, maxHP, maxSP, maxSP, 0))
			s.Send(SSMG_PLAYER_HPMPSP, BuildPlayerHPMPSP(actorID, hp, sp, sp, 0))
			s.Send(SSMG_PLAYER_STATUS, BuildPlayerStatus(
				uint16(char.Str), uint16(char.Dex), uint16(char.Int),
				uint16(char.Vit), uint16(char.Agi), uint16(char.Mnd), 13, 0))
			s.Send(SSMG_ITEM_EQUIP, BuildItemEquip())
			s.Send(SSMG_PLAYER_STATUS_EXTEND, BuildPlayerStatusExtend())
			s.Send(SSMG_PLAYER_CAPACITY, BuildPlayerCapacity())
			s.Send(SSMG_PLAYER_JOB, BuildPlayerJob(uint32(char.Job)))
			s.Send(SSMG_SKILL_RESERVE_LIST, BuildSkillReserveList())
			s.Send(SSMG_SKILL_JOINT_LIST, BuildSkillJointList())
			s.Send(SSMG_PLAYER_LEVEL, BuildPlayerLevel())
			s.Send(SSMG_PLAYER_EXP, BuildPlayerExp())
			s.Send(SSMG_ACTOR_ATTACK_TYPE, BuildActorAttackType(actorID))
			s.Send(SSMG_CHAT_EXPRESSION_UNLOCK, BuildChatExpressionUnlock())
			s.Send(SSMG_CHAT_EXEMOTION_UNLOCK, BuildChatExemotionUnlock())
			s.Send(SSMG_PLAYER_EXPOINT, BuildPlayerExpoint())
			s.Send(SSMG_DUALJOB_INFO_SEND, BuildDualjobInfoSend())
			s.Send(SSMG_ANO_BUTTON_APPEAR, BuildAnoButtonAppear())
			s.Send(SSMG_PLAYER_ELEMENTS, BuildPlayerElements())

			// Populasi dunia: spawn mob di peta. Klien retail menunggu paket ini
			// (set MOB_APPEAR + BUFF + MOVE per mob) sebelum mengirim 0x11FE.
			h.spawnMapActors(s)

			log.Printf("[Map] Spawn sequence sent, waiting for MAP_LOADED (0x11FE)")
			return nil
		}
	}

	log.Printf("[Map] CHAR_SLOT: slot %d kosong", parsed.Slot)
	return nil
}

// spawnMapActors mengirim populasi dunia (mob) ke klien. Capture asli mengirim
// blok MOB_APPEAR + ACTOR_BUFF + ACTOR_MOVE per mob sebelum klien kirim 0x11FE.
// Milestone: spawn beberapa mob statis dengan ActorID unik di sekitar peta.
func (h *MapHandler) spawnMapActors(s *session.Session) {
	type mob struct {
		mobID    uint32
		x, y     byte
		hp       uint32
	}
	mobs := []mob{
		{mobID: 0x00999A7F, x: 0xBA, y: 0x8E, hp: 0xB9},
		{mobID: 0x009959D0, x: 0x78, y: 0x86, hp: 0x96},
		{mobID: 0x009959D0, x: 0x54, y: 0x72, hp: 0xC8},
	}
	for i, m := range mobs {
		actorID := uint32(0x2800 + i)
		s.Send(SSMG_ACTOR_MOB_APPEAR, BuildActorMobAppear(actorID, m.mobID, m.x, m.y, 0x0800, 0, m.hp, m.hp))
		s.Send(SSMG_ACTOR_BUFF, BuildActorBuff(actorID))
		s.Send(SSMG_ACTOR_MOVE, BuildActorMove(actorID, int16(m.x)<<6, int16(m.y)<<6, 0x0168, 0x0006))
	}
}

// OnMapLoaded menangani CSMG_PLAYER_MAP_LOADED (0x11FE): klien selesai load map.
// Capture asli: klien kirim 0x11FE SETELAH menerima seluruh spawn flood, lalu
// server membalas SSMG_LOGIN_FINISHED (0x1B67) untuk membuka input klien.
func (h *MapHandler) OnMapLoaded(s *session.Session, data []byte) error {
	mctx, ok := s.Context.(*MapContext)
	if !ok || mctx == nil || mctx.Character == nil {
		log.Printf("[Map] MAP_LOADED: context invalid")
		return nil
	}

	s.Send(SSMG_LOGIN_FINISHED, BuildLoginFinished(uint32(mctx.Character.ID)))
	log.Printf("[Map] LOGIN_FINISHED sent, %s fully in map", mctx.Character.Name)
	return nil
}

// OnPing menangani CSMG_PING: balas PONG.
func (h *MapHandler) OnPing(s *session.Session, data []byte) error {
	s.Send(SSMG_PONG, BuildPong())
	return nil
}
