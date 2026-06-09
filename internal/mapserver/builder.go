package mapserver

import (
	"encoding/binary"

	"lumeris-go/internal/model"
)

// putUint32BE menulis uint32 big-endian ke buffer di offset.
func putUint32BE(buf []byte, offset int, val uint32) {
	binary.BigEndian.PutUint32(buf[offset:], val)
}

// putUint16BE menulis uint16 big-endian ke buffer di offset.
func putUint16BE(buf []byte, offset int, val uint16) {
	binary.BigEndian.PutUint16(buf[offset:], val)
}

// BuildVersionACK membuat SSMG_VERSION_ACK packet dengan layout identik
// login.BuildVersionACK: result uint16@0, lalu 6 version bytes@2 (echo klien).
func BuildVersionACK(result uint16, version []byte) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint16(buf[0:], result)
	if len(version) >= 6 {
		copy(buf[2:8], version[:6])
	}
	return buf
}

// BuildLoginAllowed membuat SSMG_LOGIN_ALLOWED packet.
// Same as Login server: 8 bytes, front@0, back@4
func BuildLoginAllowed(front, back uint32) []byte {
	buf := make([]byte, 8)
	putUint32BE(buf, 0, front)
	putUint32BE(buf, 4, back)
	return buf
}

// BuildLoginACK membuat SSMG_LOGIN_ACK packet untuk Map server.
// Byte-exact dari C# SSMG_LOGIN_ACK.cs + capture: body 10 byte (setelah ID dilepas):
//   result uint32@0, Unknown1 uint16@4 (=0x0100), TimeStamp uint32@6.
// PENTING: Unknown1 adalah uint16 (PutUShort@6 di C#), BUKAN uint32. Versi lama
// menulisnya 4 byte sehingga TimeStamp bergeser & body jadi 12 byte — klien gagal
// parse LOGIN_ACK dan berhenti tanpa mengirim CHAR_SLOT (gejala: stuck/layar hitam).
func BuildLoginACK(result uint32, unknown1 uint16, timestamp uint32) []byte {
	buf := make([]byte, 10)
	putUint32BE(buf, 0, result)
	binary.BigEndian.PutUint16(buf[4:], unknown1)
	putUint32BE(buf, 6, timestamp)
	return buf
}

// BuildLoginFinished membuat SSMG_LOGIN_FINISHED (0x1B67).
// C# data[7] dengan ID@0-1 + ActorID@2, jadi body (tanpa ID) = 5 byte: ActorID@0.
func BuildLoginFinished(actorID uint32) []byte {
	buf := make([]byte, 5)
	putUint32BE(buf, 0, actorID)
	return buf
}

// BuildPong membuat SSMG_PONG packet (body kosong).
func BuildPong() []byte {
	return []byte{}
}

// BuildPlayerHPMPSP membuat SSMG_PLAYER_HPMPSP (0x021C), body 33 byte.
// Byte-exact dari capture: actorID(4)@0, marker 0x03@4, lalu blok HP/MP/SP/EP
// masing-masing didahului uint32 nol. Semua nilai big-endian.
func BuildPlayerHPMPSP(actorID, hp, mp, sp, ep uint32) []byte {
	buf := make([]byte, 33)
	putUint32BE(buf, 0, actorID)
	buf[4] = 0x03
	putUint32BE(buf, 9, hp)
	putUint32BE(buf, 17, mp)
	putUint32BE(buf, 25, sp)
	putUint32BE(buf, 29, ep)
	return buf
}

// BuildPlayerMaxHPMPSP membuat SSMG_PLAYER_MAX_HPMPSP (0x0221), body 33 byte.
// Layout identik HPMPSP tapi memuat nilai maksimum.
func BuildPlayerMaxHPMPSP(actorID, maxHP, maxMP, maxSP, maxEP uint32) []byte {
	buf := make([]byte, 33)
	putUint32BE(buf, 0, actorID)
	buf[4] = 0x03
	putUint32BE(buf, 9, maxHP)
	putUint32BE(buf, 17, maxMP)
	putUint32BE(buf, 25, maxSP)
	putUint32BE(buf, 29, maxEP)
	return buf
}

// BuildPlayerStatus membuat SSMG_PLAYER_STATUS (0x0212), body 51 byte.
// Tiga blok stat (base/revide/bonus) tiap-tiap didahului marker 0x08.
// stats urut: Str Dex Int Vit Agi Mag Luk Cha (uint16 BE).
func BuildPlayerStatus(str, dex, intl, vit, agi, mag, luk, cha uint16) []byte {
	buf := make([]byte, 51)
	buf[0] = 0x08
	putUint16BE(buf, 1, str)
	putUint16BE(buf, 3, dex)
	putUint16BE(buf, 5, intl)
	putUint16BE(buf, 7, vit)
	putUint16BE(buf, 9, agi)
	putUint16BE(buf, 11, mag)
	putUint16BE(buf, 13, luk)
	putUint16BE(buf, 15, cha)
	buf[17] = 0x08 // marker blok revide (semua nol)
	buf[34] = 0x08 // marker blok bonus (semua nol)
	return buf
}

// BuildPlayerStatusExtend membuat SSMG_PLAYER_STATUS_EXTEND (0x0217) versi Saga17,
// body 39 byte. Berisi attack/def/hit/avoid + ASPD/CSPD. Nilai diambil VERBATIM
// dari capture klien asli — penting karena field attack-speed/cast-speed bernilai
// nol bisa memicu div-by-zero crash di klien retail (RST ~4 detik).
func BuildPlayerStatusExtend() []byte {
	return []byte{
		0x13, 0x01, 0x9A, 0x00, 0x8D, 0x00, 0x8D, 0x00, 0x8D, 0x00, 0xA6, 0x00,
		0xA6, 0x00, 0xA6, 0x02, 0x6A, 0x03, 0x79, 0x00, 0x2E, 0x00, 0x06, 0x00,
		0x1D, 0x00, 0x4C, 0x01, 0x51, 0x00, 0xB8, 0x00, 0xB5, 0x00, 0xA9, 0x02,
		0x08, 0x02, 0xB0,
	}
}

// BuildPlayerJob membuat SSMG_PLAYER_JOB (0x0244), body 10 byte.
// job(uint32 BE)@0, jointJob(uint32 BE)@4, dualJob(uint16 BE)@8.
func BuildPlayerJob(job uint32) []byte {
	buf := make([]byte, 10)
	putUint32BE(buf, 0, job)
	return buf
}

// BuildActorSpeed membuat SSMG_ACTOR_SPEED (0x1239), body 6 byte.
// actorID(uint32 BE)@0, speed(uint16 BE)@4.
func BuildActorSpeed(actorID uint32, speed uint16) []byte {
	buf := make([]byte, 6)
	putUint32BE(buf, 0, actorID)
	putUint16BE(buf, 4, speed)
	return buf
}

// BuildActorAttackType membuat SSMG_ACTOR_ATTACK_TYPE (0x0FBF), body 5 byte.
// Capture: 00 00 01 55 00 = actorID(4) + attackType(1). Milestone: attackType=0.
func BuildActorAttackType(actorID uint32) []byte {
	buf := make([]byte, 5)
	putUint32BE(buf, 0, actorID)
	return buf
}

// BuildPlayerCapacity membuat SSMG_PLAYER_CAPACITY (0x0230), body 16 byte.
// Capture: 4 nilai uint32 BE (kapasitas inventory: berat/volume cur/max).
// Milestone: pakai nilai aman non-nol dari capture agar klien tidak bagi-nol.
func BuildPlayerCapacity() []byte {
	buf := make([]byte, 16)
	putUint32BE(buf, 0, 0x013B)
	putUint32BE(buf, 4, 0x016D)
	putUint32BE(buf, 8, 0x0898)
	putUint32BE(buf, 12, 0x121E)
	return buf
}

// BuildPlayerElements membuat SSMG_PLAYER_ELEMENTS (0x0223), body 30 byte.
// Capture: marker 0x07@0, lalu nilai elemen (semua nol untuk char baru), 0x07@15.
func BuildPlayerElements() []byte {
	buf := make([]byte, 30)
	buf[0] = 0x07
	buf[15] = 0x07
	return buf
}

// BuildItemEquip membuat SSMG_ITEM_EQUIP (0x09E8), body 10 byte.
// Capture verbatim: FF FF FF FF FF 01 00 00 00 01 (status equip awal).
func BuildItemEquip() []byte {
	return []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x01}
}

// BuildPlayerExp membuat SSMG_PLAYER_EXP (0x0235), body 21 byte.
// Capture: byte ke-8 = 0x01 marker, sisanya progress EXP (nol untuk char baru).
func BuildPlayerExp() []byte {
	buf := make([]byte, 21)
	buf[8] = 0x01
	return buf
}

// BuildActorMode membuat SSMG_ACTOR_MODE (0x0FA7), body 12 byte.
// Capture: actorID(4) + mode1 uint32 (=2 NORMAL)@4 + mode2 uint32@8.
func BuildActorMode(actorID uint32) []byte {
	buf := make([]byte, 12)
	putUint32BE(buf, 0, actorID)
	putUint32BE(buf, 4, 2)
	return buf
}

// BuildActorOption membuat SSMG_ACTOR_OPTION (0x1A5F), body 4 byte.
// Capture verbatim: 00 00 02 00.
func BuildActorOption() []byte {
	return []byte{0x00, 0x00, 0x02, 0x00}
}

// BuildPlayerChangeMap membuat SSMG_PLAYER_CHANGE_MAP (0x11FD), body 15 byte.
// Perintah eksplisit ke klien untuk memuat geometri peta (C# SendChangeMap).
// C# data[17] (ID@0-1) -> body 15: MapID u32@0, X@4, Y@5, Dir@6, DungeonDir=4@7,
// DungeonX=255@8, DungeonY=255@9, FGTakeOff@14.
func BuildPlayerChangeMap(mapID uint32, x, y, dir byte) []byte {
	buf := make([]byte, 15)
	putUint32BE(buf, 0, mapID)
	buf[4] = x
	buf[5] = y
	buf[6] = dir
	buf[7] = 4   // DungeonDir default
	buf[8] = 255 // DungeonX default
	buf[9] = 255 // DungeonY default
	return buf
}

// BuildChatPublic membuat SSMG_CHAT_PUBLIC (0x03E9).
// actorID(uint32 BE)@0 lalu pesan UTF-8 null-terminated mulai offset 4.
func BuildChatPublic(actorID uint32, message string) []byte {
	msg := append([]byte(message), 0)
	buf := make([]byte, 4+len(msg))
	putUint32BE(buf, 0, actorID)
	copy(buf[4:], msg)
	return buf
}

// BuildPlayerStatsBreak membuat SSMG_PLAYER_STATS_BREAK (0x025D), body 1 byte.
// Capture verbatim: 3F (jumlah stat points yang bisa di-allocate).
func BuildPlayerStatsBreak() []byte {
	return []byte{0x3F}
}

// BuildPlayerGoldUpdate membuat SSMG_PLAYER_GOLD_UPDATE (0x09EC), body 8 byte.
// Capture: gold sebagai uint64 BE. Milestone: pakai nilai dari capture.
func BuildPlayerGoldUpdate(gold uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, gold)
	return buf
}

// BuildSkillReserveList membuat SSMG_SKILL_RESERVE_LIST (0x022E), body 2 byte kosong.
func BuildSkillReserveList() []byte {
	return []byte{0x00, 0x00}
}

// BuildSkillJointList membuat SSMG_SKILL_JOINT_LIST (0x022F), body 1 byte kosong.
func BuildSkillJointList() []byte {
	return []byte{0x00}
}

// BuildPlayerLevel membuat SSMG_PLAYER_LEVEL (0x023A), body 17 byte.
// Capture verbatim (struktur level/job-level char baru).
func BuildPlayerLevel() []byte {
	return []byte{0x03, 0x02, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

// BuildPlayerExpoint membuat SSMG_PLAYER_EXPOINT (0x0695), body 11 byte.
// Capture verbatim: byte ke-3 = 0x08 marker, sisanya nol.
func BuildPlayerExpoint() []byte {
	return []byte{0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

// BuildDualjobInfoSend membuat SSMG_DUALJOB_INFO_SEND (0x22D4), body 39 byte.
// Capture verbatim: daftar 12 dual-job slot.
func BuildDualjobInfoSend() []byte {
	return []byte{
		0x0C, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00,
		0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09, 0x00, 0x0A, 0x00, 0x0B, 0x00,
		0x0C, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	}
}

// BuildAnoButtonAppear membuat SSMG_ANO_BUTTON_APPEAR (0x23A0), body 3 byte.
// Capture verbatim: 01 00 00.
func BuildAnoButtonAppear() []byte {
	return []byte{0x01, 0x00, 0x00}
}

// BuildChatExpressionUnlock membuat SSMG_CHAT_EXPRESSION_UNLOCK (0x1D06), body 13 byte.
// Capture verbatim: marker 0x03 + bitmask ekspresi terbuka.
func BuildChatExpressionUnlock() []byte {
	return []byte{0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

// BuildChatExemotionUnlock membuat SSMG_CHAT_EXEMOTION_UNLOCK (0x1CE8), body 65 byte.
// Capture verbatim: marker 0x10 + bitmask emote (16 byte FF) + sisa nol.
func BuildChatExemotionUnlock() []byte {
	buf := make([]byte, 65)
	buf[0] = 0x10
	for i := 1; i <= 20; i++ {
		buf[i] = 0xFF
	}
	return buf
}

// BuildActorMobAppear membuat SSMG_ACTOR_MOB_APPEAR (0x1220), body 29 byte.
// C# data[31] (ID@0-1) -> body 29: actorID u32@0, mobID u32@4, X@8, Y@9,
// speed u16@10, dir@12, HP u32@13 & @21, MaxHP u32@17 & @25.
func BuildActorMobAppear(actorID, mobID uint32, x, y byte, speed uint16, dir byte, hp, maxHP uint32) []byte {
	buf := make([]byte, 29)
	putUint32BE(buf, 0, actorID)
	putUint32BE(buf, 4, mobID)
	buf[8] = x
	buf[9] = y
	putUint16BE(buf, 10, speed)
	buf[12] = dir
	putUint32BE(buf, 13, hp)
	putUint32BE(buf, 17, maxHP)
	putUint32BE(buf, 21, hp)
	putUint32BE(buf, 25, maxHP)
	return buf
}

// BuildActorBuff membuat SSMG_ACTOR_BUFF (0x157C), body 52 byte.
// C#: actorID u32@0 lalu daftar buff (kosong untuk actor baru).
func BuildActorBuff(actorID uint32) []byte {
	buf := make([]byte, 52)
	putUint32BE(buf, 0, actorID)
	return buf
}

// BuildActorMove membuat SSMG_ACTOR_MOVE (0x11F9), body 12 byte.
// C# data[14] (ID@0-1) -> body 12: actorID u32@0, X int16@4, Y int16@6,
// dir u16@8, moveType u16@10.
func BuildActorMove(actorID uint32, x, y int16, dir, moveType uint16) []byte {
	buf := make([]byte, 12)
	putUint32BE(buf, 0, actorID)
	binary.BigEndian.PutUint16(buf[4:], uint16(x))
	binary.BigEndian.PutUint16(buf[6:], uint16(y))
	putUint16BE(buf, 8, dir)
	putUint16BE(buf, 10, moveType)
	return buf
}

// playerInfoTail adalah salinan byte-exact bagian belakang SSMG_PLAYER_INFO (0x01FF)
// dari capture klien Saga17 asli (karakter "Larazeta"), DIMULAI tepat setelah field
// nama. Tail ini mencakup appearance, MapID, posisi, HP/MP/SP, stat, possession,
// gold, equipment-look, motion, mode, dan title — seluruh struktur yang TERBUKTI
// diterima klien retail tanpa crash. Field skalar milik karakter kita di-patch ke
// offset-offset di bawah (relatif terhadap awal tail). Pendekatan template ini
// menghindari drift offset manual yang sebelumnya membuat klien menutup koneksi.
var playerInfoTail = []byte{
	0x00, 0x00, 0x01, 0x01, 0xA8, 0x0A, 0xFF, 0xFF, 0xFF, 0x07, 0xEF, 0x6E,
	0x00, 0x00, 0x00, 0x00, 0x98, 0xF4, 0x40, 0x7C, 0x56, 0x03, 0x00, 0x00,
	0x1A, 0xCE, 0x00, 0x00, 0x1A, 0xCE, 0x00, 0x00, 0x11, 0xDF, 0x00, 0x00,
	0x11, 0xDF, 0x00, 0x00, 0x03, 0xD7, 0x00, 0x00, 0x03, 0xD7, 0x00, 0x00,
	0x00, 0x0E, 0x00, 0x00, 0x00, 0x54, 0x00, 0x09, 0x08, 0x00, 0x08, 0x00,
	0x48, 0x00, 0x06, 0x00, 0x48, 0x00, 0x30, 0x00, 0x73, 0x00, 0x00, 0x00,
	0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x19, 0xA0, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x02, 0xFA, 0xF7, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	0xFE, 0xBD, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
	0x03, 0x0E, 0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x0D, 0x64, 0x00,
	0x00, 0x00, 0x1B,
}

// playerInfoVerbatimLarazeta adalah body SSMG_PLAYER_INFO (0x01FF) lengkap (302 byte,
// setelah ID dilepas) PERSIS dari capture klien "Larazeta". Uji isolasi: replay
// byte-exact yang TERBUKTI diterima klien. Jika replay ini pun crash, masalah ada di
// framing/urutan, bukan isi PLAYER_INFO.
var playerInfoVerbatimLarazeta = []byte{
	0x00, 0x00, 0x01, 0x55, 0x00, 0x00, 0xF9, 0x6E, 0x00, 0x00, 0x00, 0x02,
	0x00, 0x09, 0x4C, 0x61, 0x72, 0x61, 0x7A, 0x65, 0x74, 0x61, 0x00, 0x00,
	0x00, 0x01, 0x01, 0xA8, 0x0A, 0xFF, 0xFF, 0xFF, 0x07, 0xEF, 0x6E, 0x00,
	0x00, 0x00, 0x00, 0x98, 0xF4, 0x40, 0x7C, 0x56, 0x03, 0x00, 0x00, 0x1A,
	0xCE, 0x00, 0x00, 0x1A, 0xCE, 0x00, 0x00, 0x11, 0xDF, 0x00, 0x00, 0x11,
	0xDF, 0x00, 0x00, 0x03, 0xD7, 0x00, 0x00, 0x03, 0xD7, 0x00, 0x00, 0x00,
	0x0E, 0x00, 0x00, 0x00, 0x54, 0x00, 0x09, 0x08, 0x00, 0x08, 0x00, 0x48,
	0x00, 0x06, 0x00, 0x48, 0x00, 0x30, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00,
	0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x19, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFA, 0xF7, 0x61, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x02, 0xFE, 0xBD, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x04, 0x00, 0x03, 0x0E, 0x07, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x03, 0x0D, 0x64, 0x00, 0x00, 0x00, 0x1B,
}

// BuildPlayerInfoVerbatim mengembalikan replay byte-exact PLAYER_INFO Larazeta.
func BuildPlayerInfoVerbatim() []byte {
	out := make([]byte, len(playerInfoVerbatimLarazeta))
	copy(out, playerInfoVerbatimLarazeta)
	return out
}

// Offset field skalar di dalam playerInfoTail (relatif awal tail), DIVERIFIKASI
// empiris dari capture: tail dimulai di body[23] (setelah nama+null), MapID di
// body[38]→tail[15], HP di body[45]→tail[22], MP body[53]→tail[30], SP body[61]→
// tail[38]. ActorID & CharID berada di header (sebelum tail).
const (
	tRace      = 0
	tForm      = 1
	tGender    = 2
	tHair      = 3 // uint16
	tHairColor = 5
	tFace      = 9  // uint16
	tRebirth   = 11 // 0x6E jika rebirth, 0 jika tidak
	tMapID     = 15 // uint32
	tPosX      = 19
	tPosY      = 20
	tHP        = 22 // uint32
	tMaxHP     = 26 // uint32
	tMP        = 30 // uint32
	tMaxMP     = 34 // uint32
	tSP        = 38 // uint32
	tMaxSP     = 42 // uint32
	tLevel     = 54 // uint16 (CL)
	tStr       = 57 // uint16, lalu Dex/Int/Vit/Agi/Mnd berurutan +2
	tTitles    = 263 // 4× uint32 title/achievement ID (16 byte terakhir tail)
)

// BuildPlayerInfo membuat SSMG_PLAYER_INFO (0x01FF) versi Saga17 — paket spawn utama
// yang membuat klien me-render karakter sendiri di map. Header (ActorID/CharID/nama)
// dibangun dinamis; sisanya memakai playerInfoTail (template byte-exact dari capture)
// dengan field skalar karakter di-patch di offset tabel t* di atas.
// BuildPlayerInfo membuat SSMG_PLAYER_INFO (0x01FF) Saga17. Tail diambil dari
// playerInfoVerbatimLarazeta (paket TERBUKTI diterima klien tanpa crash), bukan
// template lama yang 7 byte lebih panjang (berasal dari karakter bersenjata &
// menggeser semua field). Hanya field identitas/posisi/stat yang di-patch.
func BuildPlayerInfo(c *model.Character, actorID uint32) []byte {
	name := []byte(c.Name)

	// Tail proven = bagian verbatim setelah header nama Larazeta (offset 23 dst).
	const verbBase = 23
	tail := make([]byte, len(playerInfoVerbatimLarazeta)-verbBase)
	copy(tail, playerInfoVerbatimLarazeta[verbBase:])

	body := make([]byte, 0, 15+len(name)+len(tail))
	tmp := make([]byte, 12)
	binary.BigEndian.PutUint32(tmp[0:], actorID)
	binary.BigEndian.PutUint32(tmp[4:], uint32(c.ID))
	binary.BigEndian.PutUint32(tmp[8:], 2)
	body = append(body, tmp...)
	nameLen := make([]byte, 2)
	binary.BigEndian.PutUint16(nameLen, uint16(len(name)+1))
	body = append(body, nameLen...)
	body = append(body, name...)
	body = append(body, 0x00)

	p32 := func(o int, v uint32) { binary.BigEndian.PutUint32(tail[o:], v) }
	p16 := func(o int, v uint16) { binary.BigEndian.PutUint16(tail[o:], v) }

	tail[tRace] = c.Race
	tail[tForm] = c.Form
	tail[tGender] = c.Gender
	p16(tHair, uint16(c.Appearance.Hair))
	tail[tHairColor] = byte(c.Appearance.HairColor)
	p16(tFace, uint16(c.Face))
	if c.Rebirth {
		tail[tRebirth] = 0x6E
	} else {
		tail[tRebirth] = 0x00
	}
	p32(tMapID, uint32(c.MapID))
	tail[tPosX] = byte(c.X)
	tail[tPosY] = byte(c.Y)
	p32(tHP, uint32(c.HP))
	p32(tMaxHP, uint32(c.MaxHP))
	p32(tMP, uint32(c.SP))
	p32(tMaxMP, uint32(c.MaxSP))
	p32(tSP, uint32(c.SP))
	p32(tMaxSP, uint32(c.MaxSP))
	p16(tLevel, uint16(c.Level))
	p16(tStr, uint16(c.Str))
	p16(tStr+2, uint16(c.Dex))
	p16(tStr+4, uint16(c.Int))
	p16(tStr+6, uint16(c.Vit))
	p16(tStr+8, uint16(c.Agi))
	p16(tStr+10, uint16(c.Mnd))

	body = append(body, tail...)
	return body
}
