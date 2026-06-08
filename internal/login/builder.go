package login

import (
	"lumeris-go/internal/model"
)

// BuildVersionACK membuat SSMG_VERSION_ACK packet.
// result: 0 = OK, 0xFFFF = version mismatch
// versionBytes: 6 byte version info dari klien (echo back)
func BuildVersionACK(result uint16, versionBytes []byte) []byte {
	buf := make([]byte, 10)
	putUint16BE(buf, 0, result)
	if len(versionBytes) >= 6 {
		copy(buf[4:10], versionBytes[:6])
	}
	return buf
}

// BuildLoginAllowed membuat SSMG_LOGIN_ALLOWED packet dengan front/back challenge words.
func BuildLoginAllowed(front, back uint32) []byte {
	buf := make([]byte, 8)
	putUint32BE(buf, 0, front)
	putUint32BE(buf, 4, back)
	return buf
}

// BuildLoginACK membuat SSMG_LOGIN_ACK packet.
// result: LOGIN_OK / LOGIN_UNKNOWN_ACC / LOGIN_BADPASS / LOGIN_BFALOCK / LOGIN_ALREADY / LOGIN_IPBLOCK
// accountID: ID akun yang login (0 bila gagal)
func BuildLoginACK(result, accountID uint32) []byte {
	buf := make([]byte, 16)
	putUint32BE(buf, 0, result)
	putUint32BE(buf, 4, accountID)
	// RestTestTime@8 dan TestEndTime@12 default 0 (milestone)
	return buf
}

// BuildRequestNya membuat SSMG_REQUEST_NYA packet (body kosong, NyaShield).
func BuildRequestNya() []byte {
	return []byte{}
}

// BuildServerListStart membuat SSMG_SERVER_LST_START packet (body kosong).
func BuildServerListStart() []byte {
	return []byte{}
}

// BuildServerListSend membuat SSMG_SERVER_LST_SEND packet.
// name: nama server (UTF-8), ip: IP server (UTF-8)
func BuildServerListSend(name, ip string) []byte {
	nameBytes := []byte(name)
	ipBytes := []byte(ip)
	// Layout: nameLen(1) + name + \0 + ipLen(1) + ip + \0
	buf := make([]byte, 1+len(nameBytes)+1+1+len(ipBytes)+1)
	offset := 0
	buf[offset] = byte(len(nameBytes) + 1) // +1 untuk \0
	offset++
	copy(buf[offset:], nameBytes)
	offset += len(nameBytes)
	buf[offset] = 0 // \0
	offset++
	buf[offset] = byte(len(ipBytes) + 1) // +1 untuk \0
	offset++
	copy(buf[offset:], ipBytes)
	offset += len(ipBytes)
	buf[offset] = 0 // \0
	return buf
}

// BuildServerListEnd membuat SSMG_SERVER_LST_END packet (body kosong).
func BuildServerListEnd() []byte {
	return []byte{}
}

// BuildCharData membuat SSMG_CHAR_DATA packet (Saga11: 131 byte base).
// Simplified version untuk milestone - field utama saja.
func BuildCharData(char *model.Character) []byte {
	buf := make([]byte, 131)
	// Offset layout (simplified, byte-exact sesuai RE nanti di integrasi):
	// 0-3: CharID (uint32)
	putUint32BE(buf, 0, uint32(char.ID))
	// 4: Slot
	buf[4] = byte(char.Slot)
	// 5-36: Name (32 byte, null-terminated string)
	nameBytes := []byte(char.Name)
	if len(nameBytes) > 31 {
		nameBytes = nameBytes[:31]
	}
	copy(buf[5:], nameBytes)
	// 37: Race
	buf[37] = char.Race
	// 38: Gender
	buf[38] = char.Gender
	// 39: Job
	buf[39] = byte(char.Job)
	// 40: Level
	buf[40] = byte(char.Level)
	// 41-44: HP (uint32)
	putUint32BE(buf, 41, uint32(char.HP))
	// 45-48: MaxHP (uint32)
	putUint32BE(buf, 45, uint32(char.MaxHP))
	// 49-52: SP (uint32)
	putUint32BE(buf, 49, uint32(char.SP))
	// 53-56: MaxSP (uint32)
	putUint32BE(buf, 53, uint32(char.MaxSP))
	// 57: Str, 58: Dex, 59: Int, 60: Vit, 61: Agi, 62: Mnd
	buf[57] = byte(char.Str)
	buf[58] = byte(char.Dex)
	buf[59] = byte(char.Int)
	buf[60] = byte(char.Vit)
	buf[61] = byte(char.Agi)
	buf[62] = byte(char.Mnd)
	// 63: Hair, 64: HairColor, 65-66: Face (uint16)
	buf[63] = byte(char.Appearance.Hair)
	buf[64] = byte(char.Appearance.HairColor)
	putUint16BE(buf, 65, uint16(char.Face))
	// 67: Form, 68: Wig
	buf[67] = char.Form
	buf[68] = char.Wig
	// 69-72: MapID (uint32)
	putUint32BE(buf, 69, uint32(char.MapID))
	// 73-76: X, 77-80: Y (uint32 each)
	putUint32BE(buf, 73, uint32(char.X))
	putUint32BE(buf, 77, uint32(char.Y))
	// 81: QuestRemaining
	buf[81] = byte(char.QuestRemaining)
	// 82-85: JobLevel1, 86-89: JobLevel2X, 90-93: JobLevel2T, 94-97: JobLevel3 (uint32 each)
	putUint32BE(buf, 82, uint32(char.JobLevel1))
	putUint32BE(buf, 86, uint32(char.JobLevel2X))
	putUint32BE(buf, 90, uint32(char.JobLevel2T))
	putUint32BE(buf, 94, uint32(char.JobLevel3))
	// 98: Rebirth (bool as byte)
	if char.Rebirth {
		buf[98] = 1
	}
	// Sisa byte: padding/reserved (nol)
	return buf
}

// BuildCharEquip membuat SSMG_CHAR_EQUIP packet (Saga11: 230 byte).
// Milestone: kirim kosong/nol (inventory belum diimplementasi).
func BuildCharEquip() []byte {
	buf := make([]byte, 230)
	// Marker 0x0E di offset 0, 57, 114, 171 (4 slot)
	buf[0] = 0x0E
	buf[57] = 0x0E
	buf[114] = 0x0E
	buf[171] = 0x0E
	// Sisa nol = no equipment
	return buf
}

// BuildCharCreateACK membuat SSMG_CHAR_CREATE_ACK packet.
// result: CHAR_CREATE_OK / CHAR_CREATE_NAME_CONFLICT / CHAR_CREATE_ALREADY_SLOT / CHAR_CREATE_NAME_BADCHAR
func BuildCharCreateACK(result uint32) []byte {
	buf := make([]byte, 4)
	putUint32BE(buf, 0, result)
	return buf
}

// BuildCharSelectACK membuat SSMG_CHAR_SELECT_ACK packet.
// mapID: ID map tempat karakter berada
func BuildCharSelectACK(mapID uint32) []byte {
	buf := make([]byte, 4)
	putUint32BE(buf, 0, mapID)
	return buf
}

// BuildSendToMapServer membuat SSMG_SEND_TO_MAP_SERVER packet.
// serverID: ID map server (byte)
// ip: IP map server (UTF-8, TANPA \0 terminator)
// port: port map server (int32 BE)
func BuildSendToMapServer(serverID byte, ip string, port int32) []byte {
	ipBytes := []byte(ip)
	ipLen := byte(len(ipBytes)) // TANPA +1 (no null terminator sesuai spec)
	// Layout: serverID(1) + ipLen(1) + ip(ipLen) + port(4)
	buf := make([]byte, 1+1+len(ipBytes)+4)
	buf[0] = serverID
	buf[1] = ipLen
	copy(buf[2:], ipBytes)
	// Port as int32 BE (signed)
	putUint32BE(buf, 2+len(ipBytes), uint32(port))
	return buf
}

// BuildPong membuat SSMG_PONG packet (response ke CSMG_PING, body kosong).
func BuildPong() []byte {
	return []byte{}
}
