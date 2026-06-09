package login

import (
	"lumeris-go/internal/model"
)

// BuildVersionACK membuat SSMG_VERSION_ACK packet.
// result: 0 = OK, 0xFFFF = version mismatch
// versionBytes: 6 byte version info dari klien (echo back)
// Layout byte-exact: result uint16@0-1, version 6 bytes@2-7 (total 8 bytes body)
func BuildVersionACK(result uint16, versionBytes []byte) []byte {
	buf := make([]byte, 8)
	// Offset 0-1: result
	putUint16BE(buf, 0, result)
	// Offset 2-7: version bytes (6 byte)
	if len(versionBytes) >= 6 {
		copy(buf[2:8], versionBytes[:6])
	}
	return buf
}

// BuildLoginAllowed membuat SSMG_LOGIN_ALLOWED packet dengan front/back challenge words.
// PENTING: Client membaca dari offset 0 dan 4 (BUKAN 2 dan 6 seperti C# server!)
// C# server kirim dengan padding, tapi client ignore padding dan baca dari awal.
func BuildLoginAllowed(front, back uint32) []byte {
	buf := make([]byte, 8)
	// Offset 0: FrontWord
	putUint32BE(buf, 0, front)
	// Offset 4: BackWord
	putUint32BE(buf, 4, back)
	return buf
}

// BuildLoginACK membuat body SSMG_LOGIN_ACK.
// Capture klien asli (proxy_packets.log baris 6) menunjukkan paket 19 byte:
//
//	00 20 | 00 00 00 00 | 00 00 60 F4 | 00 00 00 00 | 00 00 00 00 | 00
//	 ID     result(4)     accountID(4)  RestTest(4)   TestEnd(4)    +1 byte
//
// ID 2 byte ditambah EncodeFrame, jadi body = 17 byte (BUKAN 16). Byte ke-17
// (trailing) WAJIB ada; tanpa byte itu klien gagal parse struktur fixed-size
// LOGIN_ACK dan berhenti tepat setelah login (tidak lanjut ke 0x002F).
func BuildLoginACK(result, accountID uint32) []byte {
	buf := make([]byte, 17)
	putUint32BE(buf, 0, result)
	putUint32BE(buf, 4, accountID)
	// Offset 8: RestTestTime (default 0)
	// Offset 12: TestEndTime (default 0)
	// Offset 16: trailing byte (default 0) — sesuai capture
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

// BuildServerListSend membuat body SSMG_SERVER_LST_SEND.
// C# SSMG_SERVER_LST_SEND.cs menulis nameLen di data[2] karena data[0-1] adalah ID
// paket. EncodeFrame Go sudah menambahkan ID sebagai field terpisah, jadi body di sini
// TIDAK menyertakan ID maupun padding — langsung mulai dari nameLen:
//
//	[nameLen 1][name + \0][ipLen 1][ip + \0]
//
// nameLen & ipLen termasuk byte \0 (C#: buf = Unicode.GetBytes(value+"\0"); PutByte(buf.Length)).
func BuildServerListSend(name, ip string) []byte {
	nameBytes := append([]byte(name), 0) // name + \0
	ipBytes := append([]byte(ip), 0)      // ip + \0

	buf := make([]byte, 0, 1+len(nameBytes)+1+len(ipBytes))
	buf = append(buf, byte(len(nameBytes)))
	buf = append(buf, nameBytes...)
	buf = append(buf, byte(len(ipBytes)))
	buf = append(buf, ipBytes...)
	return buf
}

// BuildServerListEnd membuat SSMG_SERVER_LST_END packet (body kosong).
func BuildServerListEnd() []byte {
	return []byte{}
}

// BuildCharData membuat SSMG_CHAR_DATA packet (Saga18, format array-4-slot).
// Diverifikasi byte-exact dari capture klien asli (proxy_packets.log, body 147 byte).
//
// Struktur: [nameMarker 4][4× nama len-prefixed (TANPA \0)] lalu tiap field adalah
// blok [marker 4][4 slot × ukuran]. Urutan & ukuran field (per slot):
//
//	Race1 Form1 Gender1 HairStyle2 HairColor1 Wig2 Exist1 Face2 Rebirth1
//	Tail1 Wing1 WingColor1 Job1 Map4 Lv1 Job1_1 Quest2 Job2X1 Job2T1 Job3_1
//
// chars dipetakan ke slot 0..3 lewat field Slot; slot kosong = nilai nol, Exist=0.
func BuildCharData(chars []*model.Character) []byte {
	// Index karakter per-slot (0..3).
	bySlot := [4]*model.Character{}
	for _, c := range chars {
		if c.Slot >= 0 && c.Slot < 4 {
			bySlot[c.Slot] = c
		}
	}

	buf := make([]byte, 0, 147)

	// Nama: marker 0x04, lalu 4 nama len-prefixed (UTF-8, tanpa null terminator).
	buf = append(buf, 0x04)
	for i := 0; i < 4; i++ {
		if c := bySlot[i]; c != nil {
			nb := []byte(c.Name)
			if len(nb) > 255 {
				nb = nb[:255]
			}
			buf = append(buf, byte(len(nb)))
			buf = append(buf, nb...)
		} else {
			buf = append(buf, 0x00) // slot kosong: panjang 0
		}
	}

	// Helper: tulis satu blok field [marker 0x04][4 slot × sz], pakai writer per-slot.
	block := func(sz int, write func(c *model.Character, dst []byte)) {
		buf = append(buf, 0x04)
		for i := 0; i < 4; i++ {
			slot := make([]byte, sz)
			if c := bySlot[i]; c != nil {
				write(c, slot)
			}
			buf = append(buf, slot...)
		}
	}

	// Race (1)
	block(1, func(c *model.Character, dst []byte) { dst[0] = c.Race })
	// Form (1)
	block(1, func(c *model.Character, dst []byte) { dst[0] = c.Form })
	// Gender (1)
	block(1, func(c *model.Character, dst []byte) { dst[0] = c.Gender })
	// HairStyle (2 BE)
	block(2, func(c *model.Character, dst []byte) { putUint16BE(dst, 0, uint16(c.Appearance.Hair)) })
	// HairColor (1)
	block(1, func(c *model.Character, dst []byte) { dst[0] = byte(c.Appearance.HairColor) })
	// Wig (2 BE) — 0xFFFF = tanpa wig
	block(2, func(c *model.Character, dst []byte) { putUint16BE(dst, 0, uint16(c.Wig)) })
	// Exist (1) — 0xFF jika ada
	block(1, func(c *model.Character, dst []byte) { dst[0] = 0xFF })
	// Face (2 BE)
	block(2, func(c *model.Character, dst []byte) { putUint16BE(dst, 0, uint16(c.Face)) })
	// Rebirth (1) — 0x64 jika rebirth, else 0
	block(1, func(c *model.Character, dst []byte) {
		if c.Rebirth {
			dst[0] = 0x64
		}
	})
	// Tail (1)
	block(1, func(c *model.Character, dst []byte) {})
	// Wing (1)
	block(1, func(c *model.Character, dst []byte) {})
	// WingColor (1)
	block(1, func(c *model.Character, dst []byte) {})
	// Job (1)
	block(1, func(c *model.Character, dst []byte) { dst[0] = byte(c.Job) })
	// Map (4 BE)
	block(4, func(c *model.Character, dst []byte) { putUint32BE(dst, 0, uint32(c.MapID)) })
	// Lv (1)
	block(1, func(c *model.Character, dst []byte) { dst[0] = byte(c.Level) })
	// Job1 (1)
	block(1, func(c *model.Character, dst []byte) { dst[0] = byte(c.JobLevel1) })
	// Quest (2 BE)
	block(2, func(c *model.Character, dst []byte) { putUint16BE(dst, 0, uint16(c.QuestRemaining)) })
	// Job2X (1)
	block(1, func(c *model.Character, dst []byte) { dst[0] = byte(c.JobLevel2X) })
	// Job2T (1)
	block(1, func(c *model.Character, dst []byte) { dst[0] = byte(c.JobLevel2T) })
	// Job3 (1)
	block(1, func(c *model.Character, dst []byte) { dst[0] = byte(c.JobLevel3) })

	return buf
}

// BuildCharEquip membuat SSMG_CHAR_EQUIP packet (Saga18, 212-byte body).
// Diverifikasi dari capture: 4 slot × [marker 0x0D=13][13 × uint32 BE] = 4×53 = 212.
// Milestone: equipment kosong (semua uint32 nol), marker tetap dipasang.
func BuildCharEquip() []byte {
	const slotSize = 1 + 13*4 // marker + 13 uint32 = 53
	buf := make([]byte, 4*slotSize)
	for i := 0; i < 4; i++ {
		buf[i*slotSize] = 0x0D // marker = jumlah slot equip (13)
	}
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
