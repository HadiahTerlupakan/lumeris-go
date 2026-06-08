package login

import (
	"fmt"
)

// ParsedVersion adalah hasil parse CSMG_SEND_VERSION.
type ParsedVersion struct {
	VersionBytes [6]byte // Raw 6 byte version dari klien
}

// ParseSendVersion mem-parse CSMG_SEND_VERSION packet.
// Layout: 6 version bytes@offset 2 (offset 0-1 diabaikan)
func ParseSendVersion(data []byte) (*ParsedVersion, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("SEND_VERSION terlalu pendek: %d bytes", len(data))
	}
	v := &ParsedVersion{}
	copy(v.VersionBytes[:], data[2:8])
	return v, nil
}

// ParsedLogin adalah hasil parse CSMG_LOGIN packet.
type ParsedLogin struct {
	Username string
	Password []byte // 20 byte SHA1 hash (atau plaintext di Validation fase - tergantung)
	MAC      []byte // 6 byte MAC address
}

// ParseLogin mem-parse CSMG_LOGIN packet.
// Layout (byte-exact, ASIMETRI off++ WAJIB):
// off=0: uLen(byte), user(ASCII uLen-1), off+=uLen
// THEN off++ (gap 1 byte)
// pLen(byte), pass(20 byte SHA1), off+=pLen
// MAC: ushort@off + uint@(off+2) = 6 byte
func ParseLogin(data []byte) (*ParsedLogin, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("LOGIN terlalu pendek: %d bytes", len(data))
	}
	offset := 0
	// Username
	uLen := int(data[offset])
	offset++
	if offset+uLen > len(data) {
		return nil, fmt.Errorf("LOGIN username overflow")
	}
	username := string(data[offset : offset+uLen-1]) // -1: exclude null terminator
	offset += uLen

	// ASIMETRI: off++ sebelum pLen
	offset++

	// Password
	if offset >= len(data) {
		return nil, fmt.Errorf("LOGIN password missing")
	}
	pLen := int(data[offset])
	offset++
	if offset+pLen > len(data) {
		return nil, fmt.Errorf("LOGIN password overflow")
	}
	password := make([]byte, pLen-1) // -1: exclude null terminator (tapi password SHA1 = raw 20 byte, no null)
	copy(password, data[offset:offset+pLen-1])
	offset += pLen

	// MAC (6 byte: ushort + uint)
	if offset+6 > len(data) {
		return nil, fmt.Errorf("LOGIN MAC missing")
	}
	mac := make([]byte, 6)
	// MAC layout: [ushort BE@offset][uint BE@offset+2]
	copy(mac[0:2], data[offset:offset+2])
	copy(mac[2:6], data[offset+2:offset+6])

	return &ParsedLogin{
		Username: username,
		Password: password,
		MAC:      mac,
	}, nil
}

// ParsedCharStatus adalah hasil parse CSMG_CHAR_STATUS.
type ParsedCharStatus struct {
	Slot byte
}

// ParseCharStatus mem-parse CSMG_CHAR_STATUS packet.
// Layout: Slot byte@offset 0
func ParseCharStatus(data []byte) (*ParsedCharStatus, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("CHAR_STATUS terlalu pendek")
	}
	return &ParsedCharStatus{Slot: data[0]}, nil
}

// ParsedCharCreate adalah hasil parse CSMG_CHAR_CREATE.
type ParsedCharCreate struct {
	Slot      byte
	Name      string
	Race      byte
	Gender    byte
	HairStyle byte
	HairColor byte
	Face      uint16
}

// ParseCharCreate mem-parse CSMG_CHAR_CREATE packet (Saga11).
// Layout: Slot@0; nameLen@1; name@2..; D=2+nameLen;
// Saga11: Race@D, Gender@D+1, (gap@D+2), HairStyle@D+3, HairColor@D+4, Face(uint16)@D+5
func ParseCharCreate(data []byte) (*ParsedCharCreate, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("CHAR_CREATE terlalu pendek")
	}
	slot := data[0]
	nameLen := int(data[1])
	if 2+nameLen > len(data) {
		return nil, fmt.Errorf("CHAR_CREATE name overflow")
	}
	name := string(data[2 : 2+nameLen-1]) // -1: exclude null terminator
	D := 2 + nameLen
	if D+7 > len(data) { // Race, Gender, gap, Hair, HairColor, Face(2)
		return nil, fmt.Errorf("CHAR_CREATE appearance data kurang")
	}
	return &ParsedCharCreate{
		Slot:      slot,
		Name:      name,
		Race:      data[D],
		Gender:    data[D+1],
		// gap@D+2 diabaikan
		HairStyle: data[D+3],
		HairColor: data[D+4],
		Face:      getUint16BE(data, D+5),
	}, nil
}

// ParsedCharDelete adalah hasil parse CSMG_CHAR_DELETE.
type ParsedCharDelete struct {
	Slot           byte
	DeletePassword string
}

// ParseCharDelete mem-parse CSMG_CHAR_DELETE packet.
// Layout: Slot@0; pwLen@1; deletePassword(ASCII pwLen-1)@2
func ParseCharDelete(data []byte) (*ParsedCharDelete, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("CHAR_DELETE terlalu pendek")
	}
	slot := data[0]
	pwLen := int(data[1])
	if 2+pwLen > len(data) {
		return nil, fmt.Errorf("CHAR_DELETE password overflow")
	}
	deletePass := string(data[2 : 2+pwLen-1]) // -1: exclude null
	return &ParsedCharDelete{
		Slot:           slot,
		DeletePassword: deletePass,
	}, nil
}

// ParsedCharSelect adalah hasil parse CSMG_CHAR_SELECT.
type ParsedCharSelect struct {
	Slot byte
}

// ParseCharSelect mem-parse CSMG_CHAR_SELECT packet.
// Layout: Slot byte@offset 0
func ParseCharSelect(data []byte) (*ParsedCharSelect, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("CHAR_SELECT terlalu pendek")
	}
	return &ParsedCharSelect{Slot: data[0]}, nil
}

// ParsedRequestMapServer adalah hasil parse CSMG_REQUEST_MAP_SERVER.
type ParsedRequestMapServer struct {
	Slot uint32 // Praktis tak dipakai; handler pakai selectedChar dari context
}

// ParseRequestMapServer mem-parse CSMG_REQUEST_MAP_SERVER packet.
// Layout: Slot uint32@offset 0
func ParseRequestMapServer(data []byte) (*ParsedRequestMapServer, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("REQUEST_MAP_SERVER terlalu pendek")
	}
	return &ParsedRequestMapServer{Slot: getUint32BE(data, 0)}, nil
}
