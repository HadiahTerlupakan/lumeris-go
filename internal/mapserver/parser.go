package mapserver

import (
	"encoding/binary"
	"fmt"
)

// ParsedSendVersion adalah hasil parse CSMG_SEND_VERSION.
type ParsedSendVersion struct {
	Version      string
	VersionBytes [6]byte
}

// ParseSendVersion mem-parse CSMG_SEND_VERSION.
// DecodeFrame sudah melepas 2-byte opcode ID, jadi `data` adalah payload murni
// dengan layout identik login.ParseSendVersion: 6 version bytes di offset 2.
func ParseSendVersion(data []byte) (*ParsedSendVersion, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("CSMG_SEND_VERSION terlalu pendek: %d bytes", len(data))
	}

	result := &ParsedSendVersion{}
	copy(result.VersionBytes[:], data[2:8])
	result.Version = fmt.Sprintf("%02X%02X%02X%02X%02X%02X",
		result.VersionBytes[0], result.VersionBytes[1],
		result.VersionBytes[2], result.VersionBytes[3],
		result.VersionBytes[4], result.VersionBytes[5])

	return result, nil
}

// ParsedLogin adalah hasil parse CSMG_LOGIN.
type ParsedLogin struct {
	Username   string
	Password   [20]byte
	MacAddress string
}

// ParseLogin mem-parse CSMG_LOGIN dengan layout identik login.ParseLogin.
// Password dikirim klien sebagai hex-string ASCII (40 char SHA1), bukan 20 raw bytes.
func ParseLogin(data []byte) (*ParsedLogin, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("CSMG_LOGIN terlalu pendek: %d bytes", len(data))
	}

	offset := 0
	result := &ParsedLogin{}

	nameLen := int(data[offset])
	offset++
	if offset+nameLen > len(data) {
		return nil, fmt.Errorf("username length overflow")
	}
	result.Username = string(data[offset : offset+nameLen-1])
	offset += nameLen

	if offset >= len(data) {
		return nil, fmt.Errorf("password missing")
	}
	passLen := int(data[offset])
	offset++
	if offset+passLen > len(data) {
		return nil, fmt.Errorf("password length overflow")
	}
	passwordHex := string(data[offset : offset+passLen-1])
	for i := 0; i+1 < len(passwordHex) && i/2 < len(result.Password); i += 2 {
		fmt.Sscanf(passwordHex[i:i+2], "%02x", &result.Password[i/2])
	}
	offset += passLen

	if offset+6 <= len(data) {
		a := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		b := binary.BigEndian.Uint32(data[offset : offset+4])
		result.MacAddress = fmt.Sprintf("%04x%08x", a, b)
	}

	return result, nil
}

// ParsedCharSlot adalah hasil parse CSMG_CHAR_SLOT.
type ParsedCharSlot struct {
	Slot uint8
}

// ParseCharSlot mem-parse CSMG_CHAR_SLOT: 1 byte slot di offset 0.
func ParseCharSlot(data []byte) (*ParsedCharSlot, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("CSMG_CHAR_SLOT terlalu pendek")
	}

	return &ParsedCharSlot{
		Slot: data[0],
	}, nil
}
