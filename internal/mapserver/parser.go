package mapserver

import (
	"encoding/binary"
	"fmt"
)

// ParsedSendVersion adalah hasil parse CSMG_SEND_VERSION.
type ParsedSendVersion struct {
	Version      string
	VersionBytes [4]byte
}

// ParseSendVersion mem-parse CSMG_SEND_VERSION (offset 2, size 10).
// C#: GetBytes(6, 4) → offset 6, 4 bytes
func ParseSendVersion(data []byte) (*ParsedSendVersion, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("CSMG_SEND_VERSION terlalu pendek: %d bytes", len(data))
	}

	result := &ParsedSendVersion{}
	// Version bytes at offset 6 (4 bytes)
	copy(result.VersionBytes[:], data[6:10])
	result.Version = fmt.Sprintf("%02X%02X%02X%02X",
		result.VersionBytes[0], result.VersionBytes[1],
		result.VersionBytes[2], result.VersionBytes[3])

	return result, nil
}

// ParsedLogin adalah hasil parse CSMG_LOGIN.
type ParsedLogin struct {
	Username   string
	Password   [20]byte
	MacAddress string
}

// ParseLogin mem-parse CSMG_LOGIN (offset 8, size 55).
// C# CSMG_LOGIN.cs line 28-44:
// - offset 2: username length (1 byte)
// - offset 3: username (ASCII)
// - next: password length (1 byte)
// - next: password (20 bytes SHA1)
// - next: MAC address (ushort + uint = 6 bytes)
func ParseLogin(data []byte) (*ParsedLogin, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("CSMG_LOGIN terlalu pendek")
	}

	offset := 2
	result := &ParsedLogin{}

	// Username length
	nameLen := int(data[offset])
	offset++
	if offset+nameLen > len(data) {
		return nil, fmt.Errorf("username length overflow")
	}
	result.Username = string(data[offset : offset+nameLen-1]) // -1 untuk \0
	offset += nameLen

	// Password length
	passLen := int(data[offset])
	offset++
	if offset+passLen > len(data) {
		return nil, fmt.Errorf("password length overflow")
	}
	copy(result.Password[:], data[offset:offset+passLen-1]) // -1 untuk \0
	offset += passLen

	// MAC address (2 bytes ushort + 4 bytes uint)
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

// ParseCharSlot mem-parse CSMG_CHAR_SLOT.
// Minimal packet: 1 byte slot number at offset 2
func ParseCharSlot(data []byte) (*ParsedCharSlot, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("CSMG_CHAR_SLOT terlalu pendek")
	}

	return &ParsedCharSlot{
		Slot: data[2],
	}, nil
}
