// Package login mengimplementasikan login flow ECO: Validation & Login server.
package login

import (
	"encoding/binary"
)

// Packet opcodes (sesuai Plan 4 spec)
const (
	// Inbound (C->S)
	CSMG_SEND_VERSION       = 0x0001
	CSMG_PING               = 0x000A
	CSMG_LOGIN              = 0x001F
	CSMG_SERVERLET_ASK      = 0x0031
	CSMG_REQUEST_MAP_SERVER = 0x0032
	CSMG_CHAR_STATUS        = 0x002A
	CSMG_CHAR_CREATE        = 0x00A0
	CSMG_CHAR_DELETE        = 0x00A5
	CSMG_CHAR_SELECT        = 0x00A7

	// Outbound (S->C)
	SSMG_VERSION_ACK        = 0x0002
	SSMG_PONG               = 0x000B
	SSMG_CHAR_STATUS_ACK    = 0x002B
	SSMG_LOGIN_ALLOWED      = 0x001E
	SSMG_LOGIN_ACK          = 0x0020
	SSMG_CHAR_DATA          = 0x0028
	SSMG_CHAR_EQUIP         = 0x0029
	SSMG_SERVER_LST_START   = 0x0032
	SSMG_SERVER_LST_SEND    = 0x0033
	SSMG_SERVER_LST_END     = 0x0034
	SSMG_CHAR_CREATE_ACK    = 0x00A1
	SSMG_CHAR_SELECT_ACK    = 0x00A8
	SSMG_SEND_TO_MAP_SERVER = 0x0033 // Sama dengan SERVER_LST_SEND, beda fase
	SSMG_REQUEST_NYA        = 0x0150
)

// Login result codes (uint32, two's complement)
const (
	LOGIN_OK          = 0x00000000
	LOGIN_UNKNOWN_ACC = 0xFFFFFFFE // -2
	LOGIN_BADPASS     = 0xFFFFFFFD // -3
	LOGIN_BFALOCK     = 0xFFFFFFFC // -4 (banned)
	LOGIN_ALREADY     = 0xFFFFFFFB // -5
	LOGIN_IPBLOCK     = 0xFFFFFFFA // -6
)

// Char create result codes
const (
	CHAR_CREATE_OK           = 0x00000000
	CHAR_CREATE_NAME_CONFLICT = 0xFFFFFF9E
	CHAR_CREATE_ALREADY_SLOT  = 0xFFFFFF9D
	CHAR_CREATE_NAME_BADCHAR  = 0xFFFFFFA0
)

// putUint32BE menulis uint32 big-endian ke offset.
func putUint32BE(buf []byte, offset int, val uint32) {
	binary.BigEndian.PutUint32(buf[offset:offset+4], val)
}

// putUint16BE menulis uint16 big-endian ke offset.
func putUint16BE(buf []byte, offset int, val uint16) {
	binary.BigEndian.PutUint16(buf[offset:offset+2], val)
}

// getUint32BE membaca uint32 big-endian dari offset.
func getUint32BE(buf []byte, offset int) uint32 {
	return binary.BigEndian.Uint32(buf[offset : offset+4])
}

// getUint16BE membaca uint16 big-endian dari offset.
func getUint16BE(buf []byte, offset int) uint16 {
	return binary.BigEndian.Uint16(buf[offset : offset+2])
}
