package mapserver

// Map Server Opcodes (Client → Server)
const (
	CSMG_SEND_VERSION = 0x000A
	CSMG_LOGIN        = 0x0010
	CSMG_PING         = 0x0032
	CSMG_CHAR_SLOT    = 0x01FD
)

// Map Server Opcodes (Server → Client)
// FIXED berdasarkan proxy capture NekogameECO:
// - 0x000B: VERSION_ACK
// - 0x000F: LOGIN_ALLOWED (bukan 0x0011!)
// - 0x0011: LOGIN_ACK (bukan 0x0012!)
const (
	SSMG_VERSION_ACK    = 0x000B
	SSMG_LOGIN_ALLOWED  = 0x000F // FIXED dari capture
	SSMG_LOGIN_ACK      = 0x0011 // FIXED dari capture
	SSMG_PONG           = 0x0033
	SSMG_LOGIN_FINISHED = 0x0013
)

// Login result codes (sama dengan Login server)
const (
	LOGIN_OK          = 0
	LOGIN_UNKNOWN_ACC = 1
	LOGIN_BADPASS     = 2
	LOGIN_BFALOCK     = 5
)
