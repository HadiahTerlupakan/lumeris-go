package mapserver

import "encoding/binary"

// putUint32BE menulis uint32 big-endian ke buffer di offset.
func putUint32BE(buf []byte, offset int, val uint32) {
	binary.BigEndian.PutUint32(buf[offset:], val)
}

// BuildVersionACK membuat SSMG_VERSION_ACK packet.
// C# SSMG_VERSION_ACK: result (4 bytes) + version (4 bytes)
func BuildVersionACK(result uint32, version []byte) []byte {
	buf := make([]byte, 8)
	putUint32BE(buf, 0, result) // Result: 0 = OK
	copy(buf[4:8], version)     // Version echo
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
// C# MapClient.Login.cs line 103-106:
// - LoginResult (4 bytes)
// - Unknown1 (4 bytes) = 0x100
// - TimeStamp (4 bytes) = Unix timestamp
func BuildLoginACK(result, unknown1, timestamp uint32) []byte {
	buf := make([]byte, 12)
	putUint32BE(buf, 0, result)
	putUint32BE(buf, 4, unknown1)
	putUint32BE(buf, 8, timestamp)
	return buf
}

// BuildPong membuat SSMG_PONG packet (body kosong).
func BuildPong() []byte {
	return []byte{}
}
