package session

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"

	"lumeris-go/internal/protocol"
)

const (
	helloLen      = 8   // byte pembuka dari klien (isi diabaikan)
	serverBlobLen = 529 // blob handshake server (modulus + pubkey)
	replyLen      = 260 // balasan klien: [0:4]=BE 0x100, [4:260]=256 hex pubkey
)

// serverHandshake menjalankan sisi-server handshake DH (NetIO.cs:240-279):
// baca 8 byte → MakePrivateKey + kirim blob 529 (raw) → baca 260 → MakeAESKeyHex.
func serverHandshake(conn net.Conn, c *protocol.Crypto) error {
	hello := make([]byte, helloLen)
	if _, err := io.ReadFull(conn, hello); err != nil {
		return err
	}
	c.MakePrivateKey()
	blob := c.BuildServerHandshake()
	if _, err := conn.Write(blob); err != nil {
		return err
	}
	reply := make([]byte, replyLen)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	// Verifikasi reply prefix
	prefix := binary.BigEndian.Uint32(reply[0:4])
	if prefix != 0x100 {
		return errors.New("serverHandshake: reply prefix bukan 0x100")
	}
	c.MakeAESKeyHex(string(reply[4:replyLen])) // reply[4:260] = 256 char hex pubkey klien
	if !c.IsReady() {
		return errors.New("serverHandshake: AES key gagal dibuat")
	}
	return nil
}

// ClientHandshake menjalankan sisi-klien handshake DH (NetIO.cs:281-294):
// kirim 8 byte → baca blob 529 → kirim 260 (pubkey sendiri, hex uppercase) →
// turunkan AES key dari pubkey server (hex di [273:529] blob).
func ClientHandshake(conn net.Conn) (*protocol.Crypto, error) {
	if _, err := conn.Write(make([]byte, helloLen)); err != nil {
		return nil, err
	}
	blob := make([]byte, serverBlobLen)
	if _, err := io.ReadFull(conn, blob); err != nil {
		return nil, err
	}
	serverPubHex := string(blob[273:serverBlobLen]) // pubkey server (uppercase, 256 char)

	c := protocol.NewCrypto()
	c.MakePrivateKey()

	reply := make([]byte, replyLen)
	binary.BigEndian.PutUint32(reply[0:], 0x100)
	pubHex := padHexLeft256(strings.ToUpper(hex.EncodeToString(c.GetKeyExchangeBytes())))
	copy(reply[4:], []byte(pubHex))
	if _, err := conn.Write(reply); err != nil {
		return nil, err
	}

	c.MakeAESKeyHex(serverPubHex)
	if !c.IsReady() {
		return nil, errors.New("ClientHandshake: AES key gagal dibuat")
	}
	return c, nil
}

// padHexLeft256 memastikan string hex tepat 256 char (128 byte pubkey) dengan
// menambah '0' di kiri bila leading-zero hilang dari big.Int.Bytes().
func padHexLeft256(s string) string {
	if len(s) >= 256 {
		return s[len(s)-256:]
	}
	return strings.Repeat("0", 256-len(s)) + s
}
