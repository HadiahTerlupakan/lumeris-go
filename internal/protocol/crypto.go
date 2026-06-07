package protocol

import (
	"math/big"
)

// modulusHex adalah modulus DH 128-byte (replika persis Encryption.Module di C#).
const modulusHex = "f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6" +
	"f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212c" +
	"b52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fab" +
	"d00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e92f78c7"

// Crypto memegang state kripto satu koneksi: kunci DH + kunci AES.
type Crypto struct {
	modulus    *big.Int
	base       *big.Int
	privateKey *big.Int
	aesKey     []byte // 16 byte saat siap, nil sebelum handshake
}

// NewCrypto membuat state dengan base=2 dan privateKey default=2 (seperti C#).
func NewCrypto() *Crypto {
	m, _ := new(big.Int).SetString(modulusHex, 16)
	return &Crypto{
		modulus:    m,
		base:       big.NewInt(2),
		privateKey: big.NewInt(2),
	}
}

// GetKeyExchangeBytes = base^privateKey mod modulus, big-endian (seperti getBytes()).
func (c *Crypto) GetKeyExchangeBytes() []byte {
	r := new(big.Int).Exp(c.base, c.privateKey, c.modulus)
	return r.Bytes()
}

// reduceNibbles: untuk tiap byte, jika nibble atas/bawah > 9 maka dikurangi 9.
func reduceNibbles(in []byte) []byte {
	out := make([]byte, len(in))
	for i, b := range in {
		hi := b >> 4
		lo := b & 0x0F
		if hi > 9 {
			hi -= 9
		}
		if lo > 9 {
			lo -= 9
		}
		out[i] = (hi << 4) | lo
	}
	return out
}

// MakeAESKey menghitung kunci AES dari blob key-exchange milik lawan bicara.
// R = A^privateKey mod modulus; ambil 16 byte pertama; reduksi nibble.
func (c *Crypto) MakeAESKey(peerKeyExchange []byte) {
	a := new(big.Int).SetBytes(peerKeyExchange)
	r := new(big.Int).Exp(a, c.privateKey, c.modulus).Bytes()
	key := make([]byte, 16)
	copy(key, r) // 16 byte pertama (big.Int.Bytes big-endian)
	c.aesKey = reduceNibbles(key)
}

// IsReady true bila kunci AES sudah dibuat.
func (c *Crypto) IsReady() bool { return c.aesKey != nil }
