package protocol

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
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

// MakePrivateKey mengacak privateKey menjadi bilangan besar (~320-bit) agar
// pubkey (base^priv mod M) berukuran penuh, seperti Encryption.MakePrivateKey di C#.
// Nilai persis priv tidak perlu cocok dengan C#: tiap sisi DH punya priv sendiri,
// hanya AES key turunan (simetris) yang harus sama.
func (c *Crypto) MakePrivateKey() {
	buf := make([]byte, 40)
	if _, err := rand.Read(buf); err != nil {
		// fallback deterministik sangat tak mungkin terpakai; tetap > 2.
		buf[0] = 0x6F
	}
	c.privateKey = new(big.Int).SetBytes(buf)
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

// hexEncode = byte -> string hex (huruf kecil), padanan Conversions.bytes2HexString
// tetapi lowercase; pemanggil yang butuh uppercase memakai strings.ToUpper.
func hexEncode(b []byte) string {
	return hex.EncodeToString(b)
}

// MakeAESKeyHex menurunkan kunci AES dari pubkey peer dalam bentuk STRING HEX
// (256 char), persis seperti C# MakeAESKey(string): A = parse-hex(s); R = A^priv mod M;
// ambil 16 byte pertama; reduksi nibble (>9 -> -9).
func (c *Crypto) MakeAESKeyHex(peerPubHex string) {
	a, ok := new(big.Int).SetString(peerPubHex, 16)
	if !ok {
		c.aesKey = nil
		return
	}
	r := new(big.Int).Exp(a, c.privateKey, c.modulus).Bytes()
	key := make([]byte, 16)
	copy(key, r)
	c.aesKey = reduceNibbles(key)
}

// cloneBytes mengembalikan salinan baru dari b agar pemanggil selalu menerima
// buffer independen (tidak pernah meng-alias slice input).
func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// Encrypt mengenkripsi src mulai dari offset memakai AES-128-ECB tanpa padding,
// blok-per-blok 16 byte; sisa < 16 byte ditransform apa adanya (replika C#).
func (c *Crypto) Encrypt(src []byte, offset int) []byte {
	if c.aesKey == nil || offset >= len(src) {
		return cloneBytes(src)
	}
	block, err := aes.NewCipher(c.aesKey)
	if err != nil {
		return cloneBytes(src)
	}
	out := make([]byte, len(src))
	copy(out, src)
	transformECB(block.Encrypt, src, out, offset)
	return out
}

// Decrypt kebalikan dari Encrypt.
func (c *Crypto) Decrypt(src []byte, offset int) []byte {
	if c.aesKey == nil || offset >= len(src) {
		return cloneBytes(src)
	}
	block, err := aes.NewCipher(c.aesKey)
	if err != nil {
		return cloneBytes(src)
	}
	out := make([]byte, len(src))
	copy(out, src)
	transformECB(block.Decrypt, src, out, offset)
	return out
}

// transformECB menjalankan fn (Encrypt/Decrypt blok 16-byte) atas src[offset:],
// menyalin hasil ke out[offset:]. Hanya blok PENUH 16 byte yang ditransform.
// Sisa < 16 byte dibiarkan apa adanya (passthrough), meniru .NET ICryptoTransform
// PaddingMode.None yang tidak menulis blok tak-lengkap ke output — sehingga byte
// sisa tetap sama dengan src (yang sudah disalin ke out). Ini yang membuat
// round-trip C# bekerja: blok parsial tak pernah ditransform di arah mana pun.
func transformECB(fn func(dst, src []byte), src, out []byte, offset int) {
	for i := offset; i+16 <= len(src); i += 16 {
		fn(out[i:i+16], src[i:i+16])
	}
}
