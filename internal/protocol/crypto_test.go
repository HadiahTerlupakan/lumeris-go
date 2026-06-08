package protocol

import (
	"bytes"
	"math/big"
	"strings"
	"testing"
)

func TestKeyExchangeDefaultPriv(t *testing.T) {
	// privateKey default = 2, base = 2 => GetKeyExchangeBytes = 2^2 mod M = 4.
	c := NewCrypto()
	kx := c.GetKeyExchangeBytes()
	// 4 sebagai BigInteger.getBytes() (big-endian, minimal) = [0x04].
	if len(kx) == 0 || kx[len(kx)-1] != 0x04 {
		t.Errorf("key exchange terakhir = %v, mau diakhiri 0x04", kx)
	}
}

func TestMakeAESKeyNibbleReduction(t *testing.T) {
	// Susun aesKey langsung untuk menguji reduksi nibble (>9 -> -9).
	// 0xFA: nibble atas F(15)>9 ->6, bawah A(10)>9 ->1 => 0x61
	in := []byte{0xFA, 0x09, 0x90, 0x00}
	out := reduceNibbles(in)
	want := []byte{0x61, 0x09, 0x90, 0x00}
	if !bytes.Equal(out, want) {
		t.Errorf("reduceNibbles = %v, mau %v", out, want)
	}
}

func TestAESRoundTripFromOffset(t *testing.T) {
	c := NewCrypto()
	c.aesKey = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	// Data 4 byte header (tidak dienkripsi) + 32 byte payload.
	src := make([]byte, 36)
	for i := range src {
		src[i] = byte(i)
	}
	const off = 4

	enc := c.Encrypt(src, off)
	// 4 byte pertama tidak berubah (di bawah offset)
	for i := 0; i < off; i++ {
		if enc[i] != src[i] {
			t.Errorf("header byte %d berubah", i)
		}
	}
	dec := c.Decrypt(enc, off)
	if !bytes.Equal(dec, src) {
		t.Errorf("round-trip AES gagal:\n  src=%v\n  dec=%v", src, dec)
	}
}

func TestAESNoKeyIsPassthrough(t *testing.T) {
	c := NewCrypto() // aesKey nil
	src := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if got := c.Encrypt(src, 4); !bytes.Equal(got, src) {
		t.Errorf("tanpa kunci, Encrypt harus passthrough")
	}
}

func TestAESPartialTrailingBlock(t *testing.T) {
	// Sisa < 16 byte DIBIARKAN apa adanya (passthrough) — .NET TransformBlock
	// PaddingMode.None hanya proses blok penuh; round-trip tetap konsisten.
	c := NewCrypto()
	c.aesKey = []byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	src := make([]byte, 4+20) // payload 20 byte = 1 blok 16 + 1 blok 4
	for i := range src {
		src[i] = byte(i * 3)
	}
	enc := c.Encrypt(src, 4)
	// 4 byte sisa terakhir (di luar blok penuh) harus = plaintext asli (passthrough).
	if !bytes.Equal(enc[4+16:], src[4+16:]) {
		t.Errorf("blok parsial seharusnya passthrough: enc=%v src=%v", enc[4+16:], src[4+16:])
	}
	dec := c.Decrypt(enc, 4)
	if !bytes.Equal(dec, src) {
		t.Errorf("round-trip blok parsial gagal")
	}
}

func TestMakePrivateKeyProducesLargeDistinctKeys(t *testing.T) {
	c1 := NewCrypto()
	c1.MakePrivateKey()
	c2 := NewCrypto()
	c2.MakePrivateKey()

	// priv harus berubah dari default 2, dan acak (dua instance beda).
	if c1.privateKey.Cmp(big.NewInt(2)) == 0 {
		t.Errorf("privateKey masih 2 setelah MakePrivateKey")
	}
	if c1.privateKey.Cmp(c2.privateKey) == 0 {
		t.Errorf("dua MakePrivateKey menghasilkan priv identik (tidak acak)")
	}
	// pubkey sekarang harus 128 byte penuh (priv besar), bukan 1 byte.
	pub := c1.GetKeyExchangeBytes()
	if len(pub) < 100 {
		t.Errorf("pubkey hanya %d byte; priv tampak terlalu kecil", len(pub))
	}
}

// pubHex menghasilkan pubkey peer sebagai string hex uppercase (seperti wire).
func pubHex(c *Crypto) string {
	return strings.ToUpper(hexEncode(c.GetKeyExchangeBytes()))
}

func TestDHSharedKeyMatchesBothSides(t *testing.T) {
	// Dua pihak DH: server & client. Masing-masing priv acak.
	server := NewCrypto()
	server.MakePrivateKey()
	client := NewCrypto()
	client.MakePrivateKey()

	// Saling tukar pubkey (hex) lalu turunkan AES key.
	server.MakeAESKeyHex(pubHex(client))
	client.MakeAESKeyHex(pubHex(server))

	if !bytes.Equal(server.aesKey, client.aesKey) {
		t.Errorf("AES key kedua sisi beda:\n  server=%x\n  client=%x", server.aesKey, client.aesKey)
	}
	if len(server.aesKey) != 16 {
		t.Errorf("aesKey len = %d, mau 16", len(server.aesKey))
	}
	// nibble tereduksi: tiap nibble <= 9
	for i, b := range server.aesKey {
		if b>>4 > 9 || b&0x0F > 9 {
			t.Errorf("byte %d (%#x) punya nibble > 9", i, b)
		}
	}
}

func TestBuildServerHandshake529(t *testing.T) {
	c := NewCrypto()
	c.MakePrivateKey()

	blob := c.BuildServerHandshake()
	if len(blob) != 529 {
		t.Fatalf("blob = %d byte, mau 529", len(blob))
	}
	// [4..7] = BE 1
	if blob[4] != 0 || blob[5] != 0 || blob[6] != 0 || blob[7] != 1 {
		t.Errorf("byte 4-7 = %v, mau 00 00 00 01", blob[4:8])
	}
	// [8] = 0x32
	if blob[8] != 0x32 {
		t.Errorf("byte 8 = %#x, mau 0x32", blob[8])
	}
	// [9..12] = BE 0x100
	if blob[9] != 0 || blob[10] != 0 || blob[11] != 1 || blob[12] != 0 {
		t.Errorf("byte 9-12 = %v, mau 00 00 01 00", blob[9:13])
	}
	// [13..268] = modulus hex LOWERCASE (256 char). Cek prefix modulus.
	modHexLower := []byte("f488fd584e49dbcd")
	if !bytes.Equal(blob[13:13+len(modHexLower)], modHexLower) {
		t.Errorf("modulus hex (lowercase) salah: %s", blob[13:13+16])
	}
	// [269..272] = BE 0x100
	if blob[269] != 0 || blob[270] != 0 || blob[271] != 1 || blob[272] != 0 {
		t.Errorf("byte 269-272 = %v, mau 00 00 01 00", blob[269:273])
	}
	// [273..528] = pubkey hex UPPERCASE (256 char) — harus uppercase, panjang 256.
	pub := blob[273:529]
	if len(pub) != 256 {
		t.Errorf("pubkey hex len = %d, mau 256", len(pub))
	}
	for _, ch := range pub {
		if ch >= 'a' && ch <= 'f' {
			t.Errorf("pubkey hex mengandung huruf kecil (harus uppercase): %s", pub)
			break
		}
	}
}
