package protocol

import (
	"bytes"
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
	// Sisa < 16 byte: C# tetap men-transform blok pendek apa adanya.
	c := NewCrypto()
	c.aesKey = []byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	src := make([]byte, 4+20) // payload 20 byte = 1 blok 16 + 1 blok 4
	for i := range src {
		src[i] = byte(i * 3)
	}
	dec := c.Decrypt(c.Encrypt(src, 4), 4)
	if !bytes.Equal(dec, src) {
		t.Errorf("round-trip blok parsial gagal")
	}
}
