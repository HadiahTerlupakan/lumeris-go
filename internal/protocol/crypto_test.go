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
	c := NewCrypto()
	_ = c
	// Susun aesKey langsung untuk menguji reduksi nibble (>9 -> -9).
	// 0xFA: nibble atas F(15)>9 ->6, bawah A(10)>9 ->1 => 0x61
	in := []byte{0xFA, 0x09, 0x90, 0x00}
	out := reduceNibbles(in)
	want := []byte{0x61, 0x09, 0x90, 0x00}
	if !bytes.Equal(out, want) {
		t.Errorf("reduceNibbles = %v, mau %v", out, want)
	}
}
