package protocol

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex tidak valid: %v", err)
	}
	return b
}

// Vektor nyata dari capture TomatoProxyTool (sesi login ke server ECO eksternal).
// Direkam via gate LUMERIS_CRYPTO_VECTOR=1 di SagaLib/NetIO.cs (sudah di-revert).
// Membuktikan Decrypt Go == hasil Decrypt C# SagaLib.Encryption, byte-for-byte.
// Enkripsi mulai offset 8 (4 byte SIZE + 4 byte length, lalu ID+DATA terenkripsi).
func TestDecryptMatchesCapture(t *testing.T) {
	aesKey := mustHex(t, "52134543831675282125043111356329")
	wire := mustHex(t, "000000000000000C45F97A44099A1DAB0003E80773FDB177")
	want := mustHex(t, "000000000000000C000A0001000003E8015F377100000000")
	const offset = 8

	c := NewCrypto()
	c.aesKey = aesKey
	got := c.Decrypt(wire, offset)

	if !bytes.Equal(got, want) {
		t.Errorf("decrypt != capture\n  got =%x\n  want=%x", got, want)
	}
}

// Memastikan reduksi nibble kita menghasilkan kunci yang semua nibble-nya <= 9,
// sebagaimana aesKey hasil capture (52 13 45 ... — tiap nibble <= 9).
func TestCaptureKeyAllNibblesReduced(t *testing.T) {
	aesKey := mustHex(t, "52134543831675282125043111356329")
	for i, b := range aesKey {
		if b>>4 > 9 || b&0x0F > 9 {
			t.Errorf("byte %d = %#x punya nibble > 9 (tak tereduksi)", i, b)
		}
	}
}
