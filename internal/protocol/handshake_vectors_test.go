package protocol

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// Vektor handshake dari capture C# (SagaLib.Encryption.MakeAESKey), direkam via
// gate LUMERIS_HS_VECTOR=1 (sudah di-revert). Membuktikan MakeAESKeyHex Go ==
// MakeAESKey C# byte-for-byte: priv server + pubkey klien hex => aesKey identik.
func TestMakeAESKeyHexMatchesCapture(t *testing.T) {
	// privHex = byte mentah privateKey server (getBytes big-endian) saat sesi capture.
	privHex := "362F382F3230323620383A35353A343120414D362F382F3230323620313A35353A343120414D4D6F"
	peerPubHex := "ADF22587D1E231D537A5A9BFFD268D2E546587A2CD6FEDEF033D0BF6FB4092E2490C5F800D08968A413EFE3D20CA84BB3064503DF573435D53351F2FB86FF74EF4E95E59A8F52EE26644757CD977CBFB3E25222004AD1BF42C7B94E400093EF488C7D483B83E09F8D37589E9F026CE207CCB241AA0F15F2DF6EFC50D6160D46A"
	wantAES := "16731045648496114288493636133263"

	c := NewCrypto()
	priv, ok := new(big.Int).SetString(privHex, 16)
	if !ok {
		t.Fatalf("priv hex invalid")
	}
	c.privateKey = priv
	c.MakeAESKeyHex(peerPubHex)

	got := hex.EncodeToString(c.aesKey)
	if got != wantAES {
		t.Errorf("aesKey = %s, mau %s", got, wantAES)
	}
}
