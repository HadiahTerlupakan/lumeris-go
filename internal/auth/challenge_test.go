package auth

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestMD5Hex(t *testing.T) {
	hash := MD5Hex("testpassword")
	// Verifikasi dengan hasil md5sum manual
	expected := "e16b2ab8d12314bf4efbd6203906ea6c"
	if hash != expected {
		t.Errorf("MD5Hex salah: got %q, want %q", hash, expected)
	}
}

func TestVerifyChallengeValid(t *testing.T) {
	// Simulasi: password "testpass" -> MD5 -> stored
	password := "testpass"
	h := md5.Sum([]byte(password))
	storedMD5 := hex.EncodeToString(h[:])

	// Server kirim front & back
	front := uint32(0x12345678)
	back := uint32(0x9ABCDEF0)

	// Klien hitung sama seperti C# MySQLAccountDB.CheckPassword:
	// SHA1(frontword_DESIMAL + storedMD5_lowercase + backword_DESIMAL)
	// frontword/backword dirender sebagai angka desimal SIGNED int32
	// (C# `int`), persis seperti yang dilakukan klien eco.exe asli.
	str := fmt.Sprintf("%d%s%d", int32(front), storedMD5, int32(back))
	response := sha1.Sum([]byte(str))

	// Verifikasi
	if !VerifyChallenge(storedMD5, front, back, response[:]) {
		t.Error("VerifyChallenge gagal untuk response valid")
	}
}

// TestVerifyChallengeRealClient adalah vektor regresi dari capture klien eco.exe
// asli (server_run.err, user "testuser"). Challenge front=0x882c60d7 punya
// high-bit set, sehingga klien memperlakukannya sebagai int32 NEGATIF. Tanpa
// cast int32 di VerifyChallenge, login challenge bernilai besar selalu gagal.
func TestVerifyChallengeRealClient(t *testing.T) {
	storedMD5 := "cc03e747a6afbbcbf8be7668acfebee5"
	front := uint32(0x882c60d7) // 2284609751 unsigned / -2010357545 signed
	back := uint32(0xf6efe442)  // 4142916674 unsigned / -152050622 signed

	// Response SHA1 persis yang dikirim klien asli di capture.
	response, _ := hex.DecodeString("5adc7066439baaf67e092d514cfb8f08b68e35e3")

	if !VerifyChallenge(storedMD5, front, back, response) {
		t.Error("VerifyChallenge gagal untuk vektor klien eco.exe asli (regresi signed int32)")
	}
}

func TestVerifyChallengeInvalid(t *testing.T) {
	storedMD5 := "179ad45c6ce2cb97cf1029e212046e81" // MD5("test")
	front := uint32(0x11111111)
	back := uint32(0x22222222)

	// Response salah (bukan SHA1 yang benar)
	wrongResponse := make([]byte, 20)
	copy(wrongResponse, []byte("wrong_response_12345"))

	if VerifyChallenge(storedMD5, front, back, wrongResponse) {
		t.Error("VerifyChallenge menerima response salah")
	}
}

func TestVerifyChallengeWrongLength(t *testing.T) {
	storedMD5 := "179ad45c6ce2cb97cf1029e212046e81"
	front := uint32(0x11111111)
	back := uint32(0x22222222)

	// Response panjang salah
	shortResponse := make([]byte, 10)

	if VerifyChallenge(storedMD5, front, back, shortResponse) {
		t.Error("VerifyChallenge menerima response panjang salah")
	}
}
