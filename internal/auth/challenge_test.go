package auth

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
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

	// Klien hitung: SHA1(front + storedMD5 + back)
	buf := make([]byte, 4+32+4)
	binary.BigEndian.PutUint32(buf[0:4], front)
	copy(buf[4:36], []byte(storedMD5))
	binary.BigEndian.PutUint32(buf[36:40], back)
	response := sha1.Sum(buf)

	// Verifikasi
	if !VerifyChallenge(storedMD5, front, back, response[:]) {
		t.Error("VerifyChallenge gagal untuk response valid")
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
