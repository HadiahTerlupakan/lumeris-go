// Package auth menyediakan fungsi autentikasi untuk login flow ECO.
package auth

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
)

// MD5Hex menghitung MD5 hash dari plaintext dan mengembalikan hex lowercase.
// Dipakai saat register (HTTP endpoint) untuk menyimpan password ke DB.
func MD5Hex(plaintext string) string {
	h := md5.Sum([]byte(plaintext))
	return hex.EncodeToString(h[:])
}

// VerifyChallenge memverifikasi response SHA1 challenge dari klien ECO.
// Klien mengirim: SHA1(front + storedMD5 + back) dimana front & back adalah
// dua uint32 random yang dikirim server via LOGIN_ALLOWED packet.
//
// storedMD5Hex: MD5 hash password tersimpan di DB (32 char hex lowercase)
// front, back: dua uint32 random yang dikirim ke klien
// response: 20 byte SHA1 hash yang dikirim klien
//
// Return true bila response cocok dengan expected SHA1.
func VerifyChallenge(storedMD5Hex string, front, back uint32, response []byte) bool {
	if len(response) != 20 {
		return false
	}
	// Bentuk buffer: [front 4 bytes BE] + [MD5 hex 32 bytes ASCII] + [back 4 bytes BE]
	buf := make([]byte, 4+32+4)
	binary.BigEndian.PutUint32(buf[0:4], front)
	copy(buf[4:36], []byte(storedMD5Hex))
	binary.BigEndian.PutUint32(buf[36:40], back)

	expected := sha1.Sum(buf)
	// Bandingkan byte-by-byte
	for i := 0; i < 20; i++ {
		if response[i] != expected[i] {
			return false
		}
	}
	return true
}
