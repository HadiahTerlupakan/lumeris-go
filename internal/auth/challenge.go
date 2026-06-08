// Package auth menyediakan fungsi autentikasi untuk login flow ECO.
package auth

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
)

// MD5Hex menghitung MD5 hash dari plaintext dan mengembalikan hex lowercase.
// Dipakai saat register (HTTP endpoint) untuk menyimpan password ke DB.
func MD5Hex(plaintext string) string {
	h := md5.Sum([]byte(plaintext))
	return hex.EncodeToString(h[:])
}

// VerifyChallenge memverifikasi response SHA1 challenge dari klien ECO.
// Format sesuai MySQLAccountDB.CheckPassword (line 247-248):
// SHA1(frontword_decimal_string + password_lowercase + backword_decimal_string)
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

	// Format: "frontword" + "password_lowercase" + "backword" (as ASCII decimal strings)
	// Contoh: "1234567890" + "851fdee206c1eec10cee5ec8e8962af2" + "9876543210"
	str := fmt.Sprintf("%d%s%d", front, strings.ToLower(storedMD5Hex), back)
	expected := sha1.Sum([]byte(str))

	// Debug logging
	log.Printf("[Auth] VerifyChallenge: front=%d back=%d md5=%s", front, back, storedMD5Hex)
	log.Printf("[Auth] Challenge string: %s", str)
	log.Printf("[Auth] Expected SHA1: %02x", expected[:])
	log.Printf("[Auth] Client SHA1:   %02x", response)

	// Bandingkan byte-by-byte
	for i := 0; i < 20; i++ {
		if response[i] != expected[i] {
			return false
		}
	}
	return true
}
