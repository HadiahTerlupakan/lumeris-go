package db

import (
	"crypto/md5"
	"encoding/hex"
)

// HashPassword menghasilkan hash MD5 hex (lowercase) dari plaintext.
// Klien ECO asli menyimpan MD5(password) di DB, bukan bcrypt.
// Dipanggil saat register (HTTP endpoint) SEBELUM CreateAccount.
func HashPassword(plaintext string) (string, error) {
	h := md5.Sum([]byte(plaintext))
	return hex.EncodeToString(h[:]), nil
}
