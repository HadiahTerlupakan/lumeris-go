package db

import "golang.org/x/crypto/bcrypt"

// HashPassword menghasilkan hash bcrypt dari plaintext. Dipanggil logika login
// (Plan 4) SEBELUM CreateAccount — klien mengirim plaintext lewat koneksi AES,
// server hash sebelum menyimpan.
func HashPassword(plaintext string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
