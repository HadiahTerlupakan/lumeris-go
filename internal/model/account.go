// Package model mendefinisikan tipe domain murni lumeris-go (tanpa dependensi DB).
package model

// Account adalah satu akun pemain yang tersimpan di DB.
type Account struct {
	ID           int64
	Username     string
	PasswordHash string
	DeletePass   string // Password untuk hapus karakter (default "0000")
	GMLevel      int
	Banned       bool
}
