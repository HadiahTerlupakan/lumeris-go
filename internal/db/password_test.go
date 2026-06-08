package db

import (
	"golang.org/x/crypto/bcrypt"
	"testing"
)

func TestHashPasswordVerifiable(t *testing.T) {
	hash, err := HashPassword("rahasia123")
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}
	if hash == "rahasia123" {
		t.Fatal("hash sama dengan plaintext (tidak di-hash)")
	}
	// hash bcrypt harus terverifikasi terhadap plaintext asli.
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("rahasia123")); err != nil {
		t.Errorf("hash tak terverifikasi: %v", err)
	}
	// password salah harus gagal.
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("salah")); err == nil {
		t.Error("password salah malah terverifikasi")
	}
}
