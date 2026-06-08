package db

import (
	"testing"
)

func TestHashPasswordMD5(t *testing.T) {
	hash, err := HashPassword("rahasia123")
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}
	if hash == "rahasia123" {
		t.Fatal("hash sama dengan plaintext (tidak di-hash)")
	}
	// MD5("rahasia123") = 7f95b733f4210c71482904eb422143f8
	expected := "7f95b733f4210c71482904eb422143f8"
	if hash != expected {
		t.Errorf("MD5 hash salah: got %q, want %q", hash, expected)
	}
	// Verifikasi hash berbeda untuk password berbeda
	hash2, _ := HashPassword("salah")
	if hash == hash2 {
		t.Error("password berbeda menghasilkan hash sama")
	}
}
