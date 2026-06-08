package register

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"lumeris-go/internal/db"
)

func TestRegisterSuccess(t *testing.T) {
	store := db.NewMemStore()
	s := NewServer(":8001", store)

	req := httptest.NewRequest(http.MethodPost, "/register", nil)
	req.Header.Set("username", "testuser")
	req.Header.Set("password", "testpass123")

	w := httptest.NewRecorder()
	s.handleRegister(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status code: %d, want 200", resp.StatusCode)
	}

	var result RegisterResponse
	json.NewDecoder(resp.Body).Decode(&result)
	if !result.Success {
		t.Errorf("Register gagal: %s", result.Error)
	}

	// Verifikasi akun tersimpan
	acc, err := store.GetAccountByName(context.Background(), "testuser")
	if err != nil {
		t.Fatalf("GetAccountByName error: %v", err)
	}
	if acc.Username != "testuser" {
		t.Error("Username salah di DB")
	}
	if len(acc.PasswordHash) != 32 { // MD5 hex = 32 char
		t.Errorf("PasswordHash format salah: %s", acc.PasswordHash)
	}
}

func TestRegisterDuplicate(t *testing.T) {
	store := db.NewMemStore()
	s := NewServer(":8001", store)

	// Buat akun pertama
	req1 := httptest.NewRequest(http.MethodPost, "/register", nil)
	req1.Header.Set("username", "testuser")
	req1.Header.Set("password", "testpass123")
	w1 := httptest.NewRecorder()
	s.handleRegister(w1, req1)

	// Coba duplikat
	req2 := httptest.NewRequest(http.MethodPost, "/register", nil)
	req2.Header.Set("username", "testuser")
	req2.Header.Set("password", "different")
	w2 := httptest.NewRecorder()
	s.handleRegister(w2, req2)

	var result RegisterResponse
	json.NewDecoder(w2.Body).Decode(&result)
	if result.Success {
		t.Error("Register duplikat harusnya gagal")
	}
	if result.Error != "Username already exists" {
		t.Errorf("Error message salah: %s", result.Error)
	}
}

func TestRegisterInvalidLength(t *testing.T) {
	store := db.NewMemStore()
	s := NewServer(":8001", store)

	tests := []struct {
		name     string
		username string
		password string
		wantErr  string
	}{
		{"username terlalu pendek", "abc", "testpass", "Username must be 4-30 characters"},
		{"username terlalu panjang", "abcdefghijklmnopqrstuvwxyz12345", "testpass", "Username must be 4-30 characters"},
		{"password terlalu pendek", "testuser", "123", "Password must be 4-32 characters"},
		{"password terlalu panjang", "testuser", "123456789012345678901234567890123", "Password must be 4-32 characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/register", nil)
			req.Header.Set("username", tt.username)
			req.Header.Set("password", tt.password)
			w := httptest.NewRecorder()
			s.handleRegister(w, req)

			var result RegisterResponse
			json.NewDecoder(w.Body).Decode(&result)
			if result.Success {
				t.Error("Register harusnya gagal")
			}
			if result.Error != tt.wantErr {
				t.Errorf("Error message: got %q, want %q", result.Error, tt.wantErr)
			}
		})
	}
}

func TestRegisterMethodNotAllowed(t *testing.T) {
	store := db.NewMemStore()
	s := NewServer(":8001", store)

	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	w := httptest.NewRecorder()
	s.handleRegister(w, req)

	var result RegisterResponse
	json.NewDecoder(w.Body).Decode(&result)
	if result.Success {
		t.Error("GET harusnya ditolak")
	}
	if result.Error != "Method not allowed" {
		t.Errorf("Error message salah: %s", result.Error)
	}
}
