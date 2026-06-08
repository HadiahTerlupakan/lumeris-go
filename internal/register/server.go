// Package register menyediakan HTTP endpoint untuk registrasi akun.
package register

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"lumeris-go/internal/auth"
	"lumeris-go/internal/db"
)

// Server adalah HTTP server untuk register endpoint.
type Server struct {
	store  db.Store
	server *http.Server
}

// NewServer membuat HTTP register server.
func NewServer(addr string, store db.Store) *Server {
	s := &Server{store: store}
	mux := http.NewServeMux()
	mux.HandleFunc("/register", s.handleRegister)
	s.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	return s
}

// Start memulai HTTP server (blocking).
func (s *Server) Start() error {
	log.Printf("[Register] HTTP server listening on %s", s.server.Addr)
	return s.server.ListenAndServe()
}

// Stop menghentikan HTTP server.
func (s *Server) Stop(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// Response format JSON
type RegisterResponse struct {
	Success bool   `json:"success,omitempty"`
	Error   string `json:"error,omitempty"`
}

// handleRegister menangani POST /register dengan header username & password.
// Port dari WebServer.Account.cs HandleRegister.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(RegisterResponse{Error: "Method not allowed"})
		return
	}

	// Baca username & password dari header
	username := r.Header.Get("username")
	password := r.Header.Get("password")

	// Validasi panjang (sesuai spec Plan 4: username 4-30, password 4-32)
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)

	if len(username) < 4 || len(username) > 30 {
		log.Printf("[Register] Username length invalid: %d", len(username))
		json.NewEncoder(w).Encode(RegisterResponse{Error: "Username must be 4-30 characters"})
		return
	}
	if len(password) < 4 || len(password) > 32 {
		log.Printf("[Register] Password length invalid: %d", len(password))
		json.NewEncoder(w).Encode(RegisterResponse{Error: "Password must be 4-32 characters"})
		return
	}

	// Hash password dengan MD5
	passwordHash := auth.MD5Hex(password)

	// Buat akun
	_, err := s.store.CreateAccount(context.Background(), username, passwordHash)
	if err == db.ErrDuplicate {
		log.Printf("[Register] Username already exists: %s", username)
		json.NewEncoder(w).Encode(RegisterResponse{Error: "Username already exists"})
		return
	}
	if err != nil {
		log.Printf("[Register] CreateAccount error: %v", err)
		json.NewEncoder(w).Encode(RegisterResponse{Error: "Internal server error"})
		return
	}

	log.Printf("[Register] Account created: %s", username)
	json.NewEncoder(w).Encode(RegisterResponse{Success: true})
}
