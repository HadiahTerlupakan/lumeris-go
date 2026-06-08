// Package db menyediakan lapisan persistence: interface Store dan implementasinya
// (MemStore in-memory + PostgresStore pgx).
package db

import (
	"context"
	"errors"

	"lumeris-go/internal/model"
)

// Error sentinel yang dikembalikan kedua impl Store secara konsisten.
var (
	// ErrNotFound dikembalikan saat baris yang diminta tak ada.
	ErrNotFound = errors.New("db: tidak ditemukan")
	// ErrDuplicate dikembalikan saat melanggar UNIQUE (username/nama/slot).
	ErrDuplicate = errors.New("db: duplikat")
	// ErrInvalidReference dikembalikan saat melanggar foreign key (mis. membuat
	// karakter untuk account_id yang tak ada). Postgres: SQLSTATE 23503; MemStore
	// memeriksa keberadaan akun secara eksplisit agar perilakunya setara.
	ErrInvalidReference = errors.New("db: referensi tak valid")
)

// Store adalah kontrak persistence lumeris-go. Dua impl: MemStore & PostgresStore.
// CreateAccount menerima passwordHash yang SUDAH di-hash (pakai HashPassword);
// Store tak mencampuri kebijakan kripto. CheckPassword menerima plaintext.
type Store interface {
	CreateAccount(ctx context.Context, username, passwordHash string) (*model.Account, error)
	GetAccountByName(ctx context.Context, username string) (*model.Account, error)
	CheckPassword(ctx context.Context, username, password string) (bool, error)
	CharsByAccount(ctx context.Context, accountID int64) ([]*model.Character, error)
	CreateCharacter(ctx context.Context, c *model.Character) error
	DeleteCharacter(ctx context.Context, charID int64) error
	LoadCharacter(ctx context.Context, charID int64) (*model.Character, error)
	SaveCharacter(ctx context.Context, c *model.Character) error
}
