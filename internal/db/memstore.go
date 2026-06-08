package db

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"sort"
	"sync"

	"lumeris-go/internal/model"
)

// MemStore adalah impl Store in-memory (map + RWMutex). Dipakai untuk test offline
// dan sebagai substrate handler login/map (Plan 4-5) tanpa DB nyata.
type MemStore struct {
	mu         sync.RWMutex
	accounts   map[int64]*model.Account
	characters map[int64]*model.Character
	nextAccID  int64
	nextCharID int64
}

// NewMemStore membuat MemStore kosong siap pakai.
func NewMemStore() *MemStore {
	return &MemStore{
		accounts:   make(map[int64]*model.Account),
		characters: make(map[int64]*model.Character),
	}
}

func (m *MemStore) CreateAccount(ctx context.Context, username, passwordHash string) (*model.Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.accounts {
		if a.Username == username {
			return nil, ErrDuplicate
		}
	}
	m.nextAccID++
	acc := &model.Account{
		ID:           m.nextAccID,
		Username:     username,
		PasswordHash: passwordHash,
		DeletePass:   "0000",
	}
	m.accounts[acc.ID] = acc
	return cloneAccount(acc), nil
}

func (m *MemStore) GetAccountByName(ctx context.Context, username string) (*model.Account, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.accounts {
		if a.Username == username {
			return cloneAccount(a), nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemStore) CheckPassword(ctx context.Context, username, password string) (bool, error) {
	acc, err := m.GetAccountByName(ctx, username)
	if err != nil {
		return false, err
	}
	// MD5-based comparison: hash password plaintext dan bandingkan dengan tersimpan
	h := md5.Sum([]byte(password))
	inputHash := hex.EncodeToString(h[:])
	if inputHash != acc.PasswordHash {
		return false, nil
	}
	return true, nil
}

func (m *MemStore) CharsByAccount(ctx context.Context, accountID int64) ([]*model.Character, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*model.Character
	for _, c := range m.characters {
		if c.AccountID == accountID {
			out = append(out, cloneCharacter(c))
		}
	}
	// Urut slot agar setara PostgresStore (ORDER BY slot) — iterasi map acak.
	sort.Slice(out, func(i, j int) bool { return out[i].Slot < out[j].Slot })
	return out, nil
}

func (m *MemStore) CreateCharacter(ctx context.Context, c *model.Character) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// FK: account_id harus menunjuk akun yang ada (setara REFERENCES di Postgres).
	if _, ok := m.accounts[c.AccountID]; !ok {
		return ErrInvalidReference
	}
	for _, ex := range m.characters {
		if ex.Name == c.Name {
			return ErrDuplicate
		}
		if ex.AccountID == c.AccountID && ex.Slot == c.Slot {
			return ErrDuplicate
		}
	}
	m.nextCharID++
	c.ID = m.nextCharID
	m.characters[c.ID] = cloneCharacter(c)
	return nil
}

func (m *MemStore) DeleteCharacter(ctx context.Context, charID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.characters[charID]; !ok {
		return ErrNotFound
	}
	delete(m.characters, charID)
	return nil
}

func (m *MemStore) LoadCharacter(ctx context.Context, charID int64) (*model.Character, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.characters[charID]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneCharacter(c), nil
}

func (m *MemStore) SaveCharacter(ctx context.Context, c *model.Character) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.characters[c.ID]; !ok {
		return ErrNotFound
	}
	m.characters[c.ID] = cloneCharacter(c)
	return nil
}

// clone* mengembalikan salinan agar pemanggil tak bisa memutasi state internal
// lewat pointer bersama (MemStore meniru semantik "DB mengembalikan baris baru").
func cloneAccount(a *model.Account) *model.Account {
	cp := *a
	return &cp
}

func cloneCharacter(c *model.Character) *model.Character {
	cp := *c
	return &cp
}
