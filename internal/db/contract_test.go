package db

import (
	"context"
	"errors"
	"testing"

	"lumeris-go/internal/model"
)

// testStore menjalankan kontrak Store yang sama terhadap impl apa pun.
// Dipakai oleh MemStore (selalu) dan PostgresStore (gated, Task 4).
func testStore(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()

	// 1. CreateAccount + GetAccountByName.
	hash, err := HashPassword("pw")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	acc, err := s.CreateAccount(ctx, "alice", hash)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if acc.ID == 0 || acc.Username != "alice" {
		t.Fatalf("akun tak valid: %+v", acc)
	}
	got, err := s.GetAccountByName(ctx, "alice")
	if err != nil {
		t.Fatalf("GetAccountByName: %v", err)
	}
	if got.ID != acc.ID {
		t.Errorf("akun beda: %+v vs %+v", got, acc)
	}

	// 2. username duplikat → ErrDuplicate.
	if _, err := s.CreateAccount(ctx, "alice", hash); !errors.Is(err, ErrDuplicate) {
		t.Errorf("CreateAccount duplikat: err = %v, mau ErrDuplicate", err)
	}

	// 3. GetAccountByName tak ada → ErrNotFound.
	if _, err := s.GetAccountByName(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetAccountByName hilang: err = %v, mau ErrNotFound", err)
	}

	// 4. CheckPassword benar & salah.
	ok, err := s.CheckPassword(ctx, "alice", "pw")
	if err != nil || !ok {
		t.Errorf("CheckPassword benar: ok=%v err=%v", ok, err)
	}
	ok, _ = s.CheckPassword(ctx, "alice", "salah")
	if ok {
		t.Error("CheckPassword salah malah true")
	}

	// 5. CreateCharacter + CharsByAccount + LoadCharacter.
	ch := &model.Character{
		AccountID: acc.ID, Slot: 0, Name: "Hero", Job: 1, Level: 1,
		MapID: 1, X: 5, Y: 6, HP: 100, MaxHP: 100, SP: 10, MaxSP: 10,
		Str: 1, Dex: 1, Int: 1, Vit: 1, Agi: 1, Mnd: 1,
		Appearance: model.Appearance{Hair: 1, HairColor: 2, Face: 3},
	}
	if err := s.CreateCharacter(ctx, ch); err != nil {
		t.Fatalf("CreateCharacter: %v", err)
	}
	if ch.ID == 0 {
		t.Fatal("CreateCharacter tak mengisi ID")
	}
	chars, err := s.CharsByAccount(ctx, acc.ID)
	if err != nil || len(chars) != 1 {
		t.Fatalf("CharsByAccount: len=%d err=%v", len(chars), err)
	}
	loaded, err := s.LoadCharacter(ctx, ch.ID)
	if err != nil {
		t.Fatalf("LoadCharacter: %v", err)
	}
	if loaded.Name != "Hero" || loaded.Appearance.Hair != 1 || loaded.X != 5 {
		t.Errorf("LoadCharacter beda: %+v", loaded)
	}

	// 6. nama karakter duplikat → ErrDuplicate.
	dup := &model.Character{AccountID: acc.ID, Slot: 1, Name: "Hero", Job: 1, MapID: 1, HP: 1, MaxHP: 1, SP: 1, MaxSP: 1}
	if err := s.CreateCharacter(ctx, dup); !errors.Is(err, ErrDuplicate) {
		t.Errorf("CreateCharacter nama duplikat: err = %v, mau ErrDuplicate", err)
	}

	// 7. SaveCharacter (update posisi) → LoadCharacter mencerminkan.
	loaded.X, loaded.Y, loaded.Level = 99, 88, 5
	if err := s.SaveCharacter(ctx, loaded); err != nil {
		t.Fatalf("SaveCharacter: %v", err)
	}
	again, _ := s.LoadCharacter(ctx, ch.ID)
	if again.X != 99 || again.Y != 88 || again.Level != 5 {
		t.Errorf("SaveCharacter tak tersimpan: %+v", again)
	}

	// 8. CreateCharacter dengan account_id tak ada → ErrInvalidReference (FK).
	orphan := &model.Character{AccountID: 999999, Slot: 0, Name: "Orphan", Job: 1, MapID: 1, HP: 1, MaxHP: 1, SP: 1, MaxSP: 1}
	if err := s.CreateCharacter(ctx, orphan); !errors.Is(err, ErrInvalidReference) {
		t.Errorf("CreateCharacter account_id tak ada: err = %v, mau ErrInvalidReference", err)
	}

	// 9. CharsByAccount terurut menaik berdasar Slot (bukan urutan insert).
	hi := &model.Character{AccountID: acc.ID, Slot: 5, Name: "Slot5", Job: 1, MapID: 1, HP: 1, MaxHP: 1, SP: 1, MaxSP: 1}
	lo := &model.Character{AccountID: acc.ID, Slot: 2, Name: "Slot2", Job: 1, MapID: 1, HP: 1, MaxHP: 1, SP: 1, MaxSP: 1}
	if err := s.CreateCharacter(ctx, hi); err != nil {
		t.Fatalf("CreateCharacter Slot5: %v", err)
	}
	if err := s.CreateCharacter(ctx, lo); err != nil {
		t.Fatalf("CreateCharacter Slot2: %v", err)
	}
	list, err := s.CharsByAccount(ctx, acc.ID)
	if err != nil {
		t.Fatalf("CharsByAccount: %v", err)
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].Slot > list[i].Slot {
			t.Errorf("CharsByAccount tak terurut slot: %v diikuti %v", list[i-1].Slot, list[i].Slot)
		}
	}

	// 10. DeleteCharacter → LoadCharacter ErrNotFound.
	if err := s.DeleteCharacter(ctx, ch.ID); err != nil {
		t.Fatalf("DeleteCharacter: %v", err)
	}
	if _, err := s.LoadCharacter(ctx, ch.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("LoadCharacter setelah delete: err = %v, mau ErrNotFound", err)
	}
}

func TestMemStoreContract(t *testing.T) {
	testStore(t, NewMemStore())
}

func TestPostgresStoreContract(t *testing.T) {
	pool := testPool(t) // skip bila LUMERIS_TEST_DSN kosong
	ctx := context.Background()

	// Skema bersih + migrasi sebelum contract test.
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS characters, accounts, schema_migrations CASCADE`); err != nil {
		t.Fatalf("bersihkan skema: %v", err)
	}
	if err := RunMigrations(ctx, pool, MigrationsFS); err != nil {
		t.Fatalf("migrasi: %v", err)
	}

	testStore(t, NewPostgresStore(pool))
}
