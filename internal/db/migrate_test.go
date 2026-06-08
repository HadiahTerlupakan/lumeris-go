package db

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool membuka pool ke Postgres test bila LUMERIS_TEST_DSN di-set; else skip.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("LUMERIS_TEST_DSN")
	if dsn == "" {
		t.Skip("LUMERIS_TEST_DSN tak di-set; lewati test Postgres")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestRunMigrationsIdempotent(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// Bersihkan agar test deterministik (drop tabel bila ada dari run sebelumnya).
	_, _ = pool.Exec(ctx, `DROP TABLE IF EXISTS characters, accounts, schema_migrations CASCADE`)

	if err := RunMigrations(ctx, pool, MigrationsFS); err != nil {
		t.Fatalf("RunMigrations (1): %v", err)
	}
	// Jalankan lagi → harus no-op, tanpa error.
	if err := RunMigrations(ctx, pool, MigrationsFS); err != nil {
		t.Fatalf("RunMigrations (2, idempoten): %v", err)
	}

	// Verifikasi tabel ada & versi tercatat (sekarang ada 2 migrasi: 001_init + 002_extend).
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if n != 2 {
		t.Errorf("schema_migrations punya %d baris, mau 2", n)
	}
}
