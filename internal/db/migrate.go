package db

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"lumeris-go/internal/migrations"
)

// MigrationsFS adalah FS berisi file *.sql migrasi. Embed-nya berada di paket
// internal/migrations (subtree-nya legal untuk //go:embed); di-re-export di sini
// agar pemanggil di paket db cukup memakai db.MigrationsFS.
var MigrationsFS fs.FS = migrations.FS

// RunMigrations menjalankan tiap file NNN_*.sql (urut nomor) yang belum tercatat
// di schema_migrations. Idempoten: file yang sudah dijalankan dilewati. Tiap file
// dijalankan dalam satu transaksi bersama insert versi-nya.
func RunMigrations(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS) error {
	// Pastikan tabel pencatat ada lebih dulu.
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("buat schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return fmt.Errorf("baca dir migrasi: %w", err)
	}
	type mig struct {
		version int
		name    string
	}
	var migs []mig
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		// nama: NNN_deskripsi.sql → ambil NNN.
		numStr, _, ok := strings.Cut(e.Name(), "_")
		if !ok {
			return fmt.Errorf("nama migrasi tak valid (butuh NNN_...): %s", e.Name())
		}
		v, err := strconv.Atoi(numStr)
		if err != nil {
			return fmt.Errorf("nomor migrasi tak valid di %s: %w", e.Name(), err)
		}
		migs = append(migs, mig{version: v, name: e.Name()})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })

	for _, mg := range migs {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, mg.version).Scan(&exists); err != nil {
			return fmt.Errorf("cek versi %d: %w", mg.version, err)
		}
		if exists {
			continue
		}
		sqlBytes, err := fs.ReadFile(fsys, mg.name)
		if err != nil {
			return fmt.Errorf("baca %s: %w", mg.name, err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin tx %s: %w", mg.name, err)
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("eksekusi %s: %w", mg.name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, mg.version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("catat versi %d: %w", mg.version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit %s: %w", mg.name, err)
		}
	}
	return nil
}
