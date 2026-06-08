package db

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"lumeris-go/internal/model"
)

// PostgresStore mengimplementasi Store di atas PostgreSQL via pgxpool.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore membungkus pool yang sudah dibuka.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// isUniqueViolation true bila err adalah pelanggaran UNIQUE Postgres (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// isForeignKeyViolation true bila err adalah pelanggaran FK Postgres (SQLSTATE 23503).
func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

func (p *PostgresStore) CreateAccount(ctx context.Context, username, passwordHash string) (*model.Account, error) {
	acc := &model.Account{Username: username, PasswordHash: passwordHash}
	err := p.pool.QueryRow(ctx,
		`INSERT INTO accounts(username, password_hash) VALUES($1,$2) RETURNING id, gm_level, banned`,
		username, passwordHash,
	).Scan(&acc.ID, &acc.GMLevel, &acc.Banned)
	if isUniqueViolation(err) {
		return nil, ErrDuplicate
	}
	if err != nil {
		return nil, err
	}
	return acc, nil
}

func (p *PostgresStore) GetAccountByName(ctx context.Context, username string) (*model.Account, error) {
	acc := &model.Account{Username: username}
	err := p.pool.QueryRow(ctx,
		`SELECT id, password_hash, gm_level, banned FROM accounts WHERE username=$1`,
		username,
	).Scan(&acc.ID, &acc.PasswordHash, &acc.GMLevel, &acc.Banned)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return acc, nil
}

func (p *PostgresStore) CheckPassword(ctx context.Context, username, password string) (bool, error) {
	acc, err := p.GetAccountByName(ctx, username)
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

func (p *PostgresStore) CharsByAccount(ctx context.Context, accountID int64) ([]*model.Character, error) {
	rows, err := p.pool.Query(ctx, selectCharCols+` WHERE account_id=$1 ORDER BY slot`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Character
	for rows.Next() {
		c, err := scanCharacter(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *PostgresStore) CreateCharacter(ctx context.Context, c *model.Character) error {
	err := p.pool.QueryRow(ctx,
		`INSERT INTO characters
		 (account_id, slot, name, job, level, map_id, x, y, hp, maxhp, sp, maxsp, str, dex, int_, vit, agi, mnd, appearance)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		 RETURNING id`,
		c.AccountID, c.Slot, c.Name, c.Job, c.Level, c.MapID, c.X, c.Y, c.HP, c.MaxHP, c.SP, c.MaxSP,
		c.Str, c.Dex, c.Int, c.Vit, c.Agi, c.Mnd, c.Appearance,
	).Scan(&c.ID)
	if isUniqueViolation(err) {
		return ErrDuplicate
	}
	if isForeignKeyViolation(err) {
		return ErrInvalidReference
	}
	return err
}

func (p *PostgresStore) DeleteCharacter(ctx context.Context, charID int64) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM characters WHERE id=$1`, charID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStore) LoadCharacter(ctx context.Context, charID int64) (*model.Character, error) {
	rows, err := p.pool.Query(ctx, selectCharCols+` WHERE id=$1`, charID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return nil, rows.Err()
		}
		return nil, ErrNotFound
	}
	return scanCharacter(rows)
}

func (p *PostgresStore) SaveCharacter(ctx context.Context, c *model.Character) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE characters SET
		 slot=$2, name=$3, job=$4, level=$5, map_id=$6, x=$7, y=$8, hp=$9, maxhp=$10, sp=$11, maxsp=$12,
		 str=$13, dex=$14, int_=$15, vit=$16, agi=$17, mnd=$18, appearance=$19
		 WHERE id=$1`,
		c.ID, c.Slot, c.Name, c.Job, c.Level, c.MapID, c.X, c.Y, c.HP, c.MaxHP, c.SP, c.MaxSP,
		c.Str, c.Dex, c.Int, c.Vit, c.Agi, c.Mnd, c.Appearance,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// selectCharCols = daftar kolom karakter, urut sesuai scanCharacter.
const selectCharCols = `SELECT id, account_id, slot, name, job, level, map_id, x, y, hp, maxhp, sp, maxsp, str, dex, int_, vit, agi, mnd, appearance FROM characters`

// scanCharacter membaca satu baris karakter (urut kolom = selectCharCols).
func scanCharacter(rows pgx.Rows) (*model.Character, error) {
	c := &model.Character{}
	err := rows.Scan(
		&c.ID, &c.AccountID, &c.Slot, &c.Name, &c.Job, &c.Level, &c.MapID, &c.X, &c.Y,
		&c.HP, &c.MaxHP, &c.SP, &c.MaxSP, &c.Str, &c.Dex, &c.Int, &c.Vit, &c.Agi, &c.Mnd, &c.Appearance,
	)
	if err != nil {
		return nil, err
	}
	return c, nil
}
