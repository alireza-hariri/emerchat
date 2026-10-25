// Package store is the SQLite persistence layer.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrForbidden = errors.New("forbidden")
	ErrConflict  = errors.New("conflict")
	ErrInvalid   = errors.New("invalid")
)

//go:embed schema.sql
var schemaV1 string

//go:embed schema_v2.sql
var schemaV2 string

//go:embed schema_v3.sql
var schemaV3 string

// migrations[i] upgrades the schema from user_version i to i+1.
var migrations = []string{schemaV1, schemaV2, schemaV3}

// Store holds a single-connection writer pool and a reader pool, which is
// how SQLite in WAL mode wants to be used.
type Store struct {
	w *sql.DB
	r *sql.DB
}

func Open(path string) (*Store, error) {
	dsn := func(extra string) string {
		return "file:" + (&url.URL{Path: path}).EscapedPath() +
			"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)" +
			"&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)" + extra
	}
	w, err := sql.Open("sqlite", dsn("&_txlock=immediate"))
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	s := &Store{w: w}
	if err := s.migrate(); err != nil {
		w.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	r, err := sql.Open("sqlite", dsn(""))
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(8)
	s.r = r
	return s, nil
}

func (s *Store) Close() error {
	return errors.Join(s.r.Close(), s.w.Close())
}

func (s *Store) migrate() error {
	var v int
	if err := s.w.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	for ; v < len(migrations); v++ {
		tx, err := s.w.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", v+1, err)
		}
		if _, err := tx.Exec("PRAGMA user_version = " + strconv.Itoa(v+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Secret returns a persistent random server secret, creating it on first use.
func (s *Store) Secret(ctx context.Context) ([]byte, error) {
	b := make([]byte, 32)
	rand.Read(b)
	if _, err := s.w.ExecContext(ctx, `INSERT OR IGNORE INTO meta(key, value) VALUES ('secret', ?)`, b); err != nil {
		return nil, err
	}
	var out []byte
	err := s.w.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'secret'`).Scan(&out)
	return out, err
}

// Backup writes a consistent copy of the database to path.
func (s *Store) Backup(ctx context.Context, path string) error {
	_, err := s.w.ExecContext(ctx, `VACUUM INTO ?`, path)
	return err
}

func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func isUniqueErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func isFKErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "FOREIGN KEY constraint failed")
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
