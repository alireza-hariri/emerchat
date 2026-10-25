package store

import (
	"context"
	"database/sql"
	"errors"
)

type Invite struct {
	Code        string `json:"code"`
	GrantsAdmin bool   `json:"grantsAdmin"`
	UsedBy      *User  `json:"usedBy,omitempty"`
	ExpiresAt   int64  `json:"expiresAt"`
	CreatedAt   int64  `json:"createdAt"`
}

// CreateInvite stores an invite. createdBy == 0 means it came from the CLI.
func (s *Store) CreateInvite(ctx context.Context, code string, createdBy int64, grantsAdmin bool, expiresAt, now int64) (Invite, error) {
	var by any
	if createdBy != 0 {
		by = createdBy
	}
	_, err := s.w.ExecContext(ctx,
		`INSERT INTO invites(code, created_by, grants_admin, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`,
		code, by, grantsAdmin, expiresAt, now)
	return Invite{Code: code, GrantsAdmin: grantsAdmin, ExpiresAt: expiresAt, CreatedAt: now}, err
}

func (s *Store) Invites(ctx context.Context, createdBy int64) ([]Invite, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT i.code, i.grants_admin, i.expires_at, i.created_at, u.id, u.username, u.display_name
		FROM invites i LEFT JOIN users u ON u.id = i.used_by
		WHERE i.created_by = ? ORDER BY i.created_at DESC LIMIT 100`, createdBy)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Invite{}
	for rows.Next() {
		var inv Invite
		var uid sql.NullInt64
		var uname, dname sql.NullString
		if err := rows.Scan(&inv.Code, &inv.GrantsAdmin, &inv.ExpiresAt, &inv.CreatedAt, &uid, &uname, &dname); err != nil {
			return nil, err
		}
		if uid.Valid {
			inv.UsedBy = &User{ID: uid.Int64, Username: uname.String, DisplayName: dname.String}
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// RevokeInvite deletes an unused invite owned by createdBy.
func (s *Store) RevokeInvite(ctx context.Context, code string, createdBy int64) error {
	res, err := s.w.ExecContext(ctx, `DELETE FROM invites WHERE code = ? AND created_by = ? AND used_by IS NULL`, code, createdBy)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, userID, expiresAt int64) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)`, tokenHash, userID, expiresAt)
	return err
}

func (s *Store) SessionUser(ctx context.Context, tokenHash []byte, now int64) (User, error) {
	return scanUser(s.r.QueryRowContext(ctx, `SELECT `+userCols+` FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ?`, tokenHash, now))
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// Prune removes expired sessions and invites and update rows older than
// updatesBefore, remembering the highest pruned seq so pollers that fell
// behind can be told to resync.
func (s *Store) Prune(ctx context.Context, now, updatesBefore int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM invites WHERE used_by IS NULL AND expires_at <= ?`, now); err != nil {
			return err
		}
		var maxSeq sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT max(seq) FROM updates WHERE created_at < ?`, updatesBefore).Scan(&maxSeq); err != nil {
			return err
		}
		if !maxSeq.Valid {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM updates WHERE seq <= ?`, maxSeq.Int64); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES ('pruned_through', ?)
			ON CONFLICT(key) DO UPDATE SET value = max(value, excluded.value)`, maxSeq.Int64)
		return err
	})
}

func (s *Store) PrunedThrough(ctx context.Context) (int64, error) {
	var v int64
	err := s.r.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'pruned_through'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}
