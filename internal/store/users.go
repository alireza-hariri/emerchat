package store

import (
	"context"
	"database/sql"
	"errors"
)

type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	PublicKey   string `json:"publicKey"`
	IsAdmin     bool   `json:"isAdmin"`
	Avatar      string `json:"avatar"` // version of the profile picture, "" if none
	LastSeen    int64  `json:"lastSeen"`
	CreatedAt   int64  `json:"createdAt"`
}

// NewUser is everything the client uploads at registration.
type NewUser struct {
	Username          string
	DisplayName       string
	AuthHash          []byte
	AuthSalt          []byte
	KDFSalt           string
	PublicKey         string
	WrappedPrivateKey string
	WrapIV            string
}

type Credentials struct {
	User              User
	AuthHash          []byte
	AuthSalt          []byte
	KDFSalt           string
	WrappedPrivateKey string
	WrapIV            string
}

const userCols = `u.id, u.username, u.display_name, u.public_key, u.is_admin, u.avatar, u.last_seen, u.created_at`

type scanner interface{ Scan(...any) error }

func scanUser(row scanner, extra ...any) (User, error) {
	var u User
	err := row.Scan(append([]any{&u.ID, &u.Username, &u.DisplayName, &u.PublicKey, &u.IsAdmin, &u.Avatar, &u.LastSeen, &u.CreatedAt}, extra...)...)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return u, err
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// Register redeems an invite and creates the user atomically. It returns
// ErrNotFound for unknown, used or expired invites and ErrConflict when the
// username is taken.
func (s *Store) Register(ctx context.Context, invite string, nu NewUser, now int64) (User, error) {
	var u User
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var createdBy sql.NullInt64
		var admin bool
		err := tx.QueryRowContext(ctx,
			`SELECT created_by, grants_admin FROM invites WHERE code = ? AND used_by IS NULL AND expires_at > ?`,
			invite, now).Scan(&createdBy, &admin)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if u, err = insertUser(ctx, tx, nu, admin, createdBy, now); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE invites SET used_by = ? WHERE code = ? AND used_by IS NULL`, u.ID, invite)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		return nil
	})
	return u, err
}

// RegisterViaLink creates the user from a group invite link and makes them a
// member of that group. With adminLinksOnly, only links created by an admin
// may be used to sign up (ErrForbidden otherwise).
func (s *Store) RegisterViaLink(ctx context.Context, code string, nu NewUser, adminLinksOnly bool, now int64) (u User, chatID int64, notify []int64, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var by sql.NullInt64
		var admin sql.NullBool
		err := tx.QueryRowContext(ctx, `SELECT c.invite_by, u.is_admin FROM chats c LEFT JOIN users u ON u.id = c.invite_by
			WHERE c.invite_code = ?`, code).Scan(&by, &admin)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if adminLinksOnly && !admin.Bool {
			return ErrForbidden
		}
		if u, err = insertUser(ctx, tx, nu, false, by, now); err != nil {
			return err
		}
		chatID, notify, err = joinByLink(ctx, tx, code, u.ID, now)
		return err
	})
	return u, chatID, notify, err
}

func insertUser(ctx context.Context, tx *sql.Tx, nu NewUser, admin bool, invitedBy sql.NullInt64, now int64) (User, error) {
	res, err := tx.ExecContext(ctx, `INSERT INTO users
		(username, display_name, auth_hash, auth_salt, kdf_salt, public_key, wrapped_private_key, wrap_iv, is_admin, invited_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nu.Username, nu.DisplayName, nu.AuthHash, nu.AuthSalt, nu.KDFSalt, nu.PublicKey, nu.WrappedPrivateKey, nu.WrapIV, admin, invitedBy, now)
	if isUniqueErr(err) {
		return User{}, ErrConflict
	}
	if err != nil {
		return User{}, err
	}
	id, _ := res.LastInsertId()
	return User{ID: id, Username: nu.Username, DisplayName: nu.DisplayName, PublicKey: nu.PublicKey, IsAdmin: admin, CreatedAt: now}, nil
}

func (s *Store) Credentials(ctx context.Context, username string) (Credentials, error) {
	var c Credentials
	u, err := scanUser(s.r.QueryRowContext(ctx,
		`SELECT `+userCols+`, u.auth_hash, u.auth_salt, u.kdf_salt, u.wrapped_private_key, u.wrap_iv
		 FROM users u WHERE u.username = ?`, username),
		&c.AuthHash, &c.AuthSalt, &c.KDFSalt, &c.WrappedPrivateKey, &c.WrapIV)
	c.User = u
	return c, err
}

func (s *Store) User(ctx context.Context, id int64) (User, error) {
	return scanUser(s.r.QueryRowContext(ctx, `SELECT `+userCols+` FROM users u WHERE u.id = ?`, id))
}

// SearchUsers matches usernames and display names by prefix.
func (s *Store) SearchUsers(ctx context.Context, q string, limit int) ([]User, error) {
	like := escapeLike(q) + "%"
	rows, err := s.r.QueryContext(ctx, `SELECT `+userCols+` FROM users u
		WHERE u.username LIKE ? ESCAPE '\' OR u.display_name LIKE ? ESCAPE '\'
		ORDER BY u.username LIMIT ?`, like, like, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) TouchLastSeen(ctx context.Context, id, now int64) error {
	_, err := s.w.ExecContext(ctx, `UPDATE users SET last_seen = ? WHERE id = ?`, now, id)
	return err
}

// SetDisplayName renames uid and tells everyone who shares a chat with them.
func (s *Store) SetDisplayName(ctx context.Context, uid int64, name string, now int64) (User, []int64, error) {
	return s.updateProfile(ctx, uid, `UPDATE users SET display_name = ? WHERE id = ?`, name, now)
}

// SetAvatar records a new profile picture version ("" removes it).
func (s *Store) SetAvatar(ctx context.Context, uid int64, version string, now int64) (User, []int64, error) {
	return s.updateProfile(ctx, uid, `UPDATE users SET avatar = ? WHERE id = ?`, version, now)
}

func (s *Store) updateProfile(ctx context.Context, uid int64, query string, value any, now int64) (u User, notify []int64, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, query, value, uid)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if u, err = scanUser(tx.QueryRowContext(ctx, `SELECT `+userCols+` FROM users u WHERE u.id = ?`, uid)); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT ?1 UNION SELECT DISTINCT m.user_id FROM chat_members m
			WHERE m.chat_id IN (SELECT chat_id FROM chat_members WHERE user_id = ?1)`, uid)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				return err
			}
			notify = append(notify, id)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		return insertUpdates(ctx, tx, notify, "user", u, now)
	})
	return u, notify, err
}

func escapeLike(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' || s[i] == '_' || s[i] == '\\' {
			out = append(out, '\\')
		}
		out = append(out, s[i])
	}
	return string(out)
}
