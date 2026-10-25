package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

type Member struct {
	User
	Role     string `json:"role"`
	LastRead int64  `json:"lastRead"`
}

type Chat struct {
	ID          int64    `json:"id"`
	Kind        string   `json:"kind"`
	Title       string   `json:"title"`
	Photo       string   `json:"photo"` // version of the group photo, "" if none
	KeyEpoch    int64    `json:"keyEpoch"`
	CreatedBy   int64    `json:"createdBy"`
	CreatedAt   int64    `json:"createdAt"`
	InviteCode  string   `json:"inviteCode,omitempty"`
	Members     []Member `json:"members"`
	LastMessage *Message `json:"lastMessage"`
	Unread      int64    `json:"unread"`
}

type Message struct {
	ID         int64  `json:"id"`
	ChatID     int64  `json:"chatId"`
	SenderID   int64  `json:"senderId"`
	Kind       string `json:"kind"`
	Epoch      int64  `json:"epoch"`
	Ciphertext string `json:"ciphertext,omitempty"`
	IV         string `json:"iv,omitempty"`
	Body       string `json:"body,omitempty"`
	ClientID   string `json:"clientId,omitempty"`
	CreatedAt  int64  `json:"createdAt"`
	EditedAt   int64  `json:"editedAt,omitempty"`
}

// WrappedKey is a group key encrypted for one member.
type WrappedKey struct {
	UserID     int64  `json:"userId"`
	Epoch      int64  `json:"epoch"`
	WrappedKey string `json:"wrappedKey"`
	IV         string `json:"iv"`
	WrappedBy  int64  `json:"wrappedBy"`
	// Public key of WrappedBy, needed to derive the unwrap key even after
	// that user has left the chat.
	WrappedByKey string `json:"wrappedByKey,omitempty"`
}

type Update struct {
	Seq  int64           `json:"seq"`
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
}

const msgCols = `id, chat_id, sender_id, kind, epoch, ciphertext, iv, body, created_at, edited_at`

func scanMessage(row scanner) (Message, error) {
	var m Message
	err := row.Scan(&m.ID, &m.ChatID, &m.SenderID, &m.Kind, &m.Epoch, &m.Ciphertext, &m.IV, &m.Body, &m.CreatedAt, &m.EditedAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return m, err
}

// querier is satisfied by both *sql.DB and *sql.Tx.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func members(ctx context.Context, q querier, chatID int64) ([]Member, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+userCols+`, m.role, m.last_read_msg_id
		FROM chat_members m JOIN users u ON u.id = m.user_id WHERE m.chat_id = ? ORDER BY m.joined_at, u.id`, chatID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		u, err := scanUser(rows, &m.Role, &m.LastRead)
		if err != nil {
			return nil, err
		}
		m.User = u
		out = append(out, m)
	}
	return out, rows.Err()
}

func memberIDs(ms []Member) []int64 {
	ids := make([]int64, len(ms))
	for i, m := range ms {
		ids[i] = m.ID
	}
	return ids
}

func findMember(ms []Member, uid int64) *Member {
	for i := range ms {
		if ms[i].ID == uid {
			return &ms[i]
		}
	}
	return nil
}

type chatRow struct {
	id, epoch, createdBy int64
	kind                 string
}

func loadChatRow(ctx context.Context, q querier, chatID int64) (chatRow, error) {
	var c chatRow
	c.id = chatID
	err := q.QueryRowContext(ctx, `SELECT kind, key_epoch, created_by FROM chats WHERE id = ?`, chatID).Scan(&c.kind, &c.epoch, &c.createdBy)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return c, err
}

// Chat returns the chat as seen by viewer, or ErrNotFound if viewer isn't a member.
func (s *Store) Chat(ctx context.Context, chatID, viewer int64) (Chat, error) {
	var c Chat
	var invite sql.NullString
	err := s.r.QueryRowContext(ctx, `SELECT c.id, c.kind, c.title, c.key_epoch, c.created_by, c.created_at, c.invite_code, c.photo
		FROM chats c JOIN chat_members m ON m.chat_id = c.id AND m.user_id = ? WHERE c.id = ?`, viewer, chatID).
		Scan(&c.ID, &c.Kind, &c.Title, &c.KeyEpoch, &c.CreatedBy, &c.CreatedAt, &invite, &c.Photo)
	c.InviteCode = invite.String
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	if c.Members, err = members(ctx, s.r, chatID); err != nil {
		return c, err
	}
	m, err := scanMessage(s.r.QueryRowContext(ctx, `SELECT `+msgCols+` FROM messages WHERE chat_id = ? ORDER BY id DESC LIMIT 1`, chatID))
	switch {
	case err == nil:
		c.LastMessage = &m
	case !errors.Is(err, ErrNotFound):
		return c, err
	}
	lastRead := findMember(c.Members, viewer).LastRead
	err = s.r.QueryRowContext(ctx, `SELECT count(*) FROM messages WHERE chat_id = ? AND id > ? AND sender_id != ?`,
		chatID, lastRead, viewer).Scan(&c.Unread)
	return c, err
}

// Chats lists the viewer's chats, most recently active first.
func (s *Store) Chats(ctx context.Context, viewer int64) ([]Chat, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT c.id FROM chats c JOIN chat_members m ON m.chat_id = c.id
		WHERE m.user_id = ?
		ORDER BY coalesce((SELECT max(id) FROM messages WHERE chat_id = c.id), 0) DESC, c.id DESC`, viewer)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Chat, 0, len(ids))
	for _, id := range ids {
		c, err := s.Chat(ctx, id, viewer)
		if errors.Is(err, ErrNotFound) {
			continue // left between queries
		}
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// DirectChat finds or creates the 1:1 chat between a and b (a == b is
// "Saved Messages"). It returns the IDs of users to notify if it was created.
func (s *Store) DirectChat(ctx context.Context, a, b, now int64) (chatID int64, notify []int64, err error) {
	lo, hi := min(a, b), max(a, b)
	key := fmt.Sprintf("%d:%d", lo, hi)
	err = s.tx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT id FROM chats WHERE direct_key = ?`, key).Scan(&chatID)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO chats(kind, direct_key, created_by, created_at) VALUES ('direct', ?, ?, ?)`, key, a, now)
		if err != nil {
			return err
		}
		chatID, _ = res.LastInsertId()
		notify = []int64{lo}
		if hi != lo {
			notify = append(notify, hi)
		}
		for _, uid := range notify {
			_, err := tx.ExecContext(ctx, `INSERT INTO chat_members(chat_id, user_id, joined_at) VALUES (?, ?, ?)`, chatID, uid, now)
			if isFKErr(err) {
				return ErrNotFound
			}
			if err != nil {
				return err
			}
		}
		return insertUpdates(ctx, tx, notify, "chat", map[string]int64{"chatId": chatID}, now)
	})
	return chatID, notify, err
}

// CreateGroup creates a group whose epoch-0 key is wrapped for every member
// (creator included). keys must cover exactly creator ∪ memberIDs.
func (s *Store) CreateGroup(ctx context.Context, creator int64, title string, memberIDs []int64, keys []WrappedKey, now int64) (chatID int64, notify []int64, err error) {
	all := []int64{creator}
	for _, id := range memberIDs {
		if !slices.Contains(all, id) {
			all = append(all, id)
		}
	}
	if !keysCover(keys, all, 0) {
		return 0, nil, fmt.Errorf("%w: keys must cover every member exactly", ErrInvalid)
	}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO chats(kind, title, created_by, created_at) VALUES ('group', ?, ?, ?)`, title, creator, now)
		if err != nil {
			return err
		}
		chatID, _ = res.LastInsertId()
		for _, uid := range all {
			role := "member"
			if uid == creator {
				role = "owner"
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO chat_members(chat_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)`, chatID, uid, role, now)
			if isFKErr(err) {
				return ErrNotFound
			}
			if err != nil {
				return err
			}
		}
		if err := insertKeys(ctx, tx, chatID, creator, keys); err != nil {
			return err
		}
		if _, err := systemMessage(ctx, tx, chatID, creator, map[string]any{"a": "create", "title": title}, now); err != nil {
			return err
		}
		return insertUpdates(ctx, tx, all, "chat", map[string]int64{"chatId": chatID}, now)
	})
	return chatID, all, err
}

func keysCover(keys []WrappedKey, members []int64, epoch int64) bool {
	if len(keys) != len(members) {
		return false
	}
	seen := map[int64]bool{}
	for _, k := range keys {
		if k.Epoch != epoch || seen[k.UserID] || !slices.Contains(members, k.UserID) {
			return false
		}
		seen[k.UserID] = true
	}
	return true
}

func insertKeys(ctx context.Context, tx *sql.Tx, chatID, wrappedBy int64, keys []WrappedKey) error {
	for _, k := range keys {
		_, err := tx.ExecContext(ctx, `INSERT INTO chat_keys(chat_id, user_id, epoch, wrapped_key, iv, wrapped_by) VALUES (?, ?, ?, ?, ?, ?)`,
			chatID, k.UserID, k.Epoch, k.WrappedKey, k.IV, wrappedBy)
		if isUniqueErr(err) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// AddMember adds uid to a group. key is the current group key wrapped for uid by `by`.
func (s *Store) AddMember(ctx context.Context, chatID, by, uid int64, key WrappedKey, now int64) (notify []int64, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		c, err := loadChatRow(ctx, tx, chatID)
		if err != nil {
			return err
		}
		ms, err := members(ctx, tx, chatID)
		if err != nil {
			return err
		}
		if findMember(ms, by) == nil {
			return ErrNotFound
		}
		if c.kind != "group" {
			return fmt.Errorf("%w: not a group", ErrInvalid)
		}
		if findMember(ms, uid) != nil {
			return ErrConflict
		}
		if key.UserID != uid || key.Epoch != c.epoch {
			return fmt.Errorf("%w: key must be for the new member at the current epoch", ErrInvalid)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO chat_members(chat_id, user_id, joined_at) VALUES (?, ?, ?)`, chatID, uid, now)
		if isFKErr(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := insertKeys(ctx, tx, chatID, by, []WrappedKey{key}); err != nil {
			return err
		}
		notify = append(memberIDs(ms), uid)
		if err := insertUpdates(ctx, tx, notify, "chat", map[string]int64{"chatId": chatID}, now); err != nil {
			return err
		}
		m, err := systemMessage(ctx, tx, chatID, by, map[string]any{"a": "add", "u": uid}, now)
		if err != nil {
			return err
		}
		return insertUpdates(ctx, tx, notify, "message", m, now)
	})
	return notify, err
}

// RemoveMember removes uid from a group (uid == by means leaving). Only the
// owner may remove others. The key epoch is bumped so the next message needs
// a fresh key the removed member never saw.
func (s *Store) RemoveMember(ctx context.Context, chatID, by, uid, now int64) (notify []int64, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		c, err := loadChatRow(ctx, tx, chatID)
		if err != nil {
			return err
		}
		ms, err := members(ctx, tx, chatID)
		if err != nil {
			return err
		}
		actor := findMember(ms, by)
		if actor == nil {
			return ErrNotFound
		}
		if c.kind != "group" {
			return fmt.Errorf("%w: not a group", ErrInvalid)
		}
		if findMember(ms, uid) == nil {
			return ErrNotFound
		}
		if by != uid && actor.Role != "owner" {
			return ErrForbidden
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?`, chatID, uid); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE chats SET key_epoch = key_epoch + 1 WHERE id = ?`, chatID); err != nil {
			return err
		}
		// Hand ownership to the longest-standing member if the owner left.
		if _, err := tx.ExecContext(ctx, `UPDATE chat_members SET role = 'owner'
			WHERE chat_id = ?1 AND NOT EXISTS (SELECT 1 FROM chat_members WHERE chat_id = ?1 AND role = 'owner')
			AND user_id = (SELECT user_id FROM chat_members WHERE chat_id = ?1 ORDER BY joined_at, user_id LIMIT 1)`, chatID); err != nil {
			return err
		}
		if err := insertUpdates(ctx, tx, []int64{uid}, "removed", map[string]int64{"chatId": chatID}, now); err != nil {
			return err
		}
		for _, m := range ms {
			if m.ID != uid {
				notify = append(notify, m.ID)
			}
		}
		action := map[string]any{"a": "remove", "u": uid}
		if by == uid {
			action = map[string]any{"a": "leave"}
		}
		m, err := systemMessage(ctx, tx, chatID, by, action, now)
		if err != nil {
			return err
		}
		if err := insertUpdates(ctx, tx, notify, "chat", map[string]int64{"chatId": chatID}, now); err != nil {
			return err
		}
		if err := insertUpdates(ctx, tx, notify, "message", m, now); err != nil {
			return err
		}
		notify = append(notify, uid)
		return nil
	})
	return notify, err
}

// Rekey installs the group key for the current epoch. The first member to
// do so wins; later attempts get ErrConflict and should fetch the keys.
func (s *Store) Rekey(ctx context.Context, chatID, by, epoch int64, keys []WrappedKey, now int64) (notify []int64, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		c, err := loadChatRow(ctx, tx, chatID)
		if err != nil {
			return err
		}
		ms, err := members(ctx, tx, chatID)
		if err != nil {
			return err
		}
		if findMember(ms, by) == nil {
			return ErrNotFound
		}
		if c.kind != "group" {
			return fmt.Errorf("%w: not a group", ErrInvalid)
		}
		if epoch != c.epoch {
			return ErrConflict
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM chat_keys WHERE chat_id = ? AND epoch = ?`, chatID, epoch).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrConflict
		}
		notify = memberIDs(ms)
		if !keysCover(keys, notify, epoch) {
			return fmt.Errorf("%w: keys must cover every member exactly", ErrInvalid)
		}
		if err := insertKeys(ctx, tx, chatID, by, keys); err != nil {
			return err
		}
		return insertUpdates(ctx, tx, notify, "chat", map[string]int64{"chatId": chatID}, now)
	})
	return notify, err
}

// Keys returns all group keys wrapped for uid.
func (s *Store) Keys(ctx context.Context, chatID, uid int64) ([]WrappedKey, error) {
	if err := s.requireMember(ctx, chatID, uid); err != nil {
		return nil, err
	}
	rows, err := s.r.QueryContext(ctx, `SELECT k.user_id, k.epoch, k.wrapped_key, k.iv, k.wrapped_by, u.public_key
		FROM chat_keys k JOIN users u ON u.id = k.wrapped_by
		WHERE k.chat_id = ? AND k.user_id = ? ORDER BY k.epoch`, chatID, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WrappedKey{}
	for rows.Next() {
		var k WrappedKey
		if err := rows.Scan(&k.UserID, &k.Epoch, &k.WrappedKey, &k.IV, &k.WrappedBy, &k.WrappedByKey); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) requireMember(ctx context.Context, chatID, uid int64) error {
	var one int
	err := s.r.QueryRowContext(ctx, `SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?`, chatID, uid).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// Messages returns up to limit messages older than before (0 = newest), oldest first.
func (s *Store) Messages(ctx context.Context, chatID, uid, before int64, limit int) ([]Message, error) {
	if err := s.requireMember(ctx, chatID, uid); err != nil {
		return nil, err
	}
	if before <= 0 {
		before = 1<<63 - 1
	}
	rows, err := s.r.QueryContext(ctx, `SELECT `+msgCols+` FROM messages WHERE chat_id = ? AND id < ? ORDER BY id DESC LIMIT ?`, chatID, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Message{}
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	slices.Reverse(out)
	return out, rows.Err()
}

// SendMessage stores an encrypted message. Group messages must use the
// current epoch, and that epoch must already have keys.
//
// fileIDs are attachments the sender uploaded to this chat; the message
// claims them so the janitor keeps them.
func (s *Store) SendMessage(ctx context.Context, chatID, sender, epoch int64, ciphertext, iv, clientID string, fileIDs []string, now int64) (m Message, notify []int64, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		c, err := loadChatRow(ctx, tx, chatID)
		if err != nil {
			return err
		}
		ms, err := members(ctx, tx, chatID)
		if err != nil {
			return err
		}
		if findMember(ms, sender) == nil {
			return ErrNotFound
		}
		if epoch != c.epoch {
			return ErrConflict
		}
		if c.kind == "group" {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM chat_keys WHERE chat_id = ? AND epoch = ?`, chatID, epoch).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return ErrConflict
			}
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO messages(chat_id, sender_id, epoch, ciphertext, iv, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			chatID, sender, epoch, ciphertext, iv, now)
		if err != nil {
			return err
		}
		id, _ := res.LastInsertId()
		for _, f := range fileIDs {
			res, err := tx.ExecContext(ctx, `UPDATE files SET message_id = ?
				WHERE id = ? AND chat_id = ? AND uploader = ? AND message_id IS NULL`, id, f, chatID, sender)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return fmt.Errorf("%w: unknown or already used attachment", ErrInvalid)
			}
		}
		m = Message{ID: id, ChatID: chatID, SenderID: sender, Kind: "msg", Epoch: epoch, Ciphertext: ciphertext, IV: iv, ClientID: clientID, CreatedAt: now}
		// Sending implies having read everything up to here.
		if _, err := tx.ExecContext(ctx, `UPDATE chat_members SET last_read_msg_id = ? WHERE chat_id = ? AND user_id = ?`, id, chatID, sender); err != nil {
			return err
		}
		notify = memberIDs(ms)
		return insertUpdates(ctx, tx, notify, "message", m, now)
	})
	return m, notify, err
}

// MarkRead advances uid's read marker and tells the other members.
func (s *Store) MarkRead(ctx context.Context, chatID, uid, upTo, now int64) (notify []int64, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		ms, err := members(ctx, tx, chatID)
		if err != nil {
			return err
		}
		if findMember(ms, uid) == nil {
			return ErrNotFound
		}
		res, err := tx.ExecContext(ctx, `UPDATE chat_members SET last_read_msg_id = ?3
			WHERE chat_id = ?1 AND user_id = ?2 AND last_read_msg_id < ?3
			AND ?3 <= (SELECT coalesce(max(id), 0) FROM messages WHERE chat_id = ?1)`, chatID, uid, upTo)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		notify = memberIDs(ms)
		return insertUpdates(ctx, tx, notify, "read", map[string]int64{"chatId": chatID, "userId": uid, "upTo": upTo}, now)
	})
	return notify, err
}

// EditMessage replaces the ciphertext of one of sender's messages. The epoch
// stays the same, so the new text is readable by exactly the same people.
func (s *Store) EditMessage(ctx context.Context, chatID, msgID, sender int64, ciphertext, iv string, now int64) (m Message, notify []int64, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		ms, err := members(ctx, tx, chatID)
		if err != nil {
			return err
		}
		if findMember(ms, sender) == nil {
			return ErrNotFound
		}
		m, err = scanMessage(tx.QueryRowContext(ctx, `SELECT `+msgCols+` FROM messages WHERE id = ? AND chat_id = ?`, msgID, chatID))
		if err != nil {
			return err
		}
		if m.SenderID != sender || m.Kind != "msg" {
			return ErrForbidden
		}
		if _, err := tx.ExecContext(ctx, `UPDATE messages SET ciphertext = ?, iv = ?, edited_at = ? WHERE id = ?`, ciphertext, iv, now, msgID); err != nil {
			return err
		}
		m.Ciphertext, m.IV, m.EditedAt = ciphertext, iv, now
		notify = memberIDs(ms)
		return insertUpdates(ctx, tx, notify, "edit", m, now)
	})
	return m, notify, err
}

// SetGroupTitle renames a group. Any member may; the change is announced
// with a system message.
func (s *Store) SetGroupTitle(ctx context.Context, chatID, by int64, title string, now int64) ([]int64, error) {
	return s.updateGroup(ctx, chatID, by, `UPDATE chats SET title = ? WHERE id = ?`, title,
		map[string]any{"a": "title", "title": title}, now)
}

// SetGroupPhoto records a new group photo version ("" removes it).
func (s *Store) SetGroupPhoto(ctx context.Context, chatID, by int64, version string, now int64) ([]int64, error) {
	return s.updateGroup(ctx, chatID, by, `UPDATE chats SET photo = ? WHERE id = ?`, version,
		map[string]any{"a": "photo", "removed": version == ""}, now)
}

func (s *Store) updateGroup(ctx context.Context, chatID, by int64, query string, value any, action map[string]any, now int64) (notify []int64, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		c, err := loadChatRow(ctx, tx, chatID)
		if err != nil {
			return err
		}
		ms, err := members(ctx, tx, chatID)
		if err != nil {
			return err
		}
		if findMember(ms, by) == nil {
			return ErrNotFound
		}
		if c.kind != "group" {
			return fmt.Errorf("%w: not a group", ErrInvalid)
		}
		if _, err := tx.ExecContext(ctx, query, value, chatID); err != nil {
			return err
		}
		notify = memberIDs(ms)
		if err := insertUpdates(ctx, tx, notify, "chat", map[string]int64{"chatId": chatID}, now); err != nil {
			return err
		}
		m, err := systemMessage(ctx, tx, chatID, by, action, now)
		if err != nil {
			return err
		}
		return insertUpdates(ctx, tx, notify, "message", m, now)
	})
	return notify, err
}

// InviteLink returns the group's invite code, creating one if needed. Any
// member may create it.
func (s *Store) InviteLink(ctx context.Context, chatID, by int64, newCode string, now int64) (code string, notify []int64, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		c, err := loadChatRow(ctx, tx, chatID)
		if err != nil {
			return err
		}
		ms, err := members(ctx, tx, chatID)
		if err != nil {
			return err
		}
		if findMember(ms, by) == nil {
			return ErrNotFound
		}
		if c.kind != "group" {
			return fmt.Errorf("%w: not a group", ErrInvalid)
		}
		var cur sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT invite_code FROM chats WHERE id = ?`, chatID).Scan(&cur); err != nil {
			return err
		}
		if cur.Valid {
			code = cur.String
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE chats SET invite_code = ?, invite_by = ? WHERE id = ?`, newCode, by, chatID); err != nil {
			return err
		}
		code, notify = newCode, memberIDs(ms)
		return insertUpdates(ctx, tx, notify, "chat", map[string]int64{"chatId": chatID}, now)
	})
	return code, notify, err
}

// RevokeInviteLink disables the group's invite link. Only the owner may.
func (s *Store) RevokeInviteLink(ctx context.Context, chatID, by, now int64) (notify []int64, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		ms, err := members(ctx, tx, chatID)
		if err != nil {
			return err
		}
		actor := findMember(ms, by)
		if actor == nil {
			return ErrNotFound
		}
		if actor.Role != "owner" {
			return ErrForbidden
		}
		if _, err := tx.ExecContext(ctx, `UPDATE chats SET invite_code = NULL, invite_by = NULL WHERE id = ?`, chatID); err != nil {
			return err
		}
		notify = memberIDs(ms)
		return insertUpdates(ctx, tx, notify, "chat", map[string]int64{"chatId": chatID}, now)
	})
	return notify, err
}

// LinkPreview is what someone holding an invite link sees before joining.
type LinkPreview struct {
	Title   string `json:"title"`
	Members int    `json:"members"`
	// ByAdmin is set when an admin created the link.
	ByAdmin bool `json:"-"`
}

func (s *Store) LinkPreview(ctx context.Context, code string) (LinkPreview, error) {
	var p LinkPreview
	err := s.r.QueryRowContext(ctx, `SELECT c.title, (SELECT count(*) FROM chat_members WHERE chat_id = c.id),
		coalesce((SELECT is_admin FROM users WHERE id = c.invite_by), 0)
		FROM chats c WHERE c.invite_code = ?`, code).Scan(&p.Title, &p.Members, &p.ByAdmin)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return p, err
}

// JoinByLink makes uid a member of the group behind an invite link. Joining
// again is a no-op that still returns the chat.
func (s *Store) JoinByLink(ctx context.Context, code string, uid, now int64) (chatID int64, notify []int64, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		chatID, notify, err = joinByLink(ctx, tx, code, uid, now)
		return err
	})
	return chatID, notify, err
}

// joinByLink adds uid and bumps the key epoch without installing a key: no
// member is around to wrap the current key for the newcomer, so the first
// client to notice (usually the newcomer's own) creates one via Rekey. The
// newcomer therefore can't read anything sent before they joined.
func joinByLink(ctx context.Context, tx *sql.Tx, code string, uid, now int64) (chatID int64, notify []int64, err error) {
	err = tx.QueryRowContext(ctx, `SELECT id FROM chats WHERE invite_code = ? AND kind = 'group'`, code).Scan(&chatID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, ErrNotFound
	}
	if err != nil {
		return 0, nil, err
	}
	ms, err := members(ctx, tx, chatID)
	if err != nil {
		return 0, nil, err
	}
	if findMember(ms, uid) != nil {
		return chatID, nil, nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO chat_members(chat_id, user_id, joined_at) VALUES (?, ?, ?)`, chatID, uid, now); err != nil {
		return 0, nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE chats SET key_epoch = key_epoch + 1 WHERE id = ?`, chatID); err != nil {
		return 0, nil, err
	}
	notify = append(memberIDs(ms), uid)
	if err := insertUpdates(ctx, tx, notify, "chat", map[string]int64{"chatId": chatID}, now); err != nil {
		return 0, nil, err
	}
	m, err := systemMessage(ctx, tx, chatID, uid, map[string]any{"a": "join"}, now)
	if err != nil {
		return 0, nil, err
	}
	return chatID, notify, insertUpdates(ctx, tx, notify, "message", m, now)
}

// AddFile records an uploaded attachment. It must be claimed by a message
// (see SendMessage) or PruneFiles will drop it.
func (s *Store) AddFile(ctx context.Context, id string, chatID, uploader, size, now int64) error {
	res, err := s.w.ExecContext(ctx, `INSERT INTO files(id, chat_id, uploader, size, created_at)
		SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?)`,
		id, chatID, uploader, size, now, chatID, uploader)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// IsMember reports ErrNotFound unless uid belongs to chatID.
func (s *Store) IsMember(ctx context.Context, chatID, uid int64) error {
	return s.requireMember(ctx, chatID, uid)
}

// CanReadFile reports ErrNotFound unless uid is a member of the file's chat.
func (s *Store) CanReadFile(ctx context.Context, id string, uid int64) error {
	var one int
	err := s.r.QueryRowContext(ctx, `SELECT 1 FROM files f JOIN chat_members m ON m.chat_id = f.chat_id AND m.user_id = ?
		WHERE f.id = ?`, uid, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// PruneFiles forgets attachments that no message claimed since before and
// returns their ids so the caller can delete the bytes.
func (s *Store) PruneFiles(ctx context.Context, before int64) (ids []string, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `DELETE FROM files WHERE message_id IS NULL AND created_at < ? RETURNING id`, before)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return ids, err
}

func systemMessage(ctx context.Context, tx *sql.Tx, chatID, by int64, body any, now int64) (Message, error) {
	b := mustJSON(body)
	res, err := tx.ExecContext(ctx, `INSERT INTO messages(chat_id, sender_id, kind, body, created_at) VALUES (?, ?, 'system', ?, ?)`, chatID, by, b, now)
	if err != nil {
		return Message{}, err
	}
	id, _ := res.LastInsertId()
	return Message{ID: id, ChatID: chatID, SenderID: by, Kind: "system", Body: b, CreatedAt: now}, nil
}

func insertUpdates(ctx context.Context, tx *sql.Tx, uids []int64, kind string, data any, now int64) error {
	payload := mustJSON(data)
	for _, uid := range uids {
		if _, err := tx.ExecContext(ctx, `INSERT INTO updates(user_id, kind, payload, created_at) VALUES (?, ?, ?, ?)`, uid, kind, payload, now); err != nil {
			return err
		}
	}
	return nil
}

// Updates returns uid's updates with seq > after, oldest first.
func (s *Store) Updates(ctx context.Context, uid, after int64, limit int) ([]Update, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT seq, kind, payload FROM updates WHERE user_id = ? AND seq > ? ORDER BY seq LIMIT ?`, uid, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Update{}
	for rows.Next() {
		var u Update
		var payload string
		if err := rows.Scan(&u.Seq, &u.Kind, &payload); err != nil {
			return nil, err
		}
		u.Data = json.RawMessage(payload)
		out = append(out, u)
	}
	return out, rows.Err()
}

// Cursor is the seq a freshly loaded client should poll from.
func (s *Store) Cursor(ctx context.Context, uid int64) (int64, error) {
	var seq sql.NullInt64
	if err := s.r.QueryRowContext(ctx, `SELECT max(seq) FROM updates WHERE user_id = ?`, uid).Scan(&seq); err != nil {
		return 0, err
	}
	pruned, err := s.PrunedThrough(ctx)
	return max(seq.Int64, pruned), err
}
