CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE users (
    id                  INTEGER PRIMARY KEY,
    username            TEXT    NOT NULL UNIQUE,
    display_name        TEXT    NOT NULL,
    auth_hash           BLOB    NOT NULL, -- argon2id(authKey, auth_salt)
    auth_salt           BLOB    NOT NULL,
    kdf_salt            TEXT    NOT NULL, -- client-side PBKDF2 salt (base64)
    public_key          TEXT    NOT NULL, -- raw P-256 point (base64)
    wrapped_private_key TEXT    NOT NULL, -- AES-GCM(pkcs8) under the client wrap key
    wrap_iv             TEXT    NOT NULL,
    is_admin            INTEGER NOT NULL DEFAULT 0,
    invited_by          INTEGER REFERENCES users(id),
    last_seen           INTEGER NOT NULL DEFAULT 0,
    created_at          INTEGER NOT NULL
);

CREATE TABLE invites (
    code         TEXT PRIMARY KEY,
    created_by   INTEGER REFERENCES users(id) ON DELETE CASCADE, -- NULL = created from CLI
    grants_admin INTEGER NOT NULL DEFAULT 0,
    used_by      INTEGER REFERENCES users(id),
    expires_at   INTEGER NOT NULL,
    created_at   INTEGER NOT NULL
);
CREATE INDEX invites_created_by ON invites(created_by);

CREATE TABLE sessions (
    token_hash BLOB PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE chats (
    id         INTEGER PRIMARY KEY,
    kind       TEXT    NOT NULL CHECK (kind IN ('direct', 'group')),
    title      TEXT    NOT NULL DEFAULT '',
    direct_key TEXT    UNIQUE, -- "minUserID:maxUserID" for direct chats
    key_epoch  INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL
);

CREATE TABLE chat_members (
    chat_id          INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role             TEXT    NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
    last_read_msg_id INTEGER NOT NULL DEFAULT 0,
    joined_at        INTEGER NOT NULL,
    PRIMARY KEY (chat_id, user_id)
);
CREATE INDEX chat_members_user ON chat_members(user_id);

-- Group keys, wrapped for each member with ECDH(wrapped_by, user).
CREATE TABLE chat_keys (
    chat_id     INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    epoch       INTEGER NOT NULL,
    wrapped_key TEXT    NOT NULL,
    iv          TEXT    NOT NULL,
    wrapped_by  INTEGER NOT NULL REFERENCES users(id),
    PRIMARY KEY (chat_id, user_id, epoch)
);

CREATE TABLE messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id    INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    sender_id  INTEGER NOT NULL REFERENCES users(id),
    kind       TEXT    NOT NULL DEFAULT 'msg' CHECK (kind IN ('msg', 'system')),
    epoch      INTEGER NOT NULL DEFAULT 0,
    ciphertext TEXT    NOT NULL DEFAULT '',
    iv         TEXT    NOT NULL DEFAULT '',
    body       TEXT    NOT NULL DEFAULT '', -- plaintext JSON, system messages only
    created_at INTEGER NOT NULL
);
CREATE INDEX messages_chat ON messages(chat_id, id);

-- Per-user event log consumed by long polling.
CREATE TABLE updates (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    kind       TEXT    NOT NULL,
    payload    TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX updates_user ON updates(user_id, seq);
