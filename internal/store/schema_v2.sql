-- Profile pictures, message edits, group invite links and file attachments.

ALTER TABLE users ADD COLUMN avatar TEXT NOT NULL DEFAULT ''; -- version token, '' = none

ALTER TABLE messages ADD COLUMN edited_at INTEGER NOT NULL DEFAULT 0;

-- A group's reusable invite link. It has no expiry or use limit and stays
-- valid until the owner revokes it.
ALTER TABLE chats ADD COLUMN invite_code TEXT;
ALTER TABLE chats ADD COLUMN invite_by INTEGER REFERENCES users(id);
CREATE UNIQUE INDEX chats_invite_code ON chats(invite_code);

-- Encrypted attachments. The bytes live in the files directory under id;
-- the key is inside the (encrypted) message that references the file.
CREATE TABLE files (
    id         TEXT    PRIMARY KEY,
    chat_id    INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    uploader   INTEGER NOT NULL REFERENCES users(id),
    size       INTEGER NOT NULL,
    message_id INTEGER REFERENCES messages(id), -- NULL until a message claims it
    created_at INTEGER NOT NULL
);
CREATE INDEX files_unclaimed ON files(created_at) WHERE message_id IS NULL;
