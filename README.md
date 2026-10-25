# emerchat

A small invite-only, end-to-end encrypted chat with a Telegram-style web UI.
Go + SQLite on the server, plain JavaScript and Web Crypto in the browser.
It builds to one binary with no build step.

## Run

```sh
go build -o emerchat ./cmd/emerchat
./emerchat -addr :8080 -db emerchat.db -base-url http://localhost:8080
```

Every start prints a fresh single-use invite link (valid 7 days). On first run,
while there are no users, that link makes its user an **admin**. After that the
start-up links are regular invites. Users can then invite others from
**Menu → Invite Friends**, or share a group's invite link (see below).

Attachments, voice messages and profile pictures are stored in the `files/`
folder next to where you start the server (change it with `-files`).

| Flag | Default | |
|---|---|---|
| `-addr` | `:8080` | listen address |
| `-db` | `emerchat.db` | SQLite file |
| `-files` | `files` | folder for encrypted attachments and profile pictures |
| `-max-upload-mb` | `50` | largest attachment |
| `-base-url` | `http://localhost:8080` | used when printing invite links |
| `-start-invite` | `true` | print an invite link on every start |
| `-invite-policy` | `all` | `all` users may invite, or only `admins` |
| `-trust-proxy` | `false` | honour `X-Forwarded-For` / `X-Forwarded-Proto` |
| `-secure-cookies` | `false` | always set `Secure` on the session cookie |
| `-new-admin-invite` | | print an admin invite and exit |
| `-backup PATH` | | write a consistent DB copy (`VACUUM INTO`) and exit |

For production see `deploy/` (systemd unit and an nginx config with long-poll
and upload settings). `deploy/install.sh` sets both up from a GitHub release
(tag `v*` to publish one):

```sh
curl -fsSL https://raw.githubusercontent.com/alireza-hariri/emerchat/main/deploy/install.sh \
  | sudo bash -s -- --domain chat.example.com --nginx
```

Run it again without flags to upgrade; it snapshots the database first. Back up the `files/` folder together with the database. Web Crypto requires a secure context, so serve it over HTTPS
(or use `localhost`).

## Test

```sh
go test -race ./...          # store, hub, HTTP API (incl. long polling, groups, rekey)
node --test web/test/*.test.mjs  # browser crypto module, run under Node's WebCrypto
```

## How it works

**Long polling.** Every event a user should see (new message, read receipt,
chat changed, removed from chat) is written to a per-user `updates` log with a
global `seq`, in the same transaction as the change. `GET /api/updates?after=SEQ`
returns at once if there is anything newer. Otherwise it parks for up to 25s
on an in-memory hub channel that is closed after the writer commits. The
handler grabs the channel *before* querying, so a wakeup can't be lost. Updates
older than 7 days are pruned. A client that is further behind gets `resync`
and reloads.

**Accounts and keys.** The password never leaves the browser:

```
master  = PBKDF2-SHA256(password, salt, 600k)
authKey = HKDF(master, "auth")  → sent at login; the server stores argon2id(authKey)
wrapKey = HKDF(master, "wrap")  → encrypts the P-256 identity private key (AES-GCM)
```

The server stores the public key and the *wrapped* private key, so any
device can log in. After unwrapping, the private key is kept as a
non-extractable `CryptoKey` in IndexedDB.

**Messages.** These use AES-256-GCM with a random IV. The additional data binds
chat id, sender id and key epoch, so the server can't move or re-attribute
ciphertexts.

- Direct chats: `HKDF(ECDH(me, peer), "direct/<chatId>")`.
- Groups: a random 32-byte key per *epoch*, wrapped for each member via
  pairwise ECDH. Removing or losing a member bumps the epoch. The first online
  member's client generates and distributes a new key (`/rekey`; the server
  takes the first one and answers 409 to the rest). New members get the
  current epoch's key only.

**Attachments and voice messages.** The browser encrypts each file with a
fresh AES-256-GCM key and uploads only ciphertext to `files/<random id>`. The
key, file name and type travel inside the encrypted message, so the server
sees only the size. Only members of the chat can download the ciphertext.
Uploads that no message claims within 24 hours are deleted.

**Editing.** Senders can edit their messages. The new text is encrypted under
the message's original key epoch, so exactly the same people can read it.
Other members see an "edited" label.

**Profiles.** Users can change their display name and profile picture from
**Menu → My Profile**. Profile pictures are *not* end-to-end encrypted; any
logged-in user can see them, just like display names.

**Group name and photo.** Any member can rename a group or change its photo
from the group's info panel. Each change shows up as a system message. Group
photos are only served to members, but like titles they are not end-to-end
encrypted.

**Group invite links.** Any group member can create the group's invite link.
It has no expiry and no usage limit, and only the owner can revoke it. Anyone
who opens the link and already has an account can join the group. Someone
without an account can sign up through it and becomes a member right away.
With `-invite-policy admins`, only links created by an admin allow sign-ups.
Joining bumps the key epoch with no key installed. The newcomer's own client
then generates a fresh group key for everyone, so newcomers can't read
earlier messages. Anyone holding the link can join, and so can the server,
which stores it. Each join shows up as a system message in the chat.

**Safety numbers.** Open a direct chat's info panel to see a 60-digit
fingerprint of both public keys. Compare it out of band to rule out a
key-substitution attack by the server.

**Known limits** (deliberately simple):

- No forward secrecy: a leaked identity key decrypts past direct messages.
- The server sees metadata: who talks to whom, when, and message and file sizes.
- Profile pictures, display names, group titles and group photos are visible to the server.
- The server delivers the JavaScript, so a compromised server could ship
  malicious code. This is inherent to web-based E2E.
- A forgotten password means a lost key and lost history; there is no recovery.

## Layout

```
cmd/emerchat/      main: flags, start-up invite, HTTP server, graceful shutdown
internal/store/    SQLite schema + queries (single writer, reader pool, WAL)
internal/hub/      long-poll wakeups
internal/server/   HTTP API, auth, rate limiting, security headers, janitor
files/             encrypted attachments (created at run time)
web/               embedded client: index.html, css/, js/ (api, crypto, keystore, dom, app)
web/test/          Node tests for the crypto module
deploy/            systemd + nginx examples
```
