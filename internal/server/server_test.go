package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"emerchat/internal/store"
)

func TestMain(m *testing.M) {
	argonMemory = 1024 // keep tests fast
	m.Run()
}

type env struct {
	t   *testing.T
	st  *store.Store
	srv *Server
	ts  *httptest.Server
}

func newEnv(t *testing.T, cfg Config) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if cfg.PollTimeout == 0 {
		cfg.PollTimeout = 5 * time.Second
	}
	if cfg.FilesDir == "" {
		cfg.FilesDir = t.TempDir()
	}
	srv, err := New(context.Background(), st, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return &env{t: t, st: st, srv: srv, ts: ts}
}

func (e *env) adminInvite() string {
	code := NewInviteCode()
	now := time.Now()
	if _, err := e.st.CreateInvite(context.Background(), code, 0, true, now.Add(time.Hour).UnixMilli(), now.UnixMilli()); err != nil {
		e.t.Fatal(err)
	}
	return code
}

type client struct {
	e       *env
	hc      *http.Client
	user    store.User
	authKey string
	noCSRF  bool
}

func (e *env) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{e: e, hc: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
}

// do sends a JSON request and decodes the response into out (if non-nil).
func (c *client) do(method, path string, body, out any) int {
	c.e.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, c.e.ts.URL+path, rd)
	if !c.noCSRF {
		req.Header.Set("X-Emer", "1")
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.hc.Do(req)
	if err != nil {
		c.e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	if out != nil && res.StatusCode < 300 && res.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(res.Body).Decode(out); err != nil {
			c.e.t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	}
	return res.StatusCode
}

func (c *client) mustDo(method, path string, body, out any, want int) {
	c.e.t.Helper()
	if got := c.do(method, path, body, out); got != want {
		c.e.t.Fatalf("%s %s: status %d, want %d", method, path, got, want)
	}
}

func b64(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func pubKey() string {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

func registerBody(invite, username string) registerReq {
	return registerReq{
		Invite: invite, Username: username, DisplayName: username,
		AuthKey: b64(32), KDFSalt: b64(16), PublicKey: pubKey(),
		WrappedPrivateKey: b64(150), WrapIV: b64(12),
	}
}

// register creates a logged-in user from an invite.
func (e *env) register(invite, username string) *client {
	e.t.Helper()
	c := e.client()
	body := registerBody(invite, username)
	var res struct{ User store.User }
	c.mustDo("POST", "/api/register", body, &res, http.StatusCreated)
	c.user, c.authKey = res.User, body.AuthKey
	return c
}

// invite has c create an invite and registers a new user with it.
func (c *client) invite(username string) *client {
	c.e.t.Helper()
	var res struct{ Invite store.Invite }
	c.mustDo("POST", "/api/invites", struct{}{}, &res, http.StatusCreated)
	return c.e.register(res.Invite.Code, username)
}

type updatesRes struct {
	Updates []store.Update
	Seq     int64
	Resync  bool
}

func (c *client) cursor() int64 {
	var res struct{ Seq int64 }
	c.mustDo("GET", "/api/chats", nil, &res, http.StatusOK)
	return res.Seq
}

func (c *client) poll(after int64, timeout int) updatesRes {
	var res updatesRes
	c.mustDo("GET", fmt.Sprintf("/api/updates?after=%d&timeout=%d", after, timeout), nil, &res, http.StatusOK)
	return res
}

func (c *client) direct(peer int64) store.Chat {
	var res struct{ Chat store.Chat }
	c.mustDo("POST", "/api/chats", map[string]int64{"peerId": peer}, &res, http.StatusOK)
	return res.Chat
}

func (c *client) send(chatID, epoch int64) (store.Message, int) {
	var res struct{ Message store.Message }
	code := c.do("POST", fmt.Sprintf("/api/chats/%d/messages", chatID),
		sendReq{Ciphertext: b64(40), IV: b64(12), Epoch: epoch, ClientID: "x"}, &res)
	return res.Message, code
}

func keysFor(epoch int64, uids ...int64) []store.WrappedKey {
	var ks []store.WrappedKey
	for _, id := range uids {
		ks = append(ks, store.WrappedKey{UserID: id, Epoch: epoch, WrappedKey: b64(48), IV: b64(12)})
	}
	return ks
}

// ---------- auth & invites ----------

func TestRegisterAndLogin(t *testing.T) {
	e := newEnv(t, Config{})
	invite := e.adminInvite()
	alice := e.register(invite, "Alice")
	if alice.user.Username != "alice" || !alice.user.IsAdmin {
		t.Fatalf("got %+v, want lowercase admin alice", alice.user)
	}

	// Invites are single use.
	if code := e.client().do("POST", "/api/register", registerBody(invite, "mallory"), nil); code != http.StatusForbidden {
		t.Fatalf("reused invite: status %d, want 403", code)
	}
	// Usernames are unique.
	var inv struct{ Invite store.Invite }
	alice.mustDo("POST", "/api/invites", struct{}{}, &inv, http.StatusCreated)
	if code := e.client().do("POST", "/api/register", registerBody(inv.Invite.Code, "alice"), nil); code != http.StatusConflict {
		t.Fatalf("duplicate username: status %d, want 409", code)
	}

	c := e.client()
	if code := c.do("POST", "/api/login", loginReq{Username: "alice", AuthKey: b64(32)}, nil); code != http.StatusUnauthorized {
		t.Fatalf("wrong key: status %d, want 401", code)
	}
	if code := c.do("POST", "/api/login", loginReq{Username: "nobody", AuthKey: b64(32)}, nil); code != http.StatusUnauthorized {
		t.Fatalf("unknown user: status %d, want 401", code)
	}
	var login struct {
		User              store.User
		WrappedPrivateKey string
		WrapIv            string
	}
	c.mustDo("POST", "/api/login", loginReq{Username: "ALICE", AuthKey: alice.authKey}, &login, http.StatusOK)
	if login.User.ID != alice.user.ID || login.WrappedPrivateKey == "" || login.WrapIv == "" {
		t.Fatalf("login response missing data: %+v", login)
	}
	c.mustDo("GET", "/api/me", nil, nil, http.StatusOK)
	c.mustDo("POST", "/api/logout", struct{}{}, nil, http.StatusNoContent)
	c.mustDo("GET", "/api/me", nil, nil, http.StatusUnauthorized)
}

func TestPreloginDoesNotRevealUsers(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	c := e.client()
	salt := func(u string) string {
		var res struct{ KdfSalt string }
		c.mustDo("GET", "/api/prelogin?u="+u, nil, &res, http.StatusOK)
		return res.KdfSalt
	}
	if s1, s2 := salt("ghost"), salt("ghost"); s1 != s2 || s1 == "" {
		t.Fatalf("fake salt not stable: %q vs %q", s1, s2)
	}
	if b, _ := base64.StdEncoding.DecodeString(salt("ghost")); len(b) != 16 {
		t.Fatalf("fake salt has %d bytes, want 16", len(b))
	}
	if salt("alice") == salt("ghost") {
		t.Fatal("real and fake salt collide")
	}
	_ = alice
}

func TestRegisterValidation(t *testing.T) {
	e := newEnv(t, Config{})
	invite := e.adminInvite()
	c := e.client()
	bad := registerBody(invite, "ab")
	c.mustDo("POST", "/api/register", bad, nil, http.StatusBadRequest)
	bad = registerBody(invite, "bob")
	bad.PublicKey = b64(65) // not a curve point
	c.mustDo("POST", "/api/register", bad, nil, http.StatusBadRequest)
	bad = registerBody(invite, "bob")
	bad.AuthKey = b64(16)
	c.mustDo("POST", "/api/register", bad, nil, http.StatusBadRequest)
	// The invite survives failed attempts.
	e.register(invite, "bob")
}

func TestInvitePolicyAdmins(t *testing.T) {
	e := newEnv(t, Config{InvitePolicy: "admins"})
	admin := e.register(e.adminInvite(), "admin")
	bob := admin.invite("bob")
	if bob.user.IsAdmin {
		t.Fatal("invited user should not be admin")
	}
	bob.mustDo("POST", "/api/invites", struct{}{}, nil, http.StatusForbidden)

	var list struct{ Invites []store.Invite }
	admin.mustDo("GET", "/api/invites", nil, &list, http.StatusOK)
	if len(list.Invites) != 1 || list.Invites[0].UsedBy == nil || list.Invites[0].UsedBy.Username != "bob" {
		t.Fatalf("invite list: %+v", list.Invites)
	}
}

func TestRevokeInvite(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	var res struct{ Invite store.Invite }
	alice.mustDo("POST", "/api/invites", struct{}{}, &res, http.StatusCreated)
	alice.mustDo("DELETE", "/api/invites/"+res.Invite.Code, nil, nil, http.StatusNoContent)
	e.client().mustDo("POST", "/api/register", registerBody(res.Invite.Code, "bob"), nil, http.StatusForbidden)
}

func TestCSRFHeaderRequired(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	alice.noCSRF = true
	alice.mustDo("POST", "/api/invites", struct{}{}, nil, http.StatusForbidden)
	alice.mustDo("GET", "/api/me", nil, nil, http.StatusOK)
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t, Config{})
	res, err := http.Get(e.ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.Header.Get("Content-Security-Policy") == "" || res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing security headers: %v", res.Header)
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t, Config{})
	e.register(e.adminInvite(), "alice")
	c := e.client()
	var last int
	for i := 0; i < 25; i++ {
		last = c.do("POST", "/api/login", loginReq{Username: "alice", AuthKey: b64(32)}, nil)
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("status %d after many failures, want 429", last)
	}
}

// ---------- chats & long polling ----------

func TestLongPollDeliversMessage(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	bob := alice.invite("bob")
	chat := alice.direct(bob.user.ID)
	if again := bob.direct(alice.user.ID); again.ID != chat.ID {
		t.Fatalf("direct chat not reused: %d vs %d", again.ID, chat.ID)
	}

	after := bob.cursor()
	got := make(chan updatesRes, 1)
	start := time.Now()
	go func() { got <- bob.poll(after, 10) }()

	time.Sleep(200 * time.Millisecond)
	sent, code := alice.send(chat.ID, 0)
	if code != http.StatusCreated {
		t.Fatalf("send: %d", code)
	}
	select {
	case res := <-got:
		elapsed := time.Since(start)
		if elapsed < 150*time.Millisecond {
			t.Fatalf("poll returned after %v, before the message was sent", elapsed)
		}
		if len(res.Updates) != 1 || res.Updates[0].Kind != "message" {
			t.Fatalf("updates: %+v", res.Updates)
		}
		var m store.Message
		json.Unmarshal(res.Updates[0].Data, &m)
		if m.ID != sent.ID || m.Ciphertext != sent.Ciphertext || res.Seq != res.Updates[0].Seq {
			t.Fatalf("got %+v seq %d, want message %d", m, res.Seq, sent.ID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("long poll did not wake up")
	}
}

func TestLongPollTimesOut(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	start := time.Now()
	res := alice.poll(alice.cursor(), 1)
	if d := time.Since(start); d < 900*time.Millisecond || d > 3*time.Second {
		t.Fatalf("poll took %v, want ~1s", d)
	}
	if len(res.Updates) != 0 {
		t.Fatalf("unexpected updates: %+v", res.Updates)
	}
}

func TestPollReturnsBacklogImmediately(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	bob := alice.invite("bob")
	after := bob.cursor()
	chat := alice.direct(bob.user.ID)
	for i := 0; i < 3; i++ {
		alice.send(chat.ID, 0)
	}
	start := time.Now()
	res := bob.poll(after, 10)
	if time.Since(start) > time.Second {
		t.Fatal("backlog poll blocked")
	}
	kinds := []string{}
	for _, u := range res.Updates {
		kinds = append(kinds, u.Kind)
	}
	if fmt.Sprint(kinds) != "[chat message message message]" {
		t.Fatalf("kinds = %v", kinds)
	}
	if again := bob.poll(res.Seq, 0); len(again.Updates) != 0 {
		t.Fatalf("updates redelivered: %+v", again.Updates)
	}
}

func TestNonMembersCannotAccessChat(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	bob := alice.invite("bob")
	carol := alice.invite("carol")
	chat := alice.direct(bob.user.ID)
	alice.send(chat.ID, 0)

	path := fmt.Sprintf("/api/chats/%d", chat.ID)
	carol.mustDo("GET", path, nil, nil, http.StatusNotFound)
	carol.mustDo("GET", path+"/messages", nil, nil, http.StatusNotFound)
	if _, code := carol.send(chat.ID, 0); code != http.StatusNotFound {
		t.Fatalf("outsider send: %d, want 404", code)
	}
	carol.mustDo("POST", path+"/read", map[string]int64{"upTo": 1}, nil, http.StatusNotFound)
	if res := carol.poll(0, 0); len(res.Updates) != 0 {
		t.Fatalf("outsider got updates: %+v", res.Updates)
	}
	e.client().mustDo("GET", "/api/chats", nil, nil, http.StatusUnauthorized)
}

func TestReadReceiptsAndUnread(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	bob := alice.invite("bob")
	chat := alice.direct(bob.user.ID)
	alice.send(chat.ID, 0)
	m2, _ := alice.send(chat.ID, 0)

	var c struct{ Chat store.Chat }
	bob.mustDo("GET", fmt.Sprintf("/api/chats/%d", chat.ID), nil, &c, http.StatusOK)
	if c.Chat.Unread != 2 {
		t.Fatalf("unread = %d, want 2", c.Chat.Unread)
	}

	after := alice.cursor()
	bob.mustDo("POST", fmt.Sprintf("/api/chats/%d/read", chat.ID), map[string]int64{"upTo": m2.ID}, nil, http.StatusNoContent)
	res := alice.poll(after, 2)
	if len(res.Updates) != 1 || res.Updates[0].Kind != "read" {
		t.Fatalf("updates: %+v", res.Updates)
	}
	bob.mustDo("GET", fmt.Sprintf("/api/chats/%d", chat.ID), nil, &c, http.StatusOK)
	if c.Chat.Unread != 0 {
		t.Fatalf("unread after read = %d", c.Chat.Unread)
	}
	// Marking past the newest message is ignored.
	bob.mustDo("POST", fmt.Sprintf("/api/chats/%d/read", chat.ID), map[string]int64{"upTo": m2.ID + 100}, nil, http.StatusNoContent)
	if res := alice.poll(res.Seq, 0); len(res.Updates) != 0 {
		t.Fatalf("bogus read produced updates: %+v", res.Updates)
	}
}

func TestSavedMessages(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	chat := alice.direct(alice.user.ID)
	if len(chat.Members) != 1 {
		t.Fatalf("saved messages members: %d", len(chat.Members))
	}
	if _, code := alice.send(chat.ID, 0); code != http.StatusCreated {
		t.Fatalf("send to self: %d", code)
	}
}

func TestMessagePagination(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	chat := alice.direct(alice.user.ID)
	for i := 0; i < 7; i++ {
		alice.send(chat.ID, 0)
	}
	var page struct {
		Messages []store.Message
		HasMore  bool
	}
	alice.mustDo("GET", fmt.Sprintf("/api/chats/%d/messages?limit=5", chat.ID), nil, &page, http.StatusOK)
	if len(page.Messages) != 5 || !page.HasMore || page.Messages[0].ID >= page.Messages[4].ID {
		t.Fatalf("first page: %d msgs, hasMore=%v", len(page.Messages), page.HasMore)
	}
	first := page.Messages[0].ID
	alice.mustDo("GET", fmt.Sprintf("/api/chats/%d/messages?limit=5&before=%d", chat.ID, first), nil, &page, http.StatusOK)
	if len(page.Messages) != 2 || page.HasMore || page.Messages[1].ID >= first {
		t.Fatalf("second page: %+v hasMore=%v", page.Messages, page.HasMore)
	}
}

func TestGroupKeysMembershipAndRekey(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	bob := alice.invite("bob")
	carol := alice.invite("carol")
	dave := alice.invite("dave")
	a, b, c := alice.user.ID, bob.user.ID, carol.user.ID

	create := createChatReq{Title: "Team", MemberIDs: []int64{b, c}, Keys: keysFor(0, a, b)}
	alice.mustDo("POST", "/api/chats", create, nil, http.StatusBadRequest) // carol's key missing
	create.Keys = keysFor(0, a, b, c)
	var res struct{ Chat store.Chat }
	alice.mustDo("POST", "/api/chats", create, &res, http.StatusOK)
	g := res.Chat
	if g.Kind != "group" || len(g.Members) != 3 || g.Members[0].Role != "owner" {
		t.Fatalf("group: %+v", g)
	}
	path := fmt.Sprintf("/api/chats/%d", g.ID)

	var keys struct{ Keys []store.WrappedKey }
	bob.mustDo("GET", path+"/keys", nil, &keys, http.StatusOK)
	if len(keys.Keys) != 1 || keys.Keys[0].WrappedBy != a || keys.Keys[0].WrappedByKey != alice.user.PublicKey {
		t.Fatalf("bob's keys: %+v", keys.Keys)
	}
	if _, code := bob.send(g.ID, 0); code != http.StatusCreated {
		t.Fatalf("send epoch 0: %d", code)
	}

	// Only the owner removes others.
	bob.mustDo("DELETE", fmt.Sprintf("%s/members/%d", path, c), nil, nil, http.StatusForbidden)
	carolAfter := carol.cursor()
	alice.mustDo("DELETE", fmt.Sprintf("%s/members/%d", path, c), nil, nil, http.StatusNoContent)
	if up := carol.poll(carolAfter, 1); len(up.Updates) != 1 || up.Updates[0].Kind != "removed" {
		t.Fatalf("carol updates: %+v", up.Updates)
	}
	carol.mustDo("GET", path+"/keys", nil, nil, http.StatusNotFound)

	// Epoch bumped; no key yet, so sending is refused at both epochs.
	bob.mustDo("GET", path, nil, &res, http.StatusOK)
	if res.Chat.KeyEpoch != 1 || len(res.Chat.Members) != 2 {
		t.Fatalf("after removal: epoch %d members %d", res.Chat.KeyEpoch, len(res.Chat.Members))
	}
	for _, ep := range []int64{0, 1} {
		if _, code := bob.send(g.ID, ep); code != http.StatusConflict {
			t.Fatalf("send epoch %d before rekey: %d, want 409", ep, code)
		}
	}

	rekey := func(cl *client, ks []store.WrappedKey) int {
		return cl.do("POST", path+"/rekey", map[string]any{"epoch": 1, "keys": ks}, nil)
	}
	if code := rekey(bob, keysFor(1, a, b, c)); code != http.StatusBadRequest {
		t.Fatalf("rekey including removed member: %d, want 400", code)
	}
	if code := rekey(bob, keysFor(1, a, b)); code != http.StatusNoContent {
		t.Fatalf("rekey: %d", code)
	}
	if code := rekey(alice, keysFor(1, a, b)); code != http.StatusConflict {
		t.Fatalf("second rekey: %d, want 409", code)
	}
	if _, code := alice.send(g.ID, 1); code != http.StatusCreated {
		t.Fatalf("send epoch 1: %d", code)
	}

	// Adding a member requires their key at the current epoch.
	add := keysFor(0, dave.user.ID)[0]
	bob.mustDo("POST", path+"/members", add, nil, http.StatusBadRequest)
	add.Epoch = 1
	bob.mustDo("POST", path+"/members", add, nil, http.StatusNoContent)
	bob.mustDo("POST", path+"/members", add, nil, http.StatusConflict)
	dave.mustDo("GET", path+"/keys", nil, &keys, http.StatusOK)
	if len(keys.Keys) != 1 || keys.Keys[0].Epoch != 1 || keys.Keys[0].WrappedBy != b {
		t.Fatalf("dave's keys: %+v", keys.Keys)
	}

	// When the owner leaves, the oldest remaining member takes over.
	alice.mustDo("DELETE", fmt.Sprintf("%s/members/%d", path, a), nil, nil, http.StatusNoContent)
	bob.mustDo("GET", path, nil, &res, http.StatusOK)
	if res.Chat.KeyEpoch != 2 || res.Chat.Members[0].ID != b || res.Chat.Members[0].Role != "owner" {
		t.Fatalf("after owner left: %+v", res.Chat)
	}
}

func TestResyncAfterPrune(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	chat := alice.direct(alice.user.ID)
	alice.send(chat.ID, 0)
	future := time.Now().Add(time.Hour).UnixMilli()
	if err := e.st.Prune(context.Background(), time.Now().UnixMilli(), future); err != nil {
		t.Fatal(err)
	}
	if res := alice.poll(0, 0); !res.Resync {
		t.Fatal("expected resync after prune")
	}
	cur := alice.cursor()
	if res := alice.poll(cur, 0); res.Resync {
		t.Fatal("fresh cursor still asks for resync")
	}
}

func TestOversizedBodyRejected(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	chat := alice.direct(alice.user.ID)
	big := sendReq{Ciphertext: b64(maxCiphertext + 10), IV: b64(12)}
	if code := alice.do("POST", fmt.Sprintf("/api/chats/%d/messages", chat.ID), big, nil); code != http.StatusBadRequest {
		t.Fatalf("oversized message: %d, want 400", code)
	}
}
