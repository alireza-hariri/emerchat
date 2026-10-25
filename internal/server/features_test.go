package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"emerchat/internal/store"
)

// raw sends a non-JSON body and returns the status and response body.
func (c *client) raw(method, path string, body []byte) (int, []byte) {
	c.e.t.Helper()
	req, _ := http.NewRequest(method, c.e.ts.URL+path, bytes.NewReader(body))
	req.Header.Set("X-Emer", "1")
	req.Header.Set("Content-Type", "application/octet-stream")
	res, err := c.hc.Do(req)
	if err != nil {
		c.e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b
}

func (c *client) upload(chatID int64, data []byte) (string, int) {
	c.e.t.Helper()
	var res struct{ File struct{ ID string } }
	code, body := c.raw("POST", fmt.Sprintf("/api/chats/%d/files", chatID), data)
	if code == http.StatusCreated {
		if err := json.Unmarshal(body, &res); err != nil {
			c.e.t.Fatal(err)
		}
	}
	return res.File.ID, code
}

func (c *client) group(title string, members ...*client) store.Chat {
	c.e.t.Helper()
	ids := []int64{c.user.ID}
	var others []int64
	for _, m := range members {
		ids = append(ids, m.user.ID)
		others = append(others, m.user.ID)
	}
	var res struct{ Chat store.Chat }
	c.mustDo("POST", "/api/chats", createChatReq{Title: title, MemberIDs: others, Keys: keysFor(0, ids...)}, &res, http.StatusOK)
	return res.Chat
}

func TestEditMessage(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	bob := alice.invite("bob")
	chat := alice.direct(bob.user.ID)
	m, _ := alice.send(chat.ID, 0)
	path := fmt.Sprintf("/api/chats/%d/messages/%d", chat.ID, m.ID)
	body := map[string]string{"ciphertext": b64(50), "iv": b64(12)}

	bob.mustDo("PATCH", path, body, nil, http.StatusForbidden)
	alice.invite("carol").mustDo("PATCH", path, body, nil, http.StatusNotFound)

	after := bob.cursor()
	var res struct{ Message store.Message }
	alice.mustDo("PATCH", path, body, &res, http.StatusOK)
	if res.Message.EditedAt == 0 || res.Message.Ciphertext != body["ciphertext"] || res.Message.Epoch != m.Epoch {
		t.Fatalf("edited: %+v", res.Message)
	}
	up := bob.poll(after, 1)
	if len(up.Updates) != 1 || up.Updates[0].Kind != "edit" {
		t.Fatalf("bob updates: %+v", up.Updates)
	}
	var page struct{ Messages []store.Message }
	bob.mustDo("GET", fmt.Sprintf("/api/chats/%d/messages", chat.ID), nil, &page, http.StatusOK)
	if got := page.Messages[0]; got.Ciphertext != body["ciphertext"] || got.EditedAt == 0 {
		t.Fatalf("stored: %+v", got)
	}
}

func TestAttachments(t *testing.T) {
	e := newEnv(t, Config{MaxUpload: 1000})
	alice := e.register(e.adminInvite(), "alice")
	bob := alice.invite("bob")
	carol := alice.invite("carol")
	chat := alice.direct(bob.user.ID)

	data := bytes.Repeat([]byte{7}, 600)
	if _, code := carol.upload(chat.ID, data); code != http.StatusNotFound {
		t.Fatalf("non-member upload: %d", code)
	}
	if _, code := alice.upload(chat.ID, make([]byte, 1001)); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload: %d", code)
	}
	if _, code := alice.upload(chat.ID, nil); code != http.StatusBadRequest {
		t.Fatalf("empty upload: %d", code)
	}
	id, code := alice.upload(chat.ID, data)
	if code != http.StatusCreated {
		t.Fatalf("upload: %d", code)
	}
	if code, got := bob.raw("GET", "/api/files/"+id, nil); code != http.StatusOK || !bytes.Equal(got, data) {
		t.Fatalf("bob download: %d (%d bytes)", code, len(got))
	}
	if code, _ := carol.raw("GET", "/api/files/"+id, nil); code != http.StatusNotFound {
		t.Fatalf("carol download: %d", code)
	}
	if code, _ := bob.raw("GET", "/api/files/..%2Fsecret", nil); code != http.StatusNotFound {
		t.Fatalf("bad id: %d", code)
	}

	send := func(cl *client, ids ...string) int {
		return cl.do("POST", fmt.Sprintf("/api/chats/%d/messages", chat.ID),
			sendReq{Ciphertext: b64(40), IV: b64(12), FileIDs: ids}, nil)
	}
	if code := send(bob, id); code != http.StatusBadRequest {
		t.Fatalf("claiming someone else's upload: %d", code)
	}
	if code := send(alice, id); code != http.StatusCreated {
		t.Fatalf("send with file: %d", code)
	}
	if code := send(alice, id); code != http.StatusBadRequest {
		t.Fatalf("claiming twice: %d", code)
	}

	// Unclaimed uploads are pruned with their bytes; claimed ones stay.
	orphan, _ := alice.upload(chat.ID, data)
	e.srv.now = func() time.Time { return time.Now().Add(orphanTTL + time.Hour) }
	e.srv.pruneFiles(context.Background(), e.srv.now())
	if _, err := os.Stat(filepath.Join(e.srv.cfg.FilesDir, orphan)); !os.IsNotExist(err) {
		t.Fatalf("orphan still on disk: %v", err)
	}
	if code, _ := alice.raw("GET", "/api/files/"+orphan, nil); code != http.StatusNotFound {
		t.Fatalf("orphan download: %d", code)
	}
	if code, _ := bob.raw("GET", "/api/files/"+id, nil); code != http.StatusOK {
		t.Fatalf("claimed file after prune: %d", code)
	}
}

func TestProfileUpdates(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	bob := alice.invite("bob")
	alice.direct(bob.user.ID)

	alice.mustDo("PATCH", "/api/me", map[string]string{"displayName": "  "}, nil, http.StatusBadRequest)
	after := bob.cursor()
	var res struct{ User store.User }
	alice.mustDo("PATCH", "/api/me", map[string]string{"displayName": "Alice A."}, &res, http.StatusOK)
	if res.User.DisplayName != "Alice A." {
		t.Fatalf("renamed: %+v", res.User)
	}
	up := bob.poll(after, 1)
	if len(up.Updates) != 1 || up.Updates[0].Kind != "user" {
		t.Fatalf("bob updates: %+v", up.Updates)
	}

	if code, _ := alice.raw("PUT", "/api/me/avatar", []byte("<svg onload=alert(1)>")); code != http.StatusBadRequest {
		t.Fatalf("svg avatar: %d", code)
	}
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 100)...)
	if code, _ := alice.raw("PUT", "/api/me/avatar", png); code != http.StatusOK {
		t.Fatalf("set avatar: %d", code)
	}
	var u struct{ User store.User }
	bob.mustDo("GET", fmt.Sprintf("/api/users/%d", alice.user.ID), nil, &u, http.StatusOK)
	if u.User.Avatar == "" {
		t.Fatal("avatar version not set")
	}
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/users/%d/avatar", e.ts.URL, alice.user.ID), nil)
	r, err := bob.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != http.StatusOK || r.Header.Get("Content-Type") != "image/png" || !bytes.Equal(got, png) {
		t.Fatalf("avatar: %d %q", r.StatusCode, r.Header.Get("Content-Type"))
	}
	alice.mustDo("DELETE", "/api/me/avatar", nil, &res, http.StatusOK)
	if res.User.Avatar != "" {
		t.Fatal("avatar not removed")
	}
	if code, _ := bob.raw("GET", fmt.Sprintf("/api/users/%d/avatar", alice.user.ID), nil); code != http.StatusNotFound {
		t.Fatalf("removed avatar: %d", code)
	}
}

func TestGroupInviteLink(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	bob := alice.invite("bob")
	carol := alice.invite("carol")
	g := alice.group("Team", bob)
	path := fmt.Sprintf("/api/chats/%d", g.ID)

	direct := alice.direct(bob.user.ID)
	alice.mustDo("POST", fmt.Sprintf("/api/chats/%d/link", direct.ID), nil, nil, http.StatusBadRequest)
	carol.mustDo("POST", path+"/link", nil, nil, http.StatusNotFound)

	var link struct{ Code string }
	bob.mustDo("POST", path+"/link", nil, &link, http.StatusOK)
	var again struct{ Code string }
	alice.mustDo("POST", path+"/link", nil, &again, http.StatusOK)
	if link.Code == "" || again.Code != link.Code {
		t.Fatalf("link not stable: %q vs %q", link.Code, again.Code)
	}

	var preview struct {
		Group     store.LinkPreview
		CanSignUp bool
	}
	e.client().mustDo("GET", "/api/join/"+link.Code, nil, &preview, http.StatusOK)
	if preview.Group.Title != "Team" || preview.Group.Members != 2 || !preview.CanSignUp {
		t.Fatalf("preview: %+v", preview)
	}
	e.client().mustDo("GET", "/api/join/nope", nil, nil, http.StatusNotFound)

	// An existing user joins; the epoch is bumped so the old key stays private.
	var res struct{ Chat store.Chat }
	carol.mustDo("POST", "/api/join/"+link.Code, nil, &res, http.StatusOK)
	if len(res.Chat.Members) != 3 || res.Chat.KeyEpoch != 1 {
		t.Fatalf("after join: members %d epoch %d", len(res.Chat.Members), res.Chat.KeyEpoch)
	}
	carol.mustDo("POST", "/api/join/"+link.Code, nil, &res, http.StatusOK) // idempotent
	if len(res.Chat.Members) != 3 || res.Chat.KeyEpoch != 1 {
		t.Fatalf("second join changed the group: %+v", res.Chat)
	}
	var keys struct{ Keys []store.WrappedKey }
	carol.mustDo("GET", path+"/keys", nil, &keys, http.StatusOK)
	if len(keys.Keys) != 0 {
		t.Fatalf("joiner got old keys: %+v", keys.Keys)
	}
	if code := carol.do("POST", path+"/rekey", map[string]any{"epoch": 1, "keys": keysFor(1, alice.user.ID, bob.user.ID, carol.user.ID)}, nil); code != http.StatusNoContent {
		t.Fatalf("joiner rekey: %d", code)
	}

	// A new visitor signs up through the link and lands in the group.
	c := e.client()
	body := registerBody("", "dave")
	body.GroupInvite = link.Code
	var reg struct {
		User   store.User
		ChatID int64
	}
	c.mustDo("POST", "/api/register", body, &reg, http.StatusCreated)
	if reg.ChatID != g.ID {
		t.Fatalf("register chatId %d, want %d", reg.ChatID, g.ID)
	}
	c.mustDo("GET", path, nil, &res, http.StatusOK)
	if len(res.Chat.Members) != 4 || res.Chat.KeyEpoch != 2 {
		t.Fatalf("after signup: members %d epoch %d", len(res.Chat.Members), res.Chat.KeyEpoch)
	}

	// Only the owner revokes; afterwards the link is dead.
	bob.mustDo("DELETE", path+"/link", nil, nil, http.StatusForbidden)
	alice.mustDo("DELETE", path+"/link", nil, nil, http.StatusNoContent)
	e.client().mustDo("GET", "/api/join/"+link.Code, nil, nil, http.StatusNotFound)
	alice.invite("erin").mustDo("POST", "/api/join/"+link.Code, nil, nil, http.StatusNotFound)
	var fresh struct{ Chat store.Chat }
	bob.mustDo("GET", path, nil, &fresh, http.StatusOK)
	if fresh.Chat.InviteCode != "" {
		t.Fatal("revoked code still visible")
	}
}

func TestGroupLinkSignupRespectsInvitePolicy(t *testing.T) {
	e := newEnv(t, Config{InvitePolicy: "admins"})
	admin := e.register(e.adminInvite(), "admin")
	var inv struct{ Invite store.Invite }
	admin.mustDo("POST", "/api/invites", struct{}{}, &inv, http.StatusCreated)
	bob := e.register(inv.Invite.Code, "bob")
	g := bob.group("Bob's", admin)

	var link struct{ Code string }
	bob.mustDo("POST", fmt.Sprintf("/api/chats/%d/link", g.ID), nil, &link, http.StatusOK)
	var preview struct{ CanSignUp bool }
	e.client().mustDo("GET", "/api/join/"+link.Code, nil, &preview, http.StatusOK)
	if preview.CanSignUp {
		t.Fatal("non-admin link offers sign-up under admins policy")
	}
	body := registerBody("", "mallory")
	body.GroupInvite = link.Code
	e.client().mustDo("POST", "/api/register", body, nil, http.StatusForbidden)

	// Re-created by the admin, the link works for sign-ups.
	admin.mustDo("DELETE", fmt.Sprintf("/api/chats/%d/link", g.ID), nil, nil, http.StatusForbidden) // bob owns it
	bob.mustDo("DELETE", fmt.Sprintf("/api/chats/%d/link", g.ID), nil, nil, http.StatusNoContent)
	admin.mustDo("POST", fmt.Sprintf("/api/chats/%d/link", g.ID), nil, &link, http.StatusOK)
	body.GroupInvite = link.Code
	e.client().mustDo("POST", "/api/register", body, nil, http.StatusCreated)
}

func TestGroupTitleAndPhoto(t *testing.T) {
	e := newEnv(t, Config{})
	alice := e.register(e.adminInvite(), "alice")
	bob := alice.invite("bob")
	carol := alice.invite("carol")
	g := alice.group("Team", bob)
	path := fmt.Sprintf("/api/chats/%d", g.ID)

	bob.mustDo("PATCH", path, map[string]string{"title": " "}, nil, http.StatusBadRequest)
	carol.mustDo("PATCH", path, map[string]string{"title": "Hijacked"}, nil, http.StatusNotFound)
	direct := alice.direct(bob.user.ID)
	alice.mustDo("PATCH", fmt.Sprintf("/api/chats/%d", direct.ID), map[string]string{"title": "x"}, nil, http.StatusBadRequest)

	after := alice.cursor()
	var res struct{ Chat store.Chat }
	bob.mustDo("PATCH", path, map[string]string{"title": "Dream Team"}, &res, http.StatusOK)
	if res.Chat.Title != "Dream Team" {
		t.Fatalf("title: %q", res.Chat.Title)
	}
	up := alice.poll(after, 1)
	if len(up.Updates) != 2 || up.Updates[0].Kind != "chat" || up.Updates[1].Kind != "message" {
		t.Fatalf("alice updates: %+v", up.Updates)
	}

	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 100)...)
	if code, _ := carol.raw("PUT", path+"/photo", png); code != http.StatusNotFound {
		t.Fatalf("non-member photo: %d", code)
	}
	if code, _ := bob.raw("PUT", path+"/photo", []byte("<html>")); code != http.StatusBadRequest {
		t.Fatalf("html photo: %d", code)
	}
	if code, _ := bob.raw("PUT", path+"/photo", png); code != http.StatusOK {
		t.Fatalf("set photo: %d", code)
	}
	alice.mustDo("GET", path, nil, &res, http.StatusOK)
	if res.Chat.Photo == "" {
		t.Fatal("photo version not set")
	}
	if code, got := alice.raw("GET", path+"/photo", nil); code != http.StatusOK || !bytes.Equal(got, png) {
		t.Fatalf("get photo: %d", code)
	}
	if code, _ := carol.raw("GET", path+"/photo", nil); code != http.StatusNotFound {
		t.Fatalf("non-member get photo: %d", code)
	}
	var cleared struct{ Chat store.Chat }
	alice.mustDo("DELETE", path+"/photo", nil, &cleared, http.StatusOK)
	if cleared.Chat.Photo != "" {
		t.Fatal("photo not removed")
	}
	if code, _ := alice.raw("GET", path+"/photo", nil); code != http.StatusNotFound {
		t.Fatalf("removed photo: %d", code)
	}
}
