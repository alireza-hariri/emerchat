package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"emerchat/internal/store"
)

const maxCiphertext = 64 << 10

func (s *Server) handleSearchUsers(w http.ResponseWriter, r *http.Request, u store.User) {
	q := strings.TrimPrefix(strings.TrimSpace(r.URL.Query().Get("q")), "@")
	if q == "" {
		writeJSON(w, http.StatusOK, map[string]any{"users": []store.User{}})
		return
	}
	users, err := s.st.SearchUsers(r.Context(), q, 20)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request, _ store.User) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	u, err := s.st.User(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

func (s *Server) handleChats(w http.ResponseWriter, r *http.Request, u store.User) {
	// Read the cursor first: anything that lands while we load chats is
	// redelivered by the next poll, and the client applies updates idempotently.
	seq, err := s.st.Cursor(r.Context(), u.ID)
	if err != nil {
		storeError(w, err)
		return
	}
	chats, err := s.st.Chats(r.Context(), u.ID)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"chats": chats, "seq": seq})
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	c, err := s.st.Chat(r.Context(), id, u.ID)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"chat": c})
}

type createChatReq struct {
	// Direct chat.
	PeerID int64 `json:"peerId"`
	// Group chat.
	Title     string             `json:"title"`
	MemberIDs []int64            `json:"memberIds"`
	Keys      []store.WrappedKey `json:"keys"`
}

func validKeys(keys []store.WrappedKey) bool {
	for _, k := range keys {
		if _, ok := decodeB64(k.WrappedKey, 32, 128); !ok {
			return false
		}
		if _, ok := decodeB64(k.IV, 12, 12); !ok {
			return false
		}
	}
	return true
}

func (s *Server) handleCreateChat(w http.ResponseWriter, r *http.Request, u store.User) {
	var req createChatReq
	if !readJSON(w, r, &req) {
		return
	}
	var (
		id     int64
		notify []int64
		err    error
	)
	if req.PeerID != 0 {
		id, notify, err = s.st.DirectChat(r.Context(), u.ID, req.PeerID, s.nowMs())
	} else {
		req.Title = strings.TrimSpace(req.Title)
		switch {
		case req.Title == "" || utf8.RuneCountInString(req.Title) > 128:
			httpError(w, http.StatusBadRequest, "group title must be 1-128 characters")
			return
		case len(req.MemberIDs) > 200:
			httpError(w, http.StatusBadRequest, "too many members")
			return
		case !validKeys(req.Keys):
			httpError(w, http.StatusBadRequest, "malformed key material")
			return
		}
		id, notify, err = s.st.CreateGroup(r.Context(), u.ID, req.Title, req.MemberIDs, req.Keys, s.nowMs())
	}
	if err != nil {
		storeError(w, err)
		return
	}
	s.hub.Notify(notify...)
	c, err := s.st.Chat(r.Context(), id, u.ID)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"chat": c})
}

func (s *Server) handleMessages(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	msgs, err := s.st.Messages(r.Context(), id, u.ID, before, limit)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": msgs, "hasMore": len(msgs) == limit})
}

type sendReq struct {
	Ciphertext string   `json:"ciphertext"`
	IV         string   `json:"iv"`
	Epoch      int64    `json:"epoch"`
	ClientID   string   `json:"clientId"`
	FileIDs    []string `json:"fileIds"`
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var req sendReq
	if !readJSON(w, r, &req) {
		return
	}
	_, okCT := decodeB64(req.Ciphertext, 17, maxCiphertext)
	_, okIV := decodeB64(req.IV, 12, 12)
	if !okCT || !okIV || len(req.ClientID) > 64 || len(req.FileIDs) > 10 {
		httpError(w, http.StatusBadRequest, "malformed message")
		return
	}
	m, notify, err := s.st.SendMessage(r.Context(), id, u.ID, req.Epoch, req.Ciphertext, req.IV, req.ClientID, req.FileIDs, s.nowMs())
	if err != nil {
		storeError(w, err)
		return
	}
	s.hub.Notify(notify...)
	writeJSON(w, http.StatusCreated, map[string]any{"message": m})
}

func (s *Server) handleEdit(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	mid, ok := pathID(w, r, "mid")
	if !ok {
		return
	}
	var req struct {
		Ciphertext string `json:"ciphertext"`
		IV         string `json:"iv"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	_, okCT := decodeB64(req.Ciphertext, 17, maxCiphertext)
	_, okIV := decodeB64(req.IV, 12, 12)
	if !okCT || !okIV {
		httpError(w, http.StatusBadRequest, "malformed message")
		return
	}
	m, notify, err := s.st.EditMessage(r.Context(), id, mid, u.ID, req.Ciphertext, req.IV, s.nowMs())
	if err != nil {
		storeError(w, err)
		return
	}
	s.hub.Notify(notify...)
	writeJSON(w, http.StatusOK, map[string]any{"message": m})
}

func (s *Server) handleRead(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		UpTo int64 `json:"upTo"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	notify, err := s.st.MarkRead(r.Context(), id, u.ID, req.UpTo, s.nowMs())
	if err != nil {
		storeError(w, err)
		return
	}
	s.hub.Notify(notify...)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	keys, err := s.st.Keys(r.Context(), id, u.ID)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (s *Server) handleAddMember(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var req store.WrappedKey
	if !readJSON(w, r, &req) {
		return
	}
	if !validKeys([]store.WrappedKey{req}) {
		httpError(w, http.StatusBadRequest, "malformed key material")
		return
	}
	notify, err := s.st.AddMember(r.Context(), id, u.ID, req.UserID, req, s.nowMs())
	if err != nil {
		storeError(w, err)
		return
	}
	s.hub.Notify(notify...)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	uid, ok := pathID(w, r, "uid")
	if !ok {
		return
	}
	notify, err := s.st.RemoveMember(r.Context(), id, u.ID, uid, s.nowMs())
	if err != nil {
		storeError(w, err)
		return
	}
	s.hub.Notify(notify...)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRekey(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Epoch int64              `json:"epoch"`
		Keys  []store.WrappedKey `json:"keys"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !validKeys(req.Keys) {
		httpError(w, http.StatusBadRequest, "malformed key material")
		return
	}
	notify, err := s.st.Rekey(r.Context(), id, u.ID, req.Epoch, req.Keys, s.nowMs())
	if err != nil {
		storeError(w, err)
		return
	}
	s.hub.Notify(notify...)
	w.WriteHeader(http.StatusNoContent)
}

// handleInviteLink returns the group's reusable invite link code, creating
// it on first use.
func (s *Server) handleInviteLink(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	code, notify, err := s.st.InviteLink(r.Context(), id, u.ID, NewInviteCode(), s.nowMs())
	if err != nil {
		storeError(w, err)
		return
	}
	s.hub.Notify(notify...)
	writeJSON(w, http.StatusOK, map[string]string{"code": code})
}

func (s *Server) handleRevokeInviteLink(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	notify, err := s.st.RevokeInviteLink(r.Context(), id, u.ID, s.nowMs())
	if err != nil {
		storeError(w, err)
		return
	}
	s.hub.Notify(notify...)
	w.WriteHeader(http.StatusNoContent)
}

// handleLinkPreview shows the group name behind an invite link, also to
// visitors who still have to sign up.
func (s *Server) handleLinkPreview(w http.ResponseWriter, r *http.Request) {
	if !s.linkLim.allow("ip:"+s.clientIP(r), s.now()) {
		httpError(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}
	p, err := s.st.LinkPreview(r.Context(), r.PathValue("code"))
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"group": p, "canSignUp": s.cfg.InvitePolicy == "all" || p.ByAdmin})
}

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request, u store.User) {
	id, notify, err := s.st.JoinByLink(r.Context(), r.PathValue("code"), u.ID, s.nowMs())
	if err != nil {
		storeError(w, err)
		return
	}
	s.hub.Notify(notify...)
	c, err := s.st.Chat(r.Context(), id, u.ID)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"chat": c})
}

// handleUpdates is the long poll: it returns as soon as the user has updates
// with seq > after, or an empty list after timeout seconds.
func (s *Server) handleUpdates(w http.ResponseWriter, r *http.Request, u store.User) {
	ctx := r.Context()
	q := r.URL.Query()
	after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
	timeout := s.cfg.PollTimeout
	if t, err := strconv.Atoi(q.Get("timeout")); err == nil && t >= 0 && time.Duration(t)*time.Second < timeout {
		timeout = time.Duration(t) * time.Second
	}

	if err := s.st.TouchLastSeen(ctx, u.ID, s.nowMs()); err != nil {
		storeError(w, err)
		return
	}
	pruned, err := s.st.PrunedThrough(ctx)
	if err != nil {
		storeError(w, err)
		return
	}
	if after < pruned {
		writeJSON(w, http.StatusOK, map[string]any{"updates": []store.Update{}, "seq": after, "resync": true})
		return
	}

	wake := s.hub.Wait(u.ID) // before querying, so a concurrent commit can't be missed
	ups, err := s.st.Updates(ctx, u.ID, after, 200)
	if err != nil {
		storeError(w, err)
		return
	}
	if len(ups) == 0 && timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		select {
		case <-wake:
			if ups, err = s.st.Updates(ctx, u.ID, after, 200); err != nil {
				storeError(w, err)
				return
			}
		case <-t.C:
		case <-ctx.Done():
			return
		}
	}
	seq := after
	if len(ups) > 0 {
		seq = ups[len(ups)-1].Seq
	}
	writeJSON(w, http.StatusOK, map[string]any{"updates": ups, "seq": seq})
}
