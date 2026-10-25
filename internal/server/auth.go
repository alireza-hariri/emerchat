package server

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"emerchat/internal/store"
)

const cookieName = "emer_session"

// Argon2id parameters. authKey is already the output of a 600k-round
// PBKDF2 on the client, so this mainly protects against a leaked DB.
var argonTime, argonMemory, argonThreads uint32 = 1, 19 * 1024, 1

var usernameRe = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)

func hashAuthKey(authKey, salt []byte) []byte {
	return argon2.IDKey(authKey, salt, argonTime, argonMemory, uint8(argonThreads), 32)
}

func randomToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// decodeB64 decodes standard base64 and checks the length bounds.
func decodeB64(s string, minLen, maxLen int) ([]byte, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	return b, err == nil && len(b) >= minLen && len(b) <= maxLen
}

func validPublicKey(s string) bool {
	b, ok := decodeB64(s, 65, 65)
	if !ok {
		return false
	}
	_, err := ecdh.P256().NewPublicKey(b)
	return err == nil
}

// fakeSalt gives unknown usernames a stable salt so prelogin doesn't reveal
// which usernames exist.
func (s *Server) fakeSalt(username string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte("kdf-salt:" + username))
	return base64.StdEncoding.EncodeToString(m.Sum(nil)[:16])
}

func normUsername(u string) string { return strings.ToLower(strings.TrimSpace(u)) }

func (s *Server) handlePrelogin(w http.ResponseWriter, r *http.Request) {
	if !s.authLim.allow("ip:"+s.clientIP(r), s.now()) {
		httpError(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}
	username := normUsername(r.URL.Query().Get("u"))
	c, err := s.st.Credentials(r.Context(), username)
	salt := c.KDFSalt
	if errors.Is(err, store.ErrNotFound) {
		salt = s.fakeSalt(username)
	} else if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"kdfSalt": salt})
}

type registerReq struct {
	Invite            string `json:"invite"`
	GroupInvite       string `json:"groupInvite"` // a group's invite link instead of a personal invite
	Username          string `json:"username"`
	DisplayName       string `json:"displayName"`
	AuthKey           string `json:"authKey"`
	KDFSalt           string `json:"kdfSalt"`
	PublicKey         string `json:"publicKey"`
	WrappedPrivateKey string `json:"wrappedPrivateKey"`
	WrapIV            string `json:"wrapIv"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.authLim.allow("ip:"+s.clientIP(r), s.now()) {
		httpError(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}
	var req registerReq
	if !readJSON(w, r, &req) {
		return
	}
	req.Username = normUsername(req.Username)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if req.DisplayName == "" {
		req.DisplayName = req.Username
	}
	authKey, okAuth := decodeB64(req.AuthKey, 32, 32)
	_, okSalt := decodeB64(req.KDFSalt, 16, 16)
	_, okWrapped := decodeB64(req.WrappedPrivateKey, 32, 1024)
	_, okIV := decodeB64(req.WrapIV, 12, 12)
	switch {
	case !usernameRe.MatchString(req.Username):
		httpError(w, http.StatusBadRequest, "username must be 3-32 characters: a-z, 0-9, _")
	case utf8.RuneCountInString(req.DisplayName) > 64:
		httpError(w, http.StatusBadRequest, "display name too long")
	case !okAuth || !okSalt || !okWrapped || !okIV:
		httpError(w, http.StatusBadRequest, "malformed key material")
	case !validPublicKey(req.PublicKey):
		httpError(w, http.StatusBadRequest, "invalid public key")
	default:
		salt := make([]byte, 16)
		rand.Read(salt)
		nu := store.NewUser{
			Username:          req.Username,
			DisplayName:       req.DisplayName,
			AuthHash:          hashAuthKey(authKey, salt),
			AuthSalt:          salt,
			KDFSalt:           req.KDFSalt,
			PublicKey:         req.PublicKey,
			WrappedPrivateKey: req.WrappedPrivateKey,
			WrapIV:            req.WrapIV,
		}
		var (
			u      store.User
			chatID int64
			notify []int64
			err    error
		)
		if req.GroupInvite != "" {
			u, chatID, notify, err = s.st.RegisterViaLink(r.Context(), req.GroupInvite, nu, s.cfg.InvitePolicy == "admins", s.nowMs())
		} else {
			u, err = s.st.Register(r.Context(), req.Invite, nu, s.nowMs())
		}
		switch {
		case errors.Is(err, store.ErrNotFound):
			httpError(w, http.StatusForbidden, "invite is invalid, used or expired")
		case errors.Is(err, store.ErrForbidden):
			httpError(w, http.StatusForbidden, "this group link can't be used to create accounts; ask for a personal invite")
		case errors.Is(err, store.ErrConflict):
			httpError(w, http.StatusConflict, "username is taken")
		case err != nil:
			storeError(w, err)
		default:
			s.hub.Notify(notify...)
			if s.startSession(w, r, u.ID) {
				writeJSON(w, http.StatusCreated, map[string]any{"user": u, "chatId": chatID})
			}
		}
	}
}

type loginReq struct {
	Username string `json:"username"`
	AuthKey  string `json:"authKey"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if !readJSON(w, r, &req) {
		return
	}
	username := normUsername(req.Username)
	now := s.now()
	if !s.authLim.allow("ip:"+s.clientIP(r), now) || !s.authLim.allow("user:"+username, now) {
		httpError(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}
	authKey, ok := decodeB64(req.AuthKey, 32, 32)
	if !ok {
		httpError(w, http.StatusBadRequest, "malformed authKey")
		return
	}
	c, err := s.st.Credentials(r.Context(), username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		storeError(w, err)
		return
	}
	if c.AuthSalt == nil {
		// Unknown user: burn the same time as a real check.
		c.AuthSalt, c.AuthHash = make([]byte, 16), make([]byte, 32)
	}
	if subtle.ConstantTimeCompare(hashAuthKey(authKey, c.AuthSalt), c.AuthHash) != 1 || err != nil {
		httpError(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	if s.startSession(w, r, c.User.ID) {
		writeJSON(w, http.StatusOK, map[string]any{
			"user":              c.User,
			"wrappedPrivateKey": c.WrappedPrivateKey,
			"wrapIv":            c.WrapIV,
		})
	}
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, uid int64) bool {
	token := randomToken(32)
	exp := s.now().Add(s.cfg.SessionTTL)
	if err := s.st.CreateSession(r.Context(), tokenHash(token), uid, exp.UnixMilli()); err != nil {
		storeError(w, err)
		return false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   s.isSecure(r),
		SameSite: http.SameSiteStrictMode,
	})
	return true
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.st.DeleteSession(r.Context(), tokenHash(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: s.isSecure(r), SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

type authedHandler func(http.ResponseWriter, *http.Request, store.User)

func (s *Server) authed(h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			httpError(w, http.StatusUnauthorized, "not logged in")
			return
		}
		u, err := s.st.SessionUser(r.Context(), tokenHash(c.Value), s.nowMs())
		if errors.Is(err, store.ErrNotFound) {
			httpError(w, http.StatusUnauthorized, "not logged in")
			return
		}
		if err != nil {
			storeError(w, err)
			return
		}
		h(w, r, u)
	}
}

func (s *Server) canInvite(u store.User) bool {
	return u.IsAdmin || s.cfg.InvitePolicy == "all"
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, u store.User) {
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "canInvite": s.canInvite(u), "maxUpload": s.cfg.MaxUpload})
}

func (s *Server) handleListInvites(w http.ResponseWriter, r *http.Request, u store.User) {
	invs, err := s.st.Invites(r.Context(), u.ID)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": invs})
}

func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request, u store.User) {
	if !s.canInvite(u) {
		httpError(w, http.StatusForbidden, "only admins can create invites")
		return
	}
	now := s.now()
	inv, err := s.st.CreateInvite(r.Context(), NewInviteCode(), u.ID, false, now.Add(s.cfg.InviteTTL).UnixMilli(), now.UnixMilli())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"invite": inv})
}

func (s *Server) handleRevokeInvite(w http.ResponseWriter, r *http.Request, u store.User) {
	if err := s.st.RevokeInvite(r.Context(), r.PathValue("code"), u.ID); err != nil {
		storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// NewInviteCode returns a 128-bit random URL-safe code.
func NewInviteCode() string { return randomToken(16) }
