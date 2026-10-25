// Package server is the HTTP API and static file server.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"emerchat/internal/hub"
	"emerchat/internal/store"
)

type Config struct {
	// InvitePolicy is "all" (any user can invite) or "admins".
	InvitePolicy string
	// TrustProxy uses X-Forwarded-For / X-Forwarded-Proto from a reverse proxy.
	TrustProxy bool
	// SecureCookies forces the Secure flag even without TLS being detected.
	SecureCookies bool
	// FilesDir holds encrypted attachments and profile pictures.
	FilesDir string
	// MaxUpload caps the size of one (encrypted) attachment in bytes.
	MaxUpload   int64
	PollTimeout time.Duration
	SessionTTL  time.Duration
	InviteTTL   time.Duration
	UpdatesTTL  time.Duration
}

func (c *Config) defaults() {
	if c.InvitePolicy == "" {
		c.InvitePolicy = "all"
	}
	if c.FilesDir == "" {
		c.FilesDir = "files"
	}
	if c.MaxUpload == 0 {
		c.MaxUpload = 50 << 20
	}
	if c.PollTimeout == 0 {
		c.PollTimeout = 25 * time.Second
	}
	if c.SessionTTL == 0 {
		c.SessionTTL = 30 * 24 * time.Hour
	}
	if c.InviteTTL == 0 {
		c.InviteTTL = 7 * 24 * time.Hour
	}
	if c.UpdatesTTL == 0 {
		c.UpdatesTTL = 7 * 24 * time.Hour
	}
}

type Server struct {
	st      *store.Store
	hub     *hub.Hub
	cfg     Config
	secret  []byte
	static  fs.FS
	authLim *limiter
	linkLim *limiter
	now     func() time.Time
	handler http.Handler
}

const maxBody = 256 << 10

func New(ctx context.Context, st *store.Store, static fs.FS, cfg Config) (*Server, error) {
	cfg.defaults()
	for _, dir := range []string{"avatars", "groups"} {
		if err := os.MkdirAll(filepath.Join(cfg.FilesDir, dir), 0o700); err != nil {
			return nil, err
		}
	}
	secret, err := st.Secret(ctx)
	if err != nil {
		return nil, err
	}
	s := &Server{
		st:      st,
		hub:     hub.New(),
		cfg:     cfg,
		secret:  secret,
		static:  static,
		authLim: newLimiter(20, 5*time.Minute),
		linkLim: newLimiter(60, 5*time.Minute),
		now:     time.Now,
	}
	s.handler = s.routes()
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	mux.HandleFunc("GET /api/prelogin", s.handlePrelogin)
	mux.HandleFunc("POST /api/register", s.handleRegister)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", s.authed(s.handleMe))
	mux.HandleFunc("PATCH /api/me", s.authed(s.handleUpdateProfile))
	mux.HandleFunc("PUT /api/me/avatar", s.authed(s.handleSetAvatar))
	mux.HandleFunc("DELETE /api/me/avatar", s.authed(s.handleDeleteAvatar))

	mux.HandleFunc("GET /api/users", s.authed(s.handleSearchUsers))
	mux.HandleFunc("GET /api/users/{id}", s.authed(s.handleUser))
	mux.HandleFunc("GET /api/users/{id}/avatar", s.authed(s.handleAvatar))

	mux.HandleFunc("GET /api/invites", s.authed(s.handleListInvites))
	mux.HandleFunc("POST /api/invites", s.authed(s.handleCreateInvite))
	mux.HandleFunc("DELETE /api/invites/{code}", s.authed(s.handleRevokeInvite))

	mux.HandleFunc("GET /api/chats", s.authed(s.handleChats))
	mux.HandleFunc("POST /api/chats", s.authed(s.handleCreateChat))
	mux.HandleFunc("GET /api/chats/{id}", s.authed(s.handleChat))
	mux.HandleFunc("PATCH /api/chats/{id}", s.authed(s.handleUpdateGroup))
	mux.HandleFunc("GET /api/chats/{id}/photo", s.authed(s.handleGroupPhoto))
	mux.HandleFunc("PUT /api/chats/{id}/photo", s.authed(s.handleSetGroupPhoto))
	mux.HandleFunc("DELETE /api/chats/{id}/photo", s.authed(s.handleDeleteGroupPhoto))
	mux.HandleFunc("GET /api/chats/{id}/messages", s.authed(s.handleMessages))
	mux.HandleFunc("POST /api/chats/{id}/messages", s.authed(s.handleSend))
	mux.HandleFunc("PATCH /api/chats/{id}/messages/{mid}", s.authed(s.handleEdit))
	mux.HandleFunc("POST /api/chats/{id}/files", s.authed(s.handleUpload))
	mux.HandleFunc("GET /api/files/{fid}", s.authed(s.handleDownload))
	mux.HandleFunc("POST /api/chats/{id}/read", s.authed(s.handleRead))
	mux.HandleFunc("GET /api/chats/{id}/keys", s.authed(s.handleKeys))
	mux.HandleFunc("POST /api/chats/{id}/members", s.authed(s.handleAddMember))
	mux.HandleFunc("DELETE /api/chats/{id}/members/{uid}", s.authed(s.handleRemoveMember))
	mux.HandleFunc("POST /api/chats/{id}/rekey", s.authed(s.handleRekey))
	mux.HandleFunc("POST /api/chats/{id}/link", s.authed(s.handleInviteLink))
	mux.HandleFunc("DELETE /api/chats/{id}/link", s.authed(s.handleRevokeInviteLink))

	mux.HandleFunc("GET /api/join/{code}", s.handleLinkPreview)
	mux.HandleFunc("POST /api/join/{code}", s.authed(s.handleJoin))

	mux.HandleFunc("GET /api/updates", s.authed(s.handleUpdates))

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		httpError(w, http.StatusNotFound, "not found")
	})
	if s.static != nil {
		files := http.FileServerFS(s.static)
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No build step means no hashed filenames: always revalidate.
			w.Header().Set("Cache-Control", "no-cache")
			files.ServeHTTP(w, r)
		}))
	}
	return securityHeaders(csrf(mux))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'self'; script-src 'self'; "+
			"connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// csrf requires a custom header on state-changing API calls. Browsers won't
// send one cross-origin without a CORS preflight, which we never allow.
// This backs up the SameSite=Strict session cookie.
func csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Method != http.MethodGet && r.Method != http.MethodHead &&
			r.Header.Get("X-Emer") != "1" {
			httpError(w, http.StatusForbidden, "missing X-Emer header")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) isSecure(r *http.Request) bool {
	return s.cfg.SecureCookies || r.TLS != nil || (s.cfg.TrustProxy && r.Header.Get("X-Forwarded-Proto") == "https")
}

func (s *Server) nowMs() int64 { return s.now().UnixMilli() }

// RunJanitor prunes expired data until ctx is cancelled.
func (s *Server) RunJanitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		now := s.now()
		if err := s.st.Prune(ctx, now.UnixMilli(), now.Add(-s.cfg.UpdatesTTL).UnixMilli()); err != nil && ctx.Err() == nil {
			log.Printf("janitor: %v", err)
		}
		s.pruneFiles(ctx, now)
		s.authLim.cleanup(now)
		s.linkLim.cleanup(now)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// --- JSON helpers ---

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// storeError maps store errors to HTTP responses.
func storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpError(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrForbidden):
		httpError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, store.ErrConflict):
		httpError(w, http.StatusConflict, "conflict")
	case errors.Is(err, store.ErrInvalid):
		httpError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, context.Canceled):
		// client went away
	default:
		log.Printf("internal error: %v", err)
		httpError(w, http.StatusInternalServerError, "internal error")
	}
}

func pathID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id <= 0 {
		httpError(w, http.StatusBadRequest, "bad "+name)
		return 0, false
	}
	return id, true
}
