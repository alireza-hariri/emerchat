package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"emerchat/internal/store"
)

// Attachments are encrypted in the browser; the server stores opaque bytes
// under FilesDir/<id>. Profile pictures are public to logged-in users and
// stored in plain form under FilesDir/avatars/<userId>.

const (
	maxAvatar = 1 << 20
	// Unclaimed uploads (the message was never sent) are deleted after this.
	orphanTTL = 24 * time.Hour
	// Big transfers outlive the server-wide read/write timeouts.
	transferTimeout = 30 * time.Minute
)

var fileIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// fileHeaders keeps stored bytes from ever being treated as a page.
func fileHeaders(w http.ResponseWriter, contentType string) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cache-Control", "private, max-age=31536000, immutable")
}

// writeFileAtomic streams r into dir/name via a temp file, so readers never
// see a partial file. It returns the number of bytes written.
func writeFileAtomic(dir, name string, r io.Reader) (int64, error) {
	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(tmp, r)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(dir, name))
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return n, err
}

func uploadError(w http.ResponseWriter, err error) {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		httpError(w, http.StatusRequestEntityTooLarge, "file is too large")
		return
	}
	storeError(w, err)
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request, u store.User) {
	chatID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if err := s.st.IsMember(r.Context(), chatID, u.ID); err != nil {
		storeError(w, err)
		return
	}
	http.NewResponseController(w).SetReadDeadline(time.Now().Add(transferTimeout))
	id := randomToken(16)
	n, err := writeFileAtomic(s.cfg.FilesDir, id, http.MaxBytesReader(w, r.Body, s.cfg.MaxUpload))
	if err != nil {
		uploadError(w, err)
		return
	}
	path := filepath.Join(s.cfg.FilesDir, id)
	if n < 16 { // shorter than an AES-GCM tag: can't be a real ciphertext
		os.Remove(path)
		httpError(w, http.StatusBadRequest, "empty file")
		return
	}
	if err := s.st.AddFile(r.Context(), id, chatID, u.ID, n, s.nowMs()); err != nil {
		os.Remove(path)
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"file": map[string]any{"id": id, "size": n}})
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request, u store.User) {
	id := r.PathValue("fid")
	if !fileIDRe.MatchString(id) {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	if err := s.st.CanReadFile(r.Context(), id, u.ID); err != nil {
		storeError(w, err)
		return
	}
	f, err := os.Open(filepath.Join(s.cfg.FilesDir, id))
	if err != nil {
		log.Printf("file %s: %v", id, err)
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	defer f.Close()
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(transferTimeout))
	fileHeaders(w, "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment")
	http.ServeContent(w, r, "", time.Time{}, f)
}

func (s *Server) pruneFiles(ctx context.Context, now time.Time) {
	ids, err := s.st.PruneFiles(ctx, now.Add(-orphanTTL).UnixMilli())
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("janitor: files: %v", err)
		}
		return
	}
	for _, id := range ids {
		if err := os.Remove(filepath.Join(s.cfg.FilesDir, id)); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("janitor: %v", err)
		}
	}
}

// --- profile ---

func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request, u store.User) {
	var req struct {
		DisplayName string `json:"displayName"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.DisplayName)
	if name == "" || utf8.RuneCountInString(name) > 64 {
		httpError(w, http.StatusBadRequest, "name must be 1-64 characters")
		return
	}
	s.profileChanged(w, r)(s.st.SetDisplayName(r.Context(), u.ID, name, s.nowMs()))
}

var avatarTypes = map[string]bool{"image/jpeg": true, "image/png": true, "image/webp": true, "image/gif": true}

// saveImage stores the request body as dir/<id> if it is a supported image.
func (s *Server) saveImage(w http.ResponseWriter, r *http.Request, dir string, id int64) bool {
	body := http.MaxBytesReader(w, r.Body, maxAvatar)
	head := make([]byte, 512)
	n, err := io.ReadFull(body, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		uploadError(w, err)
		return false
	}
	if !avatarTypes[http.DetectContentType(head[:n])] {
		httpError(w, http.StatusBadRequest, "picture must be a JPEG, PNG, WebP or GIF image")
		return false
	}
	name := strconv.FormatInt(id, 10)
	if _, err := writeFileAtomic(filepath.Join(s.cfg.FilesDir, dir), name, io.MultiReader(bytes.NewReader(head[:n]), body)); err != nil {
		uploadError(w, err)
		return false
	}
	return true
}

// serveImage serves dir/<id> as stored by saveImage.
func (s *Server) serveImage(w http.ResponseWriter, r *http.Request, dir string, id int64) {
	f, err := os.Open(filepath.Join(s.cfg.FilesDir, dir, strconv.FormatInt(id, 10)))
	if err != nil {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	ct := http.DetectContentType(head[:n])
	if !avatarTypes[ct] {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	fileHeaders(w, ct)
	http.ServeContent(w, r, "", time.Time{}, f)
}

func (s *Server) handleSetAvatar(w http.ResponseWriter, r *http.Request, u store.User) {
	if s.saveImage(w, r, "avatars", u.ID) {
		s.profileChanged(w, r)(s.st.SetAvatar(r.Context(), u.ID, randomToken(6), s.nowMs()))
	}
}

func (s *Server) handleDeleteAvatar(w http.ResponseWriter, r *http.Request, u store.User) {
	os.Remove(filepath.Join(s.cfg.FilesDir, "avatars", strconv.FormatInt(u.ID, 10)))
	s.profileChanged(w, r)(s.st.SetAvatar(r.Context(), u.ID, "", s.nowMs()))
}

// profileChanged finishes a profile update: it wakes everyone who shares a
// chat with the user and returns the updated user.
func (s *Server) profileChanged(w http.ResponseWriter, r *http.Request) func(store.User, []int64, error) {
	return func(u store.User, notify []int64, err error) {
		if err != nil {
			storeError(w, err)
			return
		}
		s.hub.Notify(notify...)
		writeJSON(w, http.StatusOK, map[string]any{"user": u})
	}
}

func (s *Server) handleAvatar(w http.ResponseWriter, r *http.Request, _ store.User) {
	if id, ok := pathID(w, r, "id"); ok {
		s.serveImage(w, r, "avatars", id)
	}
}

// --- group profile ---

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Title string `json:"title"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	title := strings.TrimSpace(req.Title)
	if title == "" || utf8.RuneCountInString(title) > 128 {
		httpError(w, http.StatusBadRequest, "group title must be 1-128 characters")
		return
	}
	s.groupChanged(w, r, id, u)(s.st.SetGroupTitle(r.Context(), id, u.ID, title, s.nowMs()))
}

func (s *Server) handleSetGroupPhoto(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	// Check first so non-members can't overwrite a group's photo file.
	if c, err := s.st.Chat(r.Context(), id, u.ID); err != nil || c.Kind != "group" {
		if err == nil {
			err = store.ErrInvalid
		}
		storeError(w, err)
		return
	}
	if s.saveImage(w, r, "groups", id) {
		s.groupChanged(w, r, id, u)(s.st.SetGroupPhoto(r.Context(), id, u.ID, randomToken(6), s.nowMs()))
	}
}

func (s *Server) handleDeleteGroupPhoto(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	notify, err := s.st.SetGroupPhoto(r.Context(), id, u.ID, "", s.nowMs())
	if err == nil {
		os.Remove(filepath.Join(s.cfg.FilesDir, "groups", strconv.FormatInt(id, 10)))
	}
	s.groupChanged(w, r, id, u)(notify, err)
}

// groupChanged wakes the members and returns the updated chat.
func (s *Server) groupChanged(w http.ResponseWriter, r *http.Request, id int64, u store.User) func([]int64, error) {
	return func(notify []int64, err error) {
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
}

func (s *Server) handleGroupPhoto(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if err := s.st.IsMember(r.Context(), id, u.ID); err != nil {
		storeError(w, err)
		return
	}
	s.serveImage(w, r, "groups", id)
}
