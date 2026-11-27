// Package webui serves the embedded Quiet UI Operator Studio assets and HTTP JSON API.
package webui

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/cronmon"
	"github.com/FrankXLT/mcp-adv-netutils/internal/dispatch"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
)

// Config configures the Operator Studio HTTP handler.
type Config struct {
	Version                string
	Dispatcher             *dispatch.Dispatcher
	Store                  *store.JobStore
	Scheduler              *cronmon.Scheduler
	Deadbolt               *security.Deadbolt
	AllowLockedCronSummary bool
}

type studioHandler struct {
	version                string
	dispatcher             *dispatch.Dispatcher
	store                  *store.JobStore
	scheduler              *cronmon.Scheduler
	deadbolt               *security.Deadbolt
	allowLockedCronSummary bool
	assets                 fs.FS
	sessionKey             []byte
}

type statusPayload struct {
	Locked          bool   `json:"locked"`
	Enabled         bool   `json:"enabled"`
	DeadboltEnabled bool   `json:"deadbolt_enabled"`
	LockedOut       bool   `json:"locked_out,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	Version         string `json:"version,omitempty"`
	Error           string `json:"error,omitempty"`
}

const (
	passphraseHeader  = "X-Netutils-Passphrase"
	sessionCookieName = "netutils_session"
	sessionKeyBytes   = 32
	defaultCronPeriod = "30d"
	defaultJobsLimit  = 50
	maxJobsLimit      = 500
	maxUnlockBodySize = 4 << 10
	maxRunBodySize    = 64 << 10
	bytesPerMiB       = 1024 * 1024
)

//go:embed all:assets
var assetsFS embed.FS

// NewHandler constructs the Operator Studio HTTP handler serving embedded static
// assets and the /api/* JSON endpoints (with /web prefix already stripped).
func NewHandler(cfg Config) (http.Handler, error) {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		return nil, fmt.Errorf("open embedded webui assets: %w", err)
	}
	sessionKey := make([]byte, sessionKeyBytes)
	if _, err := rand.Read(sessionKey); err != nil {
		return nil, fmt.Errorf("init webui session key: %w", err)
	}
	ver := strings.TrimSpace(cfg.Version)
	if ver == "" {
		ver = "dev"
	}
	sched := cfg.Scheduler
	if sched == nil && cfg.Dispatcher != nil {
		sched = cfg.Dispatcher.Scheduler()
	}
	return &studioHandler{
		version:                ver,
		dispatcher:             cfg.Dispatcher,
		store:                  cfg.Store,
		scheduler:              sched,
		deadbolt:               cfg.Deadbolt,
		allowLockedCronSummary: cfg.AllowLockedCronSummary,
		assets:                 sub,
		sessionKey:             sessionKey,
	}, nil
}

func (h *studioHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if strings.Contains(r.URL.Path, "..") || strings.Contains(r.URL.RawPath, "..") || strings.ContainsRune(r.URL.Path, '\\') {
		http.NotFound(w, r)
		return
	}
	p := path.Clean("/" + r.URL.Path)
	switch {
	case p == "/api/demo_snapshot":
		h.handleDemoSnapshot(w, r)
	case p == "/api/status":
		h.handleStatus(w, r)
	case p == "/api/unlock":
		h.handleUnlock(w, r)
	case p == "/api/lock":
		h.handleLock(w, r)
	case p == "/api/run":
		h.handleRun(w, r)
	case p == "/api/cron":
		h.handleCron(w, r)
	case p == "/api/jobs":
		h.handleJobs(w, r)
	case strings.HasPrefix(p, "/api/jobs/"):
		h.handleJobByID(w, r, strings.TrimPrefix(p, "/api/jobs/"))
	case p == "/api/watchlist":
		h.handleWatchlist(w, r)
	case p == "/api/destinations":
		h.handleDestinations(w, r)
	case strings.HasPrefix(p, "/api/destinations/"):
		h.handleDestinationByID(w, r, strings.TrimPrefix(p, "/api/destinations/"))
	case p == "/api/scan-pinned":
		h.handleScanPinned(w, r)
	case strings.HasPrefix(p, "/api/"):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	default:
		h.handleAsset(w, r, p)
	}
}

func (h *studioHandler) handleAsset(w http.ResponseWriter, r *http.Request, cleanPath string) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	rel := strings.TrimPrefix(cleanPath, "/")
	if rel == "" {
		rel = "index.html"
	}
	file, err := h.assets.Open(rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	rs, ok := file.(io.ReadSeeker)
	if err != nil || info.IsDir() || !ok {
		http.NotFound(w, r)
		return
	}
	if rel == "index.html" {
		w.Header().Set("Cache-Control", "no-store")
	}
	if ct := mime.TypeByExtension(path.Ext(rel)); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	http.ServeContent(w, r, rel, info.ModTime(), rs)
}

func (h *studioHandler) handleDemoSnapshot(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	raw, err := fs.ReadFile(h.assets, "demo_snapshots/demo_snapshot.json")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "demo snapshot unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(raw)
	}
}

func (h *studioHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	if h.deadbolt == nil || !h.deadbolt.IsEnabled() {
		writeJSON(w, http.StatusOK, statusPayload{Version: h.version})
		return
	}
	st := h.deadbolt.Status()
	authorized := h.isSessionAuthorized(w, r, st.Unlocked)
	resp := statusPayload{
		Locked: !authorized, Enabled: true, DeadboltEnabled: true,
		LockedOut: st.LockedOut, Version: h.version,
	}
	if authorized && !st.ExpiresAt.IsZero() {
		resp.ExpiresAt = st.ExpiresAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *studioHandler) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if h.deadbolt == nil || !h.deadbolt.IsEnabled() {
		writeJSON(w, http.StatusOK, statusPayload{Version: h.version})
		return
	}
	pass := r.Header.Get(passphraseHeader)
	if r.Body != nil {
		raw, status, msg := readLimitedBody(w, r.Body, maxUnlockBodySize)
		if status != 0 {
			writeJSON(w, status, map[string]string{"error": msg})
			return
		}
		if len(bytes.TrimSpace(raw)) > 0 {
			var body struct {
				Passphrase string `json:"passphrase"`
			}
			if err := json.Unmarshal(raw, &body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON unlock request"})
				return
			}
			if body.Passphrase != "" {
				pass = body.Passphrase
			}
		}
	}
	if ok, exp := h.tryDeadboltUnlock(w, pass); ok {
		h.setSessionCookie(w, r, exp)
		writeJSON(w, http.StatusOK, statusPayload{
			Enabled: true, DeadboltEnabled: true, ExpiresAt: exp.UTC().Format(time.RFC3339), Version: h.version,
		})
	}
}

func (h *studioHandler) handleLock(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	enabled := h.deadbolt != nil && h.deadbolt.IsEnabled()
	if h.deadbolt != nil {
		h.deadbolt.Lock()
	}
	h.clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, statusPayload{Locked: true, Enabled: enabled, DeadboltEnabled: enabled})
}

func (h *studioHandler) tryDeadboltUnlock(w http.ResponseWriter, pass string) (bool, time.Time) {
	ok, expiresAt, reason := h.deadbolt.Unlock(pass)
	if ok {
		return true, expiresAt
	}
	if h.deadbolt.Status().LockedOut || strings.Contains(reason, "locked") {
		writeJSON(w, http.StatusTooManyRequests, statusPayload{
			Locked: true, Enabled: true, DeadboltEnabled: true, LockedOut: true, Error: "rate limited",
		})
		return false, time.Time{}
	}
	writeJSON(w, http.StatusUnauthorized, statusPayload{
		Locked: true, Enabled: true, DeadboltEnabled: true, Error: "invalid passphrase",
	})
	return false, time.Time{}
}

func (h *studioHandler) isUnlocked(w http.ResponseWriter, r *http.Request) bool {
	if h.deadbolt == nil || !h.deadbolt.IsEnabled() {
		return true
	}
	return h.isSessionAuthorized(w, r, h.deadbolt.IsUnlocked())
}

func (h *studioHandler) allowLockedSummary() bool {
	if h.allowLockedCronSummary {
		return true
	}
	return h.deadbolt != nil && h.deadbolt.AllowLockedCronSummary()
}

func (h *studioHandler) requireUnlocked(w http.ResponseWriter, r *http.Request) bool {
	if h.isUnlocked(w, r) {
		return true
	}
	writeJSON(w, http.StatusUnauthorized, map[string]any{"locked": true, "error": "operator studio locked"})
	return false
}

func (h *studioHandler) isSessionAuthorized(w http.ResponseWriter, r *http.Request, deadboltUnlocked bool) bool {
	if !deadboltUnlocked {
		if _, err := r.Cookie(sessionCookieName); err == nil {
			h.clearSessionCookie(w, r)
		}
		return false
	}
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	if !h.verifySessionCookie(c.Value, time.Now(), h.deadbolt.UnlockEpoch()) {
		h.clearSessionCookie(w, r)
		return false
	}
	return true
}

func (h *studioHandler) setSessionCookie(w http.ResponseWriter, r *http.Request, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Round(time.Second).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    h.signSessionCookie(expiresAt, h.deadbolt.UnlockEpoch()),
		Path:     "/",
		MaxAge:   maxAge,
		Expires:  expiresAt.UTC(),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isHTTPS(r),
	})
}

func (h *studioHandler) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isHTTPS(r),
	})
}

func (h *studioHandler) signSessionCookie(expiresAt time.Time, epoch uint64) string {
	payload := strconv.FormatInt(expiresAt.Unix(), 10) + ":" + strconv.FormatUint(epoch, 10)
	mac := hmac.New(sha256.New, h.sessionKey)
	_, _ = mac.Write([]byte(payload))
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

func (h *studioHandler) verifySessionCookie(raw string, now time.Time, expectedEpoch uint64) bool {
	payload, sigHex, ok := strings.Cut(raw, ".")
	if !ok || payload == "" || sigHex == "" {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, h.sessionKey)
	_, _ = mac.Write([]byte(payload))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	expStr, epochStr, ok := strings.Cut(payload, ":")
	if !ok || expStr == "" || epochStr == "" {
		return false
	}
	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || expUnix <= now.Unix() {
		return false
	}
	epoch, err := strconv.ParseUint(epochStr, 10, 64)
	if err != nil || epoch != expectedEpoch {
		return false
	}
	return h.deadbolt == nil || epoch != 0
}

func isHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if r.URL != nil && strings.EqualFold(r.URL.Scheme, "https") {
		return true
	}
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

func readLimitedBody(w http.ResponseWriter, body io.ReadCloser, limit int64) ([]byte, int, string) {
	if body == nil {
		return nil, http.StatusBadRequest, "request body is required"
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, body, limit))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, http.StatusRequestEntityTooLarge, "request body too large"
		}
		return nil, http.StatusBadRequest, "unable to read request body"
	}
	return raw, 0, ""
}

func decodeLimitedJSON(w http.ResponseWriter, body io.ReadCloser, limit int64, dst any) (int, string) {
	raw, status, msg := readLimitedBody(w, body, limit)
	if status != 0 {
		return status, msg
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return http.StatusBadRequest, "request body must not be empty"
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return http.StatusBadRequest, "invalid JSON payload"
	}
	return 0, ""
}

func decodeOptionalJSON(w http.ResponseWriter, body io.ReadCloser, limit int64, dst any) (int, string) {
	if body == nil {
		return 0, ""
	}
	raw, status, msg := readLimitedBody(w, body, limit)
	if status != 0 {
		return status, msg
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return 0, ""
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return http.StatusBadRequest, "invalid JSON payload"
	}
	return 0, ""
}

func requireMethod(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, m := range allowed {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	return false
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		data = []byte(`{"error":"failed to encode JSON response"}`)
		statusCode = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(statusCode)
	_, _ = w.Write(append(data, '\n'))
}
