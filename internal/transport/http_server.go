package transport

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/mark3labs/mcp-go/server"
)

// HTTPConfig configures the Two-Doorway HTTP transport, Operator Studio mount,
// health endpoint, and optional backward-compatible /sse Streamable HTTP route.
type HTTPConfig struct {
	Version         string
	MCPServer       *server.MCPServer
	PathSecret      string
	LANToken        string
	EnableSSECompat bool
	AllowedHosts    []string
	Deadbolt        *security.Deadbolt
	// WebHandler serves the Operator Studio UI and API endpoints. It is mounted
	// under /web/ via http.StripPrefix("/web", ...), so requests arrive with /web stripped.
	WebHandler     http.Handler
	HealthProvider func(ctx context.Context) map[string]any
}

type transportRouter struct {
	version         string
	mcpHandler      http.Handler
	remoteSecret    string
	lanToken        string
	enableSSECompat bool
	allowedHosts    []string
	deadbolt        *security.Deadbolt
	webHandler      http.Handler
	healthProvider  func(ctx context.Context) map[string]any
}

const (
	minPathSecretLen          = 32
	ephemeralTokenBytes       = 16
	defaultListenAddr         = ":8000"
	defaultReadHeaderTimeout  = 10 * time.Second
	defaultIdleTimeout        = 60 * time.Second
	defaultShutdownTimeout    = 10 * time.Second
	lanTokenDerivationContext = "mcp-adv-netutils:lan-doorway-v1"
	webCSPHeader              = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;"
	mcpAllowedHeaders         = "Content-Type, Accept, Authorization, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID"
	mcpExposedHeaders         = "Mcp-Session-Id, Mcp-Protocol-Version"
	mcpAllowedMethods         = "GET, POST, DELETE, OPTIONS"
)

// DoorwayKind identifies which MCP ingress doorway accepted a request.
type DoorwayKind string

const (
	DoorwayRemote DoorwayKind = "remote"
	DoorwayLAN    DoorwayKind = "lan"
	DoorwayStdio  DoorwayKind = "stdio"
)

type doorwayContextKey struct{}

// WithDoorway annotates ctx with the doorway kind handling the MCP call.
func WithDoorway(ctx context.Context, kind DoorwayKind) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, doorwayContextKey{}, kind)
}

// DoorwayFromContext returns the doorway kind set on ctx, or empty string if unset.
func DoorwayFromContext(ctx context.Context) DoorwayKind {
	if ctx == nil {
		return ""
	}
	kind, _ := ctx.Value(doorwayContextKey{}).(DoorwayKind)
	return kind
}

// DeriveLANToken deterministically derives a 64-character hex LAN doorway token
// from pathSecret using HMAC-SHA256 with domain separation.
func DeriveLANToken(pathSecret string) string {
	trimmed := strings.TrimSpace(pathSecret)
	if trimmed == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(trimmed))
	_, _ = mac.Write([]byte(lanTokenDerivationContext))
	return hex.EncodeToString(mac.Sum(nil))
}

// NewHTTPHandler builds the HTTP handler implementing the remote doorway
// (/{PATH_SECRET}/mcp), LAN doorway (/lan/{LAN_TOKEN}/mcp), optional /sse
// compatibility route, /healthz, and the /web Operator Studio mount.
//
//nolint:gocritic // hugeParam: value config matches public transport API contract.
func NewHTTPHandler(cfg HTTPConfig) (http.Handler, error) {
	if cfg.MCPServer == nil {
		return nil, errors.New("mcp server must not be nil")
	}

	pathSecret := strings.TrimSpace(cfg.PathSecret)
	if hasInvalidTokenChars(pathSecret) {
		return nil, errors.New("path secret must not contain URL delimiters or whitespace")
	}

	var remoteSecret string
	if len(pathSecret) >= minPathSecretLen {
		remoteSecret = pathSecret
	}

	lanToken, err := resolveLANToken(cfg.LANToken, pathSecret)
	if err != nil {
		return nil, err
	}

	version := strings.TrimSpace(cfg.Version)
	if version == "" {
		version = "dev"
	}

	var strippedWeb http.Handler
	if cfg.WebHandler != nil {
		strippedWeb = http.StripPrefix("/web", cfg.WebHandler)
	}

	return &transportRouter{
		version:         version,
		mcpHandler:      server.NewStreamableHTTPServer(cfg.MCPServer),
		remoteSecret:    remoteSecret,
		lanToken:        lanToken,
		enableSSECompat: cfg.EnableSSECompat,
		allowedHosts:    slices.Clone(cfg.AllowedHosts),
		deadbolt:        cfg.Deadbolt,
		webHandler:      strippedWeb,
		healthProvider:  cfg.HealthProvider,
	}, nil
}

// StartHTTPServer listens on addr and serves handler with graceful shutdown on ctx cancellation.
func StartHTTPServer(ctx context.Context, addr string, handler http.Handler) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}
	if handler == nil {
		return errors.New("http handler must not be nil")
	}

	listenAddr := strings.TrimSpace(addr)
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		IdleTimeout:       defaultIdleTimeout,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	errCh := make(chan error, 1)
	go func() {
		serveErr := srv.Serve(ln)
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- fmt.Errorf("serve http: %w", serveErr)
			return
		}
		errCh <- nil
	}()

	select {
	case serveErr := <-errCh:
		return serveErr
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultShutdownTimeout)
		defer cancel()
		shutdownErr := srv.Shutdown(shutdownCtx)
		serveErr := <-errCh
		if shutdownErr != nil {
			return fmt.Errorf("shutdown http server: %w", shutdownErr)
		}
		return serveErr
	}
}

func resolveLANToken(configured, pathSecret string) (string, error) {
	trimmed := strings.TrimSpace(configured)
	if trimmed != "" {
		if hasInvalidTokenChars(trimmed) {
			return "", errors.New("lan token must not contain URL delimiters or whitespace")
		}
		return trimmed, nil
	}
	if pathSecret != "" {
		return DeriveLANToken(pathSecret), nil
	}
	var raw [ephemeralTokenBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate ephemeral lan token: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func hasInvalidTokenChars(token string) bool {
	return token != "" && strings.ContainsAny(token, "/?#\\ \t\r\n")
}

func (rt *transportRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path

	switch {
	case p == "/healthz":
		rt.handleHealthz(w, r)
	case p == "/web":
		rt.handleWebRedirect(w, r)
	case strings.HasPrefix(p, "/web/"):
		rt.handleWeb(w, r)
	case p == "/sse":
		rt.handleSSECompat(w, r)
	case p == "/lan" || strings.HasPrefix(p, "/lan/"):
		rt.handleLANDoorway(w, r)
	case isRemoteMCPCandidatePath(p):
		rt.handleRemoteDoorway(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (rt *transportRouter) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	payload := map[string]any{
		"status":  "ok",
		"version": rt.version,
	}
	if rt.deadbolt != nil {
		st := rt.deadbolt.Status()
		payload["deadbolt"] = map[string]any{
			"enabled":    st.Enabled,
			"unlocked":   st.Unlocked,
			"locked_out": st.LockedOut,
		}
	}
	if rt.healthProvider != nil {
		for k, v := range rt.healthProvider(r.Context()) {
			if k != "" {
				payload[k] = v
			}
		}
		if _, ok := payload["status"]; !ok {
			payload["status"] = "ok"
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, writeErr := w.Write(append(body, '\n')); writeErr != nil {
		return
	}
}

func (rt *transportRouter) handleWebRedirect(w http.ResponseWriter, r *http.Request) {
	setWebSecurityHeaders(w)
	q := r.URL.Query()
	var parts []string
	if q.Get("demo") == "1" {
		parts = append(parts, "demo=1")
	}
	switch q.Get("theme") {
	case "white":
		parts = append(parts, "theme=white")
	case "paper":
		parts = append(parts, "theme=paper")
	case "dark-paper":
		parts = append(parts, "theme=dark-paper")
	case "dark":
		parts = append(parts, "theme=dark")
	}
	target := "/web/"
	if len(parts) > 0 {
		target += "?" + strings.Join(parts, "&")
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func (rt *transportRouter) handleWeb(w http.ResponseWriter, r *http.Request) {
	setWebSecurityHeaders(w)
	if strings.Contains(r.URL.Path, "//") || strings.Contains(r.URL.Path, "/./") || strings.Contains(r.URL.Path, "..") || strings.Contains(r.URL.RawPath, "..") {
		http.NotFound(w, r)
		return
	}

	cleanPath := path.Clean("/" + r.URL.Path)
	isAPI := cleanPath == "/web/api" || strings.HasPrefix(cleanPath, "/web/api/")
	if isAPI {
		w.Header().Set("Cache-Control", "no-store")
	}
	if isAPI || isStateChangingMethod(r.Method) {
		if err := ValidateWebRequest(r, rt.allowedHosts); err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}

	if rt.webHandler == nil {
		http.NotFound(w, r)
		return
	}
	rt.webHandler.ServeHTTP(w, r)
}

func (rt *transportRouter) handleSSECompat(w http.ResponseWriter, r *http.Request) {
	if !rt.enableSSECompat {
		http.NotFound(w, r)
		return
	}
	if err := ValidateLANDoorwayRequest(r); err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	rt.serveLANMCP(w, r)
}

func (rt *transportRouter) handleLANDoorway(w http.ResponseWriter, r *http.Request) {
	if err := ValidateLANDoorwayRequest(r); err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	if strings.Contains(r.URL.Path, "..") {
		http.NotFound(w, r)
		return
	}

	candidate, ok := extractLANDoorwayToken(r.URL.Path)
	if !ok || !VerifyPathToken(candidate, rt.lanToken) {
		http.NotFound(w, r)
		return
	}
	rt.serveLANMCP(w, r)
}

func (rt *transportRouter) handleRemoteDoorway(w http.ResponseWriter, r *http.Request) {
	candidate, ok := extractRemoteDoorwaySecret(r.URL.Path)
	if !ok || rt.remoteSecret == "" || !VerifyPathToken(candidate, rt.remoteSecret) {
		http.NotFound(w, r)
		return
	}

	setCORSHeaders(w, "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rt.mcpHandler.ServeHTTP(w, r.WithContext(WithDoorway(r.Context(), DoorwayRemote)))
}

func (rt *transportRouter) serveLANMCP(w http.ResponseWriter, r *http.Request) {
	if originRaw := strings.TrimSpace(r.Header.Get("Origin")); originRaw != "" {
		if !isSameLANOriginHost(r, originRaw) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rt.mcpHandler.ServeHTTP(w, r.WithContext(WithDoorway(r.Context(), DoorwayLAN)))
}

func isSameLANOriginHost(r *http.Request, originRaw string) bool {
	originURL, ok := parseOriginHeader(originRaw)
	if !ok {
		return false
	}
	originHost, originPort, ok := splitHostAndPort(originURL.Host)
	if !ok {
		return false
	}
	reqHost, _, err := extractHostAndOrigin(r)
	if err != nil {
		return false
	}
	hostName, hostPort, ok := splitHostAndPort(reqHost)
	if !ok {
		return false
	}
	return originMatchesHostPort(originURL.Scheme, originHost, originPort, hostName, hostPort, r.TLS != nil)
}

func setWebSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", webCSPHeader)
}

func setCORSHeaders(w http.ResponseWriter, allowOrigin string) {
	w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
	w.Header().Set("Access-Control-Allow-Methods", mcpAllowedMethods)
	w.Header().Set("Access-Control-Allow-Headers", mcpAllowedHeaders)
	w.Header().Set("Access-Control-Expose-Headers", mcpExposedHeaders)
	w.Header().Set("Access-Control-Max-Age", "3600")
}

func isRemoteMCPCandidatePath(p string) bool {
	_, ok := extractRemoteDoorwaySecret(p)
	return ok
}

func extractRemoteDoorwaySecret(p string) (string, bool) {
	if !strings.HasPrefix(p, "/") || !strings.HasSuffix(p, "/mcp") || strings.Contains(p, "..") {
		return "", false
	}
	seg := strings.TrimSuffix(strings.TrimPrefix(p, "/"), "/mcp")
	if seg == "" || seg == "lan" || strings.Contains(seg, "/") {
		return "", false
	}
	return seg, true
}

func extractLANDoorwayToken(p string) (string, bool) {
	if !strings.HasPrefix(p, "/lan/") || !strings.HasSuffix(p, "/mcp") || strings.Contains(p, "..") {
		return "", false
	}
	token := strings.TrimSuffix(strings.TrimPrefix(p, "/lan/"), "/mcp")
	if token == "" || strings.Contains(token, "/") {
		return "", false
	}
	return token, true
}
