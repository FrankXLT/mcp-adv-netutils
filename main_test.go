package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mapEnv(vals map[string]string) func(string) string {
	return func(k string) string {
		return vals[k]
	}
}

func TestParseConfigModesAndLegacyAliases(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	cfg, err := parseConfig([]string{"--data-dir", tmpDir}, mapEnv(nil), io.Discard)
	require.NoError(t, err)
	assert.Equal(t, modeStdio, cfg.Mode)
	assert.Equal(t, ":8000", cfg.HTTPAddr)
	assert.False(t, cfg.EnableSSECompat)
	assert.Equal(t, 256, cfg.MaxStoreMB)
	assert.Equal(t, 1800*time.Second, cfg.TTL)
	assert.Equal(t, []string{"169.254.0.0/16"}, cfg.DenyCIDRs)

	cfg, err = parseConfig([]string{"--sse", "--sse-port", "9123", "--data-dir", tmpDir}, mapEnv(nil), io.Discard)
	require.NoError(t, err)
	assert.Equal(t, modeHTTP, cfg.Mode)
	assert.True(t, cfg.EnableSSECompat)
	assert.Equal(t, ":9123", cfg.HTTPAddr)

	cfg, err = parseConfig([]string{"--sse", "--sse-port", "9123", "--http-addr", "127.0.0.1:8080"}, mapEnv(nil), io.Discard)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:8080", cfg.HTTPAddr)

	cfg, err = parseConfig([]string{"--http", "--sse-compat", "--http-addr", "127.0.0.1:8443"}, mapEnv(nil), io.Discard)
	require.NoError(t, err)
	assert.Equal(t, modeHTTP, cfg.Mode)
	assert.True(t, cfg.EnableSSECompat)
	assert.Equal(t, "127.0.0.1:8443", cfg.HTTPAddr)

	cfg, err = parseConfig([]string{"--run-watchlist-once", "--data-dir", tmpDir}, mapEnv(nil), io.Discard)
	require.NoError(t, err)
	assert.Equal(t, modeWatchlistOnce, cfg.Mode)

	for _, badArgs := range [][]string{
		{"--stdio", "--http"},
		{"--stdio", "--sse"},
		{"--run-watchlist-once", "--http"},
		{"--run-watchlist-once", "--stdio"},
		{"--ttl-seconds", "-1"},
		{"--ping-count", "0"},
		{"--sse", "--sse-port", "70000"},
		{"unexpected-arg"},
	} {
		_, err = parseConfig(badArgs, mapEnv(nil), io.Discard)
		require.Error(t, err, "args=%v", badArgs)
	}
}

func TestParseConfigEnvMergingAndOverrides(t *testing.T) {
	t.Parallel()

	env := mapEnv(map[string]string{
		"NETUTILS_DATA_DIR":                  "/custom/data",
		"NETUTILS_WATCHLIST":                 "/custom/watchlist.yaml",
		"NETUTILS_ALLOW_CIDRS":               "192.168.1.0/24, 10.0.0.0/8",
		"NETUTILS_DENY_CIDRS":                "100.64.0.0/10",
		"NETUTILS_ALLOWED_HOSTS":             "studio.local",
		"NETUTILS_TTL_SECONDS":               "900",
		"NETUTILS_ALLOW_LOCKED_CRON_SUMMARY": "true",
		"PASS_HASH":                          "abc123",
		"PATH_SECRET":                        "super-secret-path-token",
		"LAN_MCP_TOKEN":                      "lan-token-value",
	})

	cfg, err := parseConfig([]string{
		"--http",
		"--allow-cidrs", "10.0.0.0/8,172.16.0.0/12",
		"--allowed-hosts", "127.0.0.1:8000,studio.local",
		"--remote-server-address", "https://dns.example/dns-query",
		"--custom-whois-server", "whois.example.org",
		"--timeout", "3s",
		"--ping-timeout", "2s",
		"--ping-count", "2",
		"--http-ping-timeout", "7s",
		"--http-ping-count", "3",
		"--tls-timeout", "6s",
	}, env, io.Discard)
	require.NoError(t, err)

	assert.Equal(t, "/custom/data", cfg.DataDir)
	assert.Equal(t, "/custom/watchlist.yaml", cfg.WatchlistPath)
	assert.Equal(t, []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"}, cfg.AllowCIDRs)
	assert.Equal(t, []string{"100.64.0.0/10", "169.254.0.0/16"}, cfg.DenyCIDRs)
	assert.Equal(t, []string{"studio.local", "127.0.0.1:8000"}, cfg.AllowedHosts)
	assert.Equal(t, 900*time.Second, cfg.TTL)
	assert.True(t, cfg.AllowLockedCronSummary)
	assert.Equal(t, "abc123", cfg.PassHash)
	assert.Equal(t, "super-secret-path-token", cfg.PathSecret)
	assert.Equal(t, "lan-token-value", cfg.LANToken)
	assert.Equal(t, "https://dns.example/dns-query", cfg.RemoteServerAddress)
	assert.Equal(t, "whois.example.org", cfg.CustomWhoisServer)
	assert.Equal(t, 3*time.Second, cfg.DNSTimeout)
	assert.Equal(t, 2*time.Second, cfg.PingTimeout)
	assert.Equal(t, 2, cfg.PingCount)
	assert.Equal(t, 7*time.Second, cfg.HTTPPingTimeout)
	assert.Equal(t, 3, cfg.HTTPPingCount)
	assert.Equal(t, 6*time.Second, cfg.TLSTimeout)

	// CLI --ttl-seconds explicitly overrides NETUTILS_TTL_SECONDS.
	cfg, err = parseConfig([]string{"--ttl-seconds", "450"}, env, io.Discard)
	require.NoError(t, err)
	assert.Equal(t, 450*time.Second, cfg.TTL)

	_, err = parseConfig(nil, mapEnv(map[string]string{"NETUTILS_TTL_SECONDS": "notanint"}), io.Discard)
	require.Error(t, err)
}

func TestParseConfigListenAliasAndNetutilsEnvFallbacks(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fallbackEnv := mapEnv(map[string]string{
		"NETUTILS_PASS_HASH":     "netutils-pass-hash",
		"NETUTILS_PATH_SECRET":   "netutils-path-secret",
		"NETUTILS_LAN_MCP_TOKEN": "netutils-lan-token",
	})
	cfg, err := parseConfig([]string{"--http", "--listen=:9001", "--data-dir", tmpDir}, fallbackEnv, io.Discard)
	require.NoError(t, err)
	assert.Equal(t, ":9001", cfg.HTTPAddr)
	assert.Equal(t, "netutils-pass-hash", cfg.PassHash)
	assert.Equal(t, "netutils-path-secret", cfg.PathSecret)
	assert.Equal(t, "netutils-lan-token", cfg.LANToken)

	// Explicit --http-addr takes precedence over --listen.
	cfg, err = parseConfig([]string{"--http", "--listen=:9001", "--http-addr=:8443", "--data-dir", tmpDir}, fallbackEnv, io.Discard)
	require.NoError(t, err)
	assert.Equal(t, ":8443", cfg.HTTPAddr)

	// --listen takes precedence over --sse default --sse-port.
	cfg, err = parseConfig([]string{"--sse", "--listen=:9001", "--data-dir", tmpDir}, fallbackEnv, io.Discard)
	require.NoError(t, err)
	assert.Equal(t, ":9001", cfg.HTTPAddr)
	assert.True(t, cfg.EnableSSECompat)

	// Canonical PASS_HASH / PATH_SECRET / LAN_MCP_TOKEN win over NETUTILS_* fallbacks.
	precedenceEnv := mapEnv(map[string]string{
		"PASS_HASH":              "primary-hash",
		"NETUTILS_PASS_HASH":     "fallback-hash",
		"PATH_SECRET":            "primary-secret",
		"NETUTILS_PATH_SECRET":   "fallback-secret",
		"LAN_MCP_TOKEN":          "primary-token",
		"NETUTILS_LAN_MCP_TOKEN": "fallback-token",
	})
	cfg, err = parseConfig([]string{"--data-dir", tmpDir}, precedenceEnv, io.Discard)
	require.NoError(t, err)
	assert.Equal(t, "primary-hash", cfg.PassHash)
	assert.Equal(t, "primary-secret", cfg.PathSecret)
	assert.Equal(t, "primary-token", cfg.LANToken)
}

func TestResolveWatchlistPath(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	localWL := filepath.Join(tmpDir, "watchlist.yaml")
	appWL := filepath.Join(tmpDir, "app-watchlist.yaml")
	missingWL := filepath.Join(tmpDir, "missing.yaml")
	require.NoError(t, os.WriteFile(appWL, []byte("version: 1\nitems: []\n"), 0o600))

	assert.Equal(t, "/explicit/wl.yaml", resolveWatchlistPath("/explicit/wl.yaml", localWL, appWL))
	assert.Equal(t, appWL, resolveWatchlistPath("", missingWL, appWL))

	require.NoError(t, os.WriteFile(localWL, []byte("version: 1\nitems: []\n"), 0o600))
	assert.Equal(t, localWL, resolveWatchlistPath("", localWL, appWL))
	assert.Empty(t, resolveWatchlistPath("", missingWL, tmpDir))
}

func TestResolveDataDir(t *testing.T) {
	dir, err := resolveDataDir("/flag/dir", "/env/dir", modeHTTP)
	require.NoError(t, err)
	assert.Equal(t, "/flag/dir", dir)

	dir, err = resolveDataDir("", "/env/dir", modeStdio)
	require.NoError(t, err)
	assert.Equal(t, "/env/dir", dir)

	dir, err = resolveDataDir("", "", modeHTTP)
	require.NoError(t, err)
	assert.Equal(t, defaultDataDir, dir)

	cacheRoot := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheRoot)
	for _, mode := range []runMode{modeStdio, modeWatchlistOnce} {
		dir, err = resolveDataDir("", "", mode)
		require.NoError(t, err)
		if !isWritableDir(defaultDataDir, false) {
			assert.Equal(t, filepath.Join(cacheRoot, appCacheSubdir), dir)
		}
	}

	// Unwritable XDG_CACHE_HOME (regular file) falls back to TMPDIR.
	blockingFile := filepath.Join(cacheRoot, "not-a-dir")
	require.NoError(t, os.WriteFile(blockingFile, []byte("x"), 0o600))
	tmpRoot := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", blockingFile)
	t.Setenv("TMPDIR", tmpRoot)
	dir, err = resolveDataDir("", "", modeStdio)
	require.NoError(t, err)
	if !isWritableDir(defaultDataDir, false) {
		assert.Equal(t, filepath.Join(tmpRoot, appCacheSubdir), dir)
	}
}

func TestRunWatchlistOnceEndToEnd(t *testing.T) {
	t.Parallel()

	t.Run("missing watchlist falls back to empty", func(t *testing.T) {
		t.Parallel()
		dataDir := t.TempDir()
		missingWL := filepath.Join(t.TempDir(), "missing.yaml")
		var stdout, stderr bytes.Buffer

		err := runApp(context.Background(), []string{
			"--run-watchlist-once",
			"--data-dir", dataDir,
			"--watchlist", missingWL,
		}, mapEnv(nil), nil, &stdout, &stderr)
		require.NoError(t, err)
		assert.Contains(t, stdout.String(), "CRON WATCHLIST")
		assert.Contains(t, stdout.String(), "0 checks tracked")
		assert.FileExists(t, filepath.Join(dataDir, storeDBFilename))
	})

	t.Run("executes watchlist item and persists SQLite state", func(t *testing.T) {
		t.Parallel()
		dataDir := t.TempDir()
		wlPath := filepath.Join(t.TempDir(), "watchlist.yaml")
		wlContent := `version: 1
items:
  - key: mac-local
    schedule: "*/5 * * * *"
    tool: mac_vendor_lookup
    target: "02:42:ac:11:00:02"
    enabled: true
`
		require.NoError(t, os.WriteFile(wlPath, []byte(wlContent), 0o600))

		var stdout, stderr bytes.Buffer
		err := runApp(context.Background(), []string{
			"--run-watchlist-once",
			"--data-dir", dataDir,
			"--watchlist", wlPath,
		}, mapEnv(nil), nil, &stdout, &stderr)
		require.NoError(t, err)
		assert.Contains(t, stdout.String(), "CRON WATCHLIST")
		assert.Contains(t, stdout.String(), "1 checks tracked")
		assert.Contains(t, stdout.String(), "02:42:AC:11:00:02")

		st, err := store.Open(context.Background(), filepath.Join(dataDir, storeDBFilename), 32)
		require.NoError(t, err)
		defer func() { _ = st.Close() }()

		summary, err := st.GetCronStatus(context.Background(), "24h")
		require.NoError(t, err)
		require.Len(t, summary.States, 1)
		assert.Equal(t, "mac-local", summary.States[0].JobKey)
		assert.Equal(t, "OK", summary.States[0].LastStatus)
	})
}

func TestRunAppHTTPRouterAndGracefulShutdown(t *testing.T) {
	t.Parallel()

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	dataDir := t.TempDir()
	wlPath := filepath.Join(t.TempDir(), "watchlist.yaml")
	require.NoError(t, os.WriteFile(wlPath, []byte("version: 1\nitems: []\n"), 0o600))

	passHash := security.NormalizePhrase("correct horse battery staple")
	pathSecret := "secret-remote-doorway-token-0123456789abcdef"
	lanToken := "secret-lan-doorway-token-0123456789abcdef"
	env := mapEnv(map[string]string{
		"PASS_HASH":              passHash,
		"PATH_SECRET":            pathSecret,
		"LAN_MCP_TOKEN":          lanToken,
		"NETUTILS_ALLOWED_HOSTS": addr,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stdout, stderr bytes.Buffer
	errCh := make(chan error, 1)
	go func() {
		errCh <- runApp(ctx, []string{
			"--http",
			"--http-addr", addr,
			"--sse-compat",
			"--data-dir", dataDir,
			"--watchlist", wlPath,
		}, env, nil, &stdout, &stderr)
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	baseURL := "http://" + addr

	healthResp := waitForHealthz(t, ctx, client, baseURL+"/healthz", errCh)
	assert.Equal(t, "ok", healthResp["status"])
	assert.Equal(t, version, healthResp["version"])
	deadboltInfo, ok := healthResp["deadbolt"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, deadboltInfo["enabled"])

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/web/", nil)
	require.NoError(t, err)
	webResp, err := client.Do(req)
	require.NoError(t, err)
	webBody, err := io.ReadAll(webResp.Body)
	_ = webResp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, webResp.StatusCode)
	assert.Contains(t, string(webBody), "Network Studio")

	statusReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/web/api/status", nil)
	require.NoError(t, err)
	statusResp, err := client.Do(statusReq)
	require.NoError(t, err)
	statusBody, err := io.ReadAll(statusResp.Body)
	_ = statusResp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusResp.StatusCode)
	assert.Contains(t, string(statusBody), `"locked":true`)

	cancel()
	select {
	case runErr := <-errCh:
		require.NoError(t, runErr)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for HTTP server shutdown")
	}

	assert.Empty(t, stdout.String())
	logOutput := stderr.String()
	assert.Contains(t, logOutput, "listening on "+addr)
	assert.NotContains(t, logOutput, passHash)
	assert.NotContains(t, logOutput, pathSecret)
	assert.NotContains(t, logOutput, lanToken)
}

func TestRunAppStdioNoStdoutLogPollution(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	missingWL := filepath.Join(t.TempDir(), "absent-watchlist.yaml")
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}` + "\n"

	var stdout, stderr bytes.Buffer
	err := runApp(context.Background(), []string{
		"--stdio",
		"--data-dir", dataDir,
		"--watchlist", missingWL,
	}, mapEnv(nil), strings.NewReader(initReq), &stdout, &stderr)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	require.Len(t, lines, 1)
	var rpcResp map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &rpcResp))
	assert.Equal(t, "2.0", rpcResp["jsonrpc"])
	assert.Contains(t, stderr.String(), "mode=stdio")
}

func waitForHealthz(t *testing.T, ctx context.Context, client *http.Client, url string, errCh <-chan error) map[string]any {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case runErr := <-errCh:
			t.Fatalf("http server exited prematurely: %v", runErr)
		default:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr == nil && resp.StatusCode == http.StatusOK {
				var payload map[string]any
				require.NoError(t, json.Unmarshal(body, &payload))
				return payload
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", url)
	return nil
}
