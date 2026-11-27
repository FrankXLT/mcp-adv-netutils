package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/ascii"
	"github.com/FrankXLT/mcp-adv-netutils/internal/cronmon"
	"github.com/FrankXLT/mcp-adv-netutils/internal/dispatch"
	internaldns "github.com/FrankXLT/mcp-adv-netutils/internal/dns"
	"github.com/FrankXLT/mcp-adv-netutils/internal/http_ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/resolver"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	internalserver "github.com/FrankXLT/mcp-adv-netutils/internal/server"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
	"github.com/FrankXLT/mcp-adv-netutils/internal/tls"
	"github.com/FrankXLT/mcp-adv-netutils/internal/transport"
	"github.com/FrankXLT/mcp-adv-netutils/internal/webui"
	"github.com/FrankXLT/mcp-adv-netutils/internal/whois"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

type (
	runMode uint8

	rawCLIFlags struct {
		stdio, httpMode, sseCompat, sseLegacy, runWatchlistOnce bool
		ssePort, ttlSeconds                                     int
		listenAddr, allowCIDRs, denyCIDRs, allowedHosts         string
	}

	appConfig struct {
		Mode                                                       runMode
		HTTPAddr, DataDir, WatchlistPath                           string
		PassHash, PathSecret, LANToken                             string
		RemoteServerAddress, CustomWhoisServer                     string
		EnableSSECompat, AllowLockedCronSummary, WatchlistExplicit bool
		MaxStoreMB, PingCount, HTTPPingCount                       int
		AllowCIDRs, DenyCIDRs, AllowedHosts                        []string
		TTL, DNSTimeout, PingTimeout, HTTPPingTimeout, TLSTimeout  time.Duration
	}

	appRuntime struct {
		version    string
		cfg        *appConfig
		dbPath     string
		watchlist  *cronmon.WatchlistFile
		deadbolt   *security.Deadbolt
		jobStore   *store.JobStore
		dispatcher *dispatch.Dispatcher
		mcpServer  *mcpserver.MCPServer
		scheduler  *cronmon.Scheduler
	}
)

const (
	modeStdio runMode = iota
	modeHTTP
	modeWatchlistOnce

	defaultVersion        = "2.0.0"
	defaultHTTPAddr       = ":8000"
	defaultWatchlistFile  = "watchlist.yaml"
	defaultAppWatchlist   = "/app/watchlist.yaml"
	defaultDataDir        = "/data"
	appCacheSubdir        = "mcp-adv-netutils"
	storeDBFilename       = "netutils_jobs.db"
	deadboltStateFilename = ".deadbolt_state.json"
	defaultReaperInterval = time.Hour
	defaultStopTimeout    = 10 * time.Second
	dataDirPerm           = 0o750
	minPathSecretLen      = 32
)

var version = defaultVersion

func main() {
	if err := runApp(context.Background(), os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err.Error())
		os.Exit(1)
	}
}

func runApp(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	cfg, err := parseConfig(args, getenv, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	logger := log.New(stderr, "", log.LstdFlags)
	rt, err := initRuntime(sigCtx, cfg, logger)
	if err != nil {
		return err
	}
	defer func() { _ = rt.jobStore.Close() }()

	switch cfg.Mode {
	case modeWatchlistOnce:
		return runWatchlistOnce(sigCtx, rt, stdout)
	case modeHTTP:
		return runHTTPMode(sigCtx, rt, logger)
	case modeStdio:
		return runStdioMode(sigCtx, rt, stdin, stdout, logger)
	default:
		return fmt.Errorf("unsupported run mode %d", cfg.Mode)
	}
}

func parseConfig(args []string, getenv func(string) string, stderr io.Writer) (*appConfig, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	cfg, raw := &appConfig{}, &rawCLIFlags{}
	fs := flag.NewFlagSet("mcp-adv-netutils", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&raw.stdio, "stdio", false, "Run JSON-RPC MCP server over stdin/stdout (default)")
	fs.BoolVar(&raw.httpMode, "http", false, "Start Two-Doorway HTTP server and /web Operator Studio")
	fs.StringVar(&cfg.HTTPAddr, "http-addr", defaultHTTPAddr, "HTTP listen address")
	fs.StringVar(&raw.listenAddr, "listen", "", "Backward-compatible alias for --http-addr")
	fs.BoolVar(&raw.sseCompat, "sse-compat", false, "Enable legacy LAN /sse Streamable HTTP route")
	fs.BoolVar(&raw.sseLegacy, "sse", false, "Backward-compatible alias enabling --http and --sse-compat")
	fs.IntVar(&raw.ssePort, "sse-port", 8000, "Backward-compatible HTTP port when --sse is enabled")
	fs.BoolVar(&raw.runWatchlistOnce, "run-watchlist-once", false, "Execute enabled watchlist items once, print ASCII summary, and exit")
	fs.StringVar(&cfg.DataDir, "data-dir", "", "Directory for SQLite job store and Deadbolt state (env NETUTILS_DATA_DIR)")
	fs.StringVar(&cfg.WatchlistPath, "watchlist", "", "Path to YAML cron watchlist (env NETUTILS_WATCHLIST)")
	fs.IntVar(&cfg.MaxStoreMB, "max-store-mb", 256, "Maximum SQLite job store size in MiB")
	fs.StringVar(&raw.allowCIDRs, "allow-cidrs", "", "Comma-separated allowlist CIDRs (merged with NETUTILS_ALLOW_CIDRS)")
	fs.StringVar(&raw.denyCIDRs, "deny-cidrs", "169.254.0.0/16", "Comma-separated denylist CIDRs (merged with NETUTILS_DENY_CIDRS)")
	fs.StringVar(&raw.allowedHosts, "allowed-hosts", "", "Comma-separated allowed Host values for /web (merged with NETUTILS_ALLOWED_HOSTS)")
	fs.IntVar(&raw.ttlSeconds, "ttl-seconds", 1800, "Deadbolt sliding unlock TTL in seconds (env NETUTILS_TTL_SECONDS)")
	fs.StringVar(&cfg.RemoteServerAddress, "remote-server-address", "", "Custom DNS-over-HTTPS server address")
	fs.StringVar(&cfg.CustomWhoisServer, "custom-whois-server", "", "Custom WHOIS server address")
	fs.DurationVar(&cfg.DNSTimeout, "timeout", 5*time.Second, "Timeout for DNS queries")
	fs.DurationVar(&cfg.PingTimeout, "ping-timeout", 5*time.Second, "Timeout for ping operations")
	fs.IntVar(&cfg.PingCount, "ping-count", 4, "Default number of ping packets to send")
	fs.DurationVar(&cfg.HTTPPingTimeout, "http-ping-timeout", 10*time.Second, "Timeout for HTTP ping operations")
	fs.IntVar(&cfg.HTTPPingCount, "http-ping-count", 1, "Default number of HTTP ping requests to send")
	fs.DurationVar(&cfg.TLSTimeout, "tls-timeout", 10*time.Second, "Timeout for TLS certificate checks")
	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("parse flags: %w", err)
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	visited := make(map[string]bool, fs.NFlag())
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	return finalizeConfig(cfg, raw, visited, getenv)
}

func finalizeConfig(cfg *appConfig, raw *rawCLIFlags, visited map[string]bool, getenv func(string) string) (*appConfig, error) {
	httpReq := raw.httpMode || raw.sseLegacy
	if raw.runWatchlistOnce && (httpReq || raw.stdio) {
		return nil, errors.New("--run-watchlist-once cannot be combined with --http, --sse, or --stdio")
	}
	if raw.stdio && httpReq {
		return nil, errors.New("--stdio cannot be combined with --http or --sse")
	}
	switch {
	case raw.runWatchlistOnce:
		cfg.Mode = modeWatchlistOnce
	case httpReq:
		cfg.Mode = modeHTTP
	default:
		cfg.Mode = modeStdio
	}
	if visited["listen"] && !visited["http-addr"] {
		cfg.HTTPAddr = firstNonEmpty(raw.listenAddr, defaultHTTPAddr)
	}
	cfg.HTTPAddr = firstNonEmpty(cfg.HTTPAddr, defaultHTTPAddr)
	cfg.EnableSSECompat = raw.sseCompat || raw.sseLegacy
	if raw.sseLegacy && !visited["http-addr"] && !visited["listen"] {
		if raw.ssePort < 1 || raw.ssePort > 65535 {
			return nil, fmt.Errorf("invalid --sse-port %d: must be between 1 and 65535", raw.ssePort)
		}
		cfg.HTTPAddr = ":" + strconv.Itoa(raw.ssePort)
	}
	ttlSec := raw.ttlSeconds
	if !visited["ttl-seconds"] {
		if rawEnv := strings.TrimSpace(getenv("NETUTILS_TTL_SECONDS")); rawEnv != "" {
			parsed, err := strconv.Atoi(rawEnv)
			if err != nil {
				return nil, fmt.Errorf("parse NETUTILS_TTL_SECONDS %q: %w", rawEnv, err)
			}
			ttlSec = parsed
		}
	}
	if err := validateToolBounds(cfg, ttlSec); err != nil {
		return nil, err
	}
	if cfg.MaxStoreMB == 0 {
		cfg.MaxStoreMB = 256
	}
	var err error
	if cfg.DataDir, err = resolveDataDir(cfg.DataDir, getenv("NETUTILS_DATA_DIR"), cfg.Mode); err != nil {
		return nil, err
	}
	if cfg.AllowLockedCronSummary, err = parseEnvBool(getenv("NETUTILS_ALLOW_LOCKED_CRON_SUMMARY")); err != nil {
		return nil, err
	}
	cfg.TTL = time.Duration(ttlSec) * time.Second
	explicitWatchlist := firstNonEmpty(cfg.WatchlistPath, getenv("NETUTILS_WATCHLIST"))
	cfg.WatchlistExplicit = explicitWatchlist != ""
	cfg.WatchlistPath = resolveWatchlistPath(explicitWatchlist, defaultWatchlistFile, defaultAppWatchlist)
	cfg.AllowCIDRs = mergeCSV(getenv("NETUTILS_ALLOW_CIDRS"), raw.allowCIDRs)
	cfg.DenyCIDRs = mergeCSV(getenv("NETUTILS_DENY_CIDRS"), raw.denyCIDRs)
	cfg.AllowedHosts = mergeCSV(getenv("NETUTILS_ALLOWED_HOSTS"), raw.allowedHosts)
	cfg.PassHash = firstNonEmpty(getenv("PASS_HASH"), getenv("NETUTILS_PASS_HASH"))
	cfg.PathSecret = firstNonEmpty(getenv("PATH_SECRET"), getenv("NETUTILS_PATH_SECRET"))
	cfg.LANToken = firstNonEmpty(getenv("LAN_MCP_TOKEN"), getenv("NETUTILS_LAN_MCP_TOKEN"))
	cfg.RemoteServerAddress = strings.TrimSpace(cfg.RemoteServerAddress)
	cfg.CustomWhoisServer = strings.TrimSpace(cfg.CustomWhoisServer)
	return cfg, nil
}

func validateToolBounds(cfg *appConfig, ttlSec int) error {
	for _, chk := range []struct {
		ok  bool
		msg string
	}{
		{ttlSec >= 0, "--ttl-seconds must be >= 0"},
		{cfg.MaxStoreMB >= 0, "--max-store-mb must be >= 0"},
		{cfg.DNSTimeout > 0, "--timeout must be > 0"},
		{cfg.PingTimeout > 0, "--ping-timeout must be > 0"},
		{cfg.PingCount > 0, "--ping-count must be > 0"},
		{cfg.HTTPPingTimeout > 0, "--http-ping-timeout must be > 0"},
		{cfg.HTTPPingCount > 0, "--http-ping-count must be > 0"},
		{cfg.TLSTimeout > 0, "--tls-timeout must be > 0"},
	} {
		if !chk.ok {
			return errors.New(chk.msg)
		}
	}
	return nil
}

func resolveDataDir(flagVal, envVal string, mode runMode) (string, error) {
	if explicit := firstNonEmpty(flagVal, envVal); explicit != "" {
		return filepath.Clean(explicit), nil
	}
	if mode == modeHTTP {
		return defaultDataDir, nil
	}
	if isWritableDir(defaultDataDir, false) {
		return defaultDataDir, nil
	}
	if cacheBase, err := os.UserCacheDir(); err == nil && strings.TrimSpace(cacheBase) != "" {
		if candidate := filepath.Join(cacheBase, appCacheSubdir); isWritableDir(candidate, true) {
			return candidate, nil
		}
	}
	if tmpCandidate := filepath.Join(os.TempDir(), appCacheSubdir); isWritableDir(tmpCandidate, true) {
		return tmpCandidate, nil
	}
	return "", errors.New("unable to locate a writable data directory; specify --data-dir or NETUTILS_DATA_DIR")
}

func isWritableDir(dir string, create bool) bool {
	if create && os.MkdirAll(dir, dataDirPerm) != nil {
		return false
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return false
	}
	f, err := os.CreateTemp(dir, ".netutils-writecheck-*")
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = os.Remove(f.Name())
	return true
}

func initRuntime(ctx context.Context, cfg *appConfig, logger *log.Logger) (*appRuntime, error) {
	ver := firstNonEmpty(version, defaultVersion)
	guard, err := security.NewTargetGuard(cfg.AllowCIDRs, cfg.DenyCIDRs)
	if err != nil {
		return nil, fmt.Errorf("create target guard: %w", err)
	}
	deadbolt := security.NewDeadbolt(security.DeadboltConfig{
		PassHash: cfg.PassHash, TTL: cfg.TTL, AllowLockedCronSummary: cfg.AllowLockedCronSummary,
		StatePath: filepath.Join(cfg.DataDir, deadboltStateFilename),
	})
	dbPath := filepath.Join(cfg.DataDir, storeDBFilename)
	jobStore, err := store.Open(ctx, dbPath, cfg.MaxStoreMB)
	if err != nil {
		return nil, fmt.Errorf("open job store: %w", err)
	}
	mcpSrv, disp, err := internalserver.SetupServerWithDispatcher(&internalserver.NetUtilsConfig{
		QueryConfig:    &internaldns.QueryConfig{Timeout: cfg.DNSTimeout, RemoteServerAddress: cfg.RemoteServerAddress, Guard: guard},
		WhoisConfig:    &whois.Config{CustomServer: cfg.CustomWhoisServer, Timeout: 10 * time.Second, Guard: guard},
		ResolverConfig: &resolver.Config{Timeout: cfg.DNSTimeout, Guard: guard},
		PingConfig:     &ping.Config{Timeout: cfg.PingTimeout, Count: cfg.PingCount, Guard: guard},
		HTTPPingConfig: &http_ping.Config{Timeout: cfg.HTTPPingTimeout, Count: cfg.HTTPPingCount, Guard: guard},
		TLSConfig:      &tls.Config{Timeout: cfg.TLSTimeout, Port: 443, Guard: guard},
		Version:        ver, Guard: guard, Store: jobStore, Deadbolt: deadbolt,
		DefaultStdio: cfg.Mode == modeStdio, AllowLockedCronSummary: cfg.AllowLockedCronSummary,
	})
	if err != nil {
		_ = jobStore.Close()
		return nil, fmt.Errorf("setup mcp server: %w", err)
	}
	watchlistPath := cfg.WatchlistPath
	if !cfg.WatchlistExplicit && cfg.DataDir != "" {
		watchlistPath = seedWritableWatchlist(cfg.DataDir, watchlistPath)
	}
	wlPath, wl, err := loadWatchlistOrEmpty(watchlistPath, logger)
	if err != nil {
		_ = jobStore.Close()
		return nil, err
	}
	sched, err := cronmon.NewScheduler(&cronmon.SchedulerConfig{
		Store: jobStore, WatchlistPath: wlPath, Watchlist: wl, Runner: disp.CronRunner(), Guard: guard,
	})
	if err != nil {
		_ = jobStore.Close()
		return nil, fmt.Errorf("create cron scheduler: %w", err)
	}
	disp.SetScheduler(sched)
	if err := disp.ReconcileDestinationMonitors(ctx); err != nil {
		_ = jobStore.Close()
		return nil, fmt.Errorf("reconcile destination monitors: %w", err)
	}
	return &appRuntime{
		version: ver, cfg: cfg, dbPath: dbPath, watchlist: wl, deadbolt: deadbolt,
		jobStore: jobStore, dispatcher: disp, mcpServer: mcpSrv, scheduler: sched,
	}, nil
}

func resolveWatchlistPath(explicit string, candidates ...string) string {
	if trimmed := strings.TrimSpace(explicit); trimmed != "" {
		return trimmed
	}
	for _, candidate := range candidates {
		clean := filepath.Clean(strings.TrimSpace(candidate))
		if clean == "" || clean == "." {
			continue
		}
		if info, err := os.Stat(clean); err == nil && !info.IsDir() {
			// #nosec G304 -- candidate watchlist path is restricted to known defaults or test paths.
			if f, openErr := os.Open(clean); openErr == nil {
				_ = f.Close()
				return clean
			}
		}
	}
	return ""
}

func buildHTTPHandler(rt *appRuntime) (http.Handler, error) {
	webHandler, err := webui.NewHandler(webui.Config{
		Version: rt.version, Dispatcher: rt.dispatcher, Store: rt.jobStore,
		Scheduler: rt.scheduler, Deadbolt: rt.deadbolt, AllowLockedCronSummary: rt.cfg.AllowLockedCronSummary,
	})
	if err != nil {
		return nil, fmt.Errorf("create webui handler: %w", err)
	}
	httpHandler, err := transport.NewHTTPHandler(transport.HTTPConfig{
		Version: rt.version, MCPServer: rt.mcpServer, PathSecret: rt.cfg.PathSecret,
		LANToken: rt.cfg.LANToken, EnableSSECompat: rt.cfg.EnableSSECompat, AllowedHosts: rt.cfg.AllowedHosts,
		Deadbolt: rt.deadbolt, WebHandler: webHandler,
		HealthProvider: func(ctx context.Context) map[string]any {
			out := make(map[string]any)
			if res, listErr := rt.scheduler.ManageWatchlist(ctx, cronmon.ManageParams{Action: "list"}); listErr == nil {
				out["watchlist_items"] = len(res.Items)
			}
			if stats, statsErr := rt.jobStore.Stats(ctx); statsErr == nil {
				out["store"] = map[string]any{"jobs": stats.JobCount, "incidents": stats.IncidentCount, "cron_items": stats.CronStateCount, "size_bytes": stats.DBSizeBytes}
			} else {
				out["store_error"] = "unavailable"
			}
			return out
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create http handler: %w", err)
	}
	return httpHandler, nil
}

func runWatchlistOnce(ctx context.Context, rt *appRuntime, stdout io.Writer) error {
	runErr := rt.scheduler.RunOnce(ctx)
	cardCtx, cancelCard := context.WithTimeout(context.WithoutCancel(ctx), defaultStopTimeout)
	defer cancelCard()
	if _, card, cardErr := rt.scheduler.BuildCronStatusCard(cardCtx, "24h"); cardErr == nil && card != nil {
		if rendered, renderErr := ascii.Render(card, ascii.StyleDefault); renderErr == nil {
			_, _ = fmt.Fprintln(stdout, rendered)
		}
	}
	return finishStore(rt.jobStore, runErr, "run watchlist once")
}

func runHTTPMode(ctx context.Context, rt *appRuntime, logger *log.Logger) error {
	httpHandler, err := buildHTTPHandler(rt)
	if err != nil {
		return err
	}
	rt.jobStore.StartReaper(ctx, defaultReaperInterval)
	if err := rt.scheduler.Start(ctx); err != nil {
		return fmt.Errorf("start cron scheduler: %w", err)
	}
	logger.Printf("mcp-adv-netutils %s listening on %s (mode=http sse_compat=%t deadbolt=%t remote_doorway=%t db=%s watchlist_items=%d)", rt.version, rt.cfg.HTTPAddr, rt.cfg.EnableSSECompat, rt.deadbolt.IsEnabled(), len(rt.cfg.PathSecret) >= minPathSecretLen, rt.dbPath, len(rt.watchlist.Items))
	srvErr := transport.StartHTTPServer(ctx, rt.cfg.HTTPAddr, httpHandler)
	stopCtx, cancelStop := context.WithTimeout(context.WithoutCancel(ctx), defaultStopTimeout)
	defer cancelStop()
	if stopErr := rt.scheduler.Stop(stopCtx); stopErr != nil && srvErr == nil {
		srvErr = fmt.Errorf("stop cron scheduler: %w", stopErr)
	}
	return finishStore(rt.jobStore, srvErr, "http server")
}

func runStdioMode(ctx context.Context, rt *appRuntime, stdin io.Reader, stdout io.Writer, logger *log.Logger) error {
	logger.Printf("mcp-adv-netutils %s starting (mode=stdio deadbolt=%t db=%s watchlist_items=%d)", rt.version, rt.deadbolt.IsEnabled(), rt.dbPath, len(rt.watchlist.Items))
	stdioSrv := mcpserver.NewStdioServer(rt.mcpServer)
	stdioSrv.SetErrorLogger(logger)
	listenErr := stdioSrv.Listen(ctx, stdin, stdout)
	if errors.Is(listenErr, context.Canceled) {
		listenErr = nil
	}
	return finishStore(rt.jobStore, listenErr, "serve stdio")
}

func finishStore(jobStore *store.JobStore, runErr error, op string) error {
	closeErr := jobStore.Close()
	if runErr != nil {
		return fmt.Errorf("%s: %w", op, runErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close job store: %w", closeErr)
	}
	return nil
}

func mergeCSV(inputs ...string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, raw := range inputs {
		for item := range strings.SplitSeq(raw, ",") {
			if s := strings.TrimSpace(item); s != "" {
				if _, ok := seen[s]; !ok {
					seen[s] = struct{}{}
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func parseEnvBool(raw string) (bool, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return false, nil
	}
	v, err := strconv.ParseBool(trimmed)
	if err != nil {
		return false, fmt.Errorf("parse boolean env value %q: %w", raw, err)
	}
	return v, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
