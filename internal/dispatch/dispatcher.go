// Package dispatch provides the unified pure-Go diagnostic tool dispatcher,
// Deadbolt access enforcement, multi-style ASCII/JSON card formatting, and SQLite archival.
package dispatch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/ascii"
	"github.com/FrankXLT/mcp-adv-netutils/internal/cronmon"
	"github.com/FrankXLT/mcp-adv-netutils/internal/dns"
	"github.com/FrankXLT/mcp-adv-netutils/internal/http_ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/resolver"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
	"github.com/FrankXLT/mcp-adv-netutils/internal/tls"
	"github.com/FrankXLT/mcp-adv-netutils/internal/transport"
	"github.com/FrankXLT/mcp-adv-netutils/internal/whois"
)

// Config configures a Dispatcher instance with security guards, persistence, and tool defaults.
type Config struct {
	Version                string
	Deadbolt               *security.Deadbolt
	Guard                  *security.TargetGuard
	Store                  *store.JobStore
	Scheduler              *cronmon.Scheduler
	DNS                    *dns.QueryConfig
	Whois                  *whois.Config
	Resolver               *resolver.Config
	Ping                   *ping.Config
	HTTP                   *http_ping.Config
	TLS                    *tls.Config
	AllowLockedCronSummary bool
}

// Request represents a single unified tool dispatch invocation.
type Request struct {
	Tool         string         `json:"tool"`
	Args         map[string]any `json:"args,omitempty"`
	Style        string         `json:"style,omitempty"`
	Source       string         `json:"source,omitempty"`
	SkipDeadbolt bool           `json:"skip_deadbolt,omitempty"`
	SkipArchive  bool           `json:"skip_archive,omitempty"`
}

// WhiskerPoint represents one min/avg/max RTT and packet loss sample for SVG whisker charts.
type WhiskerPoint struct {
	Label   string  `json:"label"`
	MinMs   float64 `json:"minMs"`
	AvgMs   float64 `json:"avgMs"`
	MaxMs   float64 `json:"maxMs"`
	LossPct float64 `json:"lossPct"`
}

// WaterfallPhase represents one timing phase bar for SVG latency waterfall charts.
type WaterfallPhase struct {
	Label      string  `json:"label"`
	StartMs    float64 `json:"startMs"`
	DurationMs float64 `json:"durationMs"`
	IsTotal    bool    `json:"isTotal,omitempty"`
}

// LANHostView represents a discovered LAN host formatted for Operator Studio tables.
type LANHostView struct {
	IP        string  `json:"ip"`
	Hostname  string  `json:"hostname,omitempty"`
	MAC       string  `json:"mac,omitempty"`
	Vendor    string  `json:"vendor,omitempty"`
	Runtime   string  `json:"runtime,omitempty"`
	Segment   string  `json:"segment"`
	RTTMs     float64 `json:"rtt_ms,omitempty"`
	OpenPorts []int   `json:"open_ports,omitempty"`
}

// SnapshotDiffView represents added, removed, and changed host deltas against a baseline snapshot.
type SnapshotDiffView struct {
	BaselineID string   `json:"baseline_id"`
	CurrentID  string   `json:"current_id"`
	CapturedAt string   `json:"captured_at,omitempty"`
	Added      []string `json:"added"`
	Removed    []string `json:"removed"`
	Changed    []string `json:"changed"`
}

// LANInventoryView groups physical UAA and virtual LAA LAN hosts alongside optional snapshot deltas.
type LANInventoryView struct {
	BaselineID   string            `json:"baseline_id,omitempty"`
	CurrentID    string            `json:"current_id,omitempty"`
	CapturedAt   string            `json:"captured_at,omitempty"`
	Physical     []LANHostView     `json:"physical"`
	Virtual      []LANHostView     `json:"virtual"`
	SnapshotDiff *SnapshotDiffView `json:"snapshot_diff,omitempty"`
}

// TLSHealthView summarizes leaf certificate health and TLS handshake posture for chart views.
type TLSHealthView struct {
	Valid         bool   `json:"valid"`
	Subject       string `json:"subject,omitempty"`
	Issuer        string `json:"issuer,omitempty"`
	DaysRemaining int    `json:"days_remaining"`
	NotAfter      string `json:"not_after,omitempty"`
	HostnameMatch bool   `json:"hostname_match"`
	Protocol      string `json:"protocol,omitempty"`
	Cipher        string `json:"cipher,omitempty"`
}

// DNSComparisonRow represents one resolver comparison entry for split-DNS and host-card views.
type DNSComparisonRow struct {
	Resolver  string   `json:"resolver"`
	LatencyMs float64  `json:"latency_ms,omitempty"`
	Answers   []string `json:"answers,omitempty"`
	Status    string   `json:"status"`
	Match     bool     `json:"match"`
}

// Outcome is the unified result returned across MCP, Operator Studio HTTP API, and cron execution.
type Outcome struct {
	JobID          string                   `json:"job_id"`
	Tool           string                   `json:"tool"`
	Target         string                   `json:"target"`
	Status         string                   `json:"status"`
	Summary        string                   `json:"summary"`
	CreatedAt      string                   `json:"created_at"`
	ExpiresAt      string                   `json:"expires_at"`
	DurationMS     int64                    `json:"duration_ms"`
	Style          string                   `json:"style"`
	Output         string                   `json:"output"`
	ASCII          map[string]string        `json:"ascii,omitempty"`
	Data           any                      `json:"data,omitempty"`
	Whiskers       []WhiskerPoint           `json:"whiskers,omitempty"`
	Waterfall      []WaterfallPhase         `json:"waterfall,omitempty"`
	LANInventory   *LANInventoryView        `json:"lan_inventory,omitempty"`
	SnapshotDiff   *SnapshotDiffView        `json:"snapshot_diff,omitempty"`
	TLSHealth      *TLSHealthView           `json:"tls_health,omitempty"`
	DNSComparisons []DNSComparisonRow       `json:"dns_comparisons,omitempty"`
	Deadbolt       *security.DeadboltStatus `json:"deadbolt,omitempty"`
}

// Dispatcher routes all 33 diagnostic tools, enforces Deadbolt policy, renders multi-style cards, and archives jobs.
type Dispatcher struct {
	cfg       Config
	version   string
	deadbolt  *security.Deadbolt
	guard     *security.TargetGuard
	jobStore  *store.JobStore
	dnsCfg    *dns.QueryConfig
	whoisCfg  *whois.Config
	resCfg    *resolver.Config
	pingCfg   *ping.Config
	httpCfg   *http_ping.Config
	tlsCfg    *tls.Config
	mu        sync.RWMutex
	destMu    sync.Mutex
	scheduler *cronmon.Scheduler
}

type toolExec struct {
	Target         string
	Status         string
	Summary        string
	Data           any
	Card           *ascii.ReportCard
	Whiskers       []WhiskerPoint
	Waterfall      []WaterfallPhase
	LANInventory   *LANInventoryView
	SnapshotDiff   *SnapshotDiffView
	TLSHealth      *TLSHealthView
	DNSComparisons []DNSComparisonRow
	Deadbolt       *security.DeadboltStatus
}

const (
	defaultVersion = "dev"
	jobIDRandBytes = 6
)

var (
	// ErrUnknownTool indicates an unrecognized tool name was requested.
	ErrUnknownTool = errors.New("unknown tool")
	// ErrDeadboltLocked indicates access was denied because Deadbolt protection is locked.
	ErrDeadboltLocked = errors.New("deadbolt is locked")
	// ErrInvalidStyle indicates an unsupported ASCII/JSON render style was requested.
	ErrInvalidStyle = errors.New("invalid render style")
	// ErrInvalidArgs indicates missing or malformed tool arguments.
	ErrInvalidArgs = errors.New("invalid tool arguments")

	canonicalToolNames = []string{
		"arp_neighbor_sweep", "dns_reverse_batch", "get_cron_status", "get_job_report",
		"http_ping", "local_dns_query", "lock_netutils", "mac_vendor_lookup",
		"manage_cron_watchlist", "manage_saved_destinations", "mdns_ssdp_discover", "mtr_path_quality",
		"mtu_path_probe", "ping", "recipe_diff_dns", "recipe_diff_http",
		"recipe_diff_ping", "recipe_diff_snapshot", "recipe_host_card", "recipe_lan_radar",
		"recipe_path_autopsy", "recipe_wake_verify", "remote_dns_query", "render_run_digest",
		"resolve_hostname", "snmp_switch_port", "split_dns_audit", "tcp_port_scan",
		"tls_certificate_check", "traceroute", "unlock_netutils", "whois_query",
		"wol_wake",
	}

	knownToolSet = func() map[string]struct{} {
		m := make(map[string]struct{}, len(canonicalToolNames))
		for _, n := range canonicalToolNames {
			m[n] = struct{}{}
		}
		return m
	}()
)

// New constructs a Dispatcher from cfg, populating tool defaults and propagating cfg.Guard.
//
//nolint:gocritic // hugeParam: Config value signature matches public dispatch API contract.
func New(cfg Config) (*Dispatcher, error) {
	d := &Dispatcher{
		cfg: cfg, version: firstNonEmpty(cfg.Version, defaultVersion),
		deadbolt: cfg.Deadbolt, guard: cfg.Guard, jobStore: cfg.Store, scheduler: cfg.Scheduler,
	}
	d.dnsCfg = initCfg(cfg.DNS, dns.QueryConfig{Timeout: 5 * time.Second}, func(c *dns.QueryConfig) {
		c.LocalServers = slices.Clone(c.LocalServers)
		if c.Guard == nil {
			c.Guard = cfg.Guard
		}
	})
	d.whoisCfg = initCfg(cfg.Whois, whois.Config{Timeout: 10 * time.Second}, func(c *whois.Config) {
		if c.Guard == nil {
			c.Guard = cfg.Guard
		}
	})
	d.resCfg = initCfg(cfg.Resolver, resolver.Config{Timeout: 5 * time.Second}, func(c *resolver.Config) {
		if c.Guard == nil {
			c.Guard = cfg.Guard
		}
	})
	d.pingCfg = initCfg(cfg.Ping, ping.Config{Timeout: 5 * time.Second, Count: 4}, func(c *ping.Config) {
		if c.Guard == nil {
			c.Guard = cfg.Guard
		}
	})
	d.httpCfg = initCfg(cfg.HTTP, http_ping.Config{Timeout: 10 * time.Second, Count: 1}, func(c *http_ping.Config) {
		if c.Guard == nil {
			c.Guard = cfg.Guard
		}
	})
	d.tlsCfg = initCfg(cfg.TLS, tls.Config{Timeout: 10 * time.Second, Port: 443}, func(c *tls.Config) {
		if c.Guard == nil {
			c.Guard = cfg.Guard
		}
	})
	return d, nil
}

func initCfg[T any](src *T, def T, fix func(*T)) *T {
	cp := def
	if src != nil {
		cp = *src
	}
	fix(&cp)
	return &cp
}

// SetScheduler safely sets or replaces the cronmon.Scheduler reference.
func (d *Dispatcher) SetScheduler(s *cronmon.Scheduler) {
	d.mu.Lock()
	d.scheduler = s
	d.mu.Unlock()
}

// Scheduler returns the currently attached cronmon.Scheduler (thread-safe).
func (d *Dispatcher) Scheduler() *cronmon.Scheduler {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.scheduler
}

// Store returns the configured SQLite JobStore.
func (d *Dispatcher) Store() *store.JobStore { return d.jobStore }

// Deadbolt returns the configured Deadbolt lock manager.
func (d *Dispatcher) Deadbolt() *security.Deadbolt { return d.deadbolt }

// Guard returns the configured TargetGuard policy.
func (d *Dispatcher) Guard() *security.TargetGuard { return d.guard }

// Version returns the configured service version string.
func (d *Dispatcher) Version() string { return d.version }

// ToolNames returns a sorted slice of all 33 supported tool names.
func (d *Dispatcher) ToolNames() []string { return slices.Clone(canonicalToolNames) }

// Dispatch validates Deadbolt access and style, executes req.Tool, renders ASCII/JSON cards, and archives jobs.
func (d *Dispatcher) Dispatch(ctx context.Context, req Request) (*Outcome, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("request context canceled: %w", err)
	}
	tool := strings.ToLower(strings.TrimSpace(req.Tool))
	if _, ok := knownToolSet[tool]; !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownTool, req.Tool)
	}
	normStyle, err := ascii.NormalizeStyle(req.Style)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStyle, err)
	}
	if lockedOut, handled, lockErr := d.checkDeadboltPolicy(ctx, tool, &req, normStyle); lockErr != nil || handled {
		return lockedOut, lockErr
	}
	if tool == "get_job_report" {
		return d.GetJobReport(ctx, (&argReader{m: req.Args}).str("job_id", "id", "target"), normStyle)
	}

	started := time.Now()
	execRes, err := d.executeTool(ctx, tool, req.Args, started)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	shouldArchive := !req.SkipArchive && d.jobStore != nil && isArchivableTool(tool)
	var jobID string
	var expiresAt time.Time
	if shouldArchive {
		if jobID, err = newJobID(now.Unix()); err != nil {
			return nil, err
		}
		expiresAt = now.Add(store.DefaultRetention)
	}
	out, err := finalizeOutcome(tool, normStyle, execRes, now, time.Since(started).Milliseconds(), jobID, expiresAt)
	if err != nil {
		return nil, err
	}
	if shouldArchive {
		if err := d.archiveOutcome(ctx, out, req.Source, now, expiresAt); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// GetJobReport retrieves a persisted job from SQLite and formats it in the requested style.
func (d *Dispatcher) GetJobReport(ctx context.Context, jobID, style string) (*Outcome, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}
	normStyle, err := ascii.NormalizeStyle(style)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStyle, err)
	}
	cleanID := strings.TrimSpace(jobID)
	if cleanID == "" {
		return nil, fmt.Errorf("%w: parameter \"job_id\" is required", ErrInvalidArgs)
	}
	if d.jobStore == nil {
		return nil, errors.New("job store is not configured")
	}
	rec, err := d.jobStore.GetJob(ctx, cleanID)
	if err != nil {
		return nil, fmt.Errorf("load job %q: %w", cleanID, err)
	}
	return outcomeFromJobRecord(rec, normStyle)
}

// CronRunner returns a cronmon.RunnerFunc executing watchlist items via Dispatch with Deadbolt and archival bypassed.
func (d *Dispatcher) CronRunner() cronmon.RunnerFunc {
	return func(ctx context.Context, item cronmon.WatchItem) (*cronmon.RunResult, error) {
		args := maps.Clone(item.Args)
		if args == nil {
			args = make(map[string]any)
		}
		if t := strings.TrimSpace(item.Target); t != "" {
			if existing, ok := args["target"].(string); !ok || strings.TrimSpace(existing) == "" {
				args["target"] = t
			}
		}
		out, err := d.Dispatch(ctx, Request{
			Tool: item.Tool, Args: args, Style: ascii.StyleDefault,
			Source: "cron", SkipDeadbolt: true, SkipArchive: true,
		})
		if err != nil {
			return nil, err
		}
		payloadJSON, err := encodePayloadEnvelope(out)
		if err != nil {
			return nil, err
		}
		return &cronmon.RunResult{
			Status: out.Status, Summary: out.Summary, ASCIIDefault: out.ASCII[ascii.StyleDefault],
			PayloadJSON: payloadJSON, DurationMS: out.DurationMS,
		}, nil
	}
}

func (d *Dispatcher) checkDeadboltPolicy(ctx context.Context, tool string, req *Request, normStyle string) (*Outcome, bool, error) {
	doorway := transport.DoorwayFromContext(ctx)
	if req.SkipDeadbolt || doorway == transport.DoorwayLAN || doorway == transport.DoorwayStdio ||
		tool == "unlock_netutils" || tool == "lock_netutils" {
		return nil, false, nil
	}
	if d.deadbolt == nil || !d.deadbolt.IsEnabled() || d.deadbolt.IsUnlocked() {
		return nil, false, nil
	}
	if tool == "get_cron_status" && (d.cfg.AllowLockedCronSummary || d.deadbolt.AllowLockedCronSummary()) {
		started := time.Now()
		summary, err := d.loadCronSummary(ctx, (&argReader{m: req.Args}).str("period", "target"))
		if err != nil {
			return nil, true, err
		}
		durMS := time.Since(started).Milliseconds()
		st := d.deadbolt.Status()
		execRes := buildLockedCronSummaryExec(summary, durMS, &st)
		out, err := finalizeOutcome("get_cron_status", normStyle, execRes, time.Now().UTC(), durMS, "", time.Time{})
		return out, true, err
	}
	return nil, true, ErrDeadboltLocked
}

func (d *Dispatcher) loadCronSummary(ctx context.Context, period string) (*store.CronSummary, error) {
	if d.jobStore != nil {
		summary, err := d.jobStore.GetCronStatus(ctx, period)
		if err != nil {
			return nil, fmt.Errorf("get cron status (%s): %w", period, err)
		}
		return summary, nil
	}
	if sched := d.Scheduler(); sched != nil {
		summary, _, err := sched.BuildCronStatusCard(ctx, period)
		if err != nil {
			return nil, fmt.Errorf("build cron status (%s): %w", period, err)
		}
		return summary, nil
	}
	return nil, errors.New("cron scheduler or job store is not configured")
}

func (d *Dispatcher) executeTool(ctx context.Context, tool string, args map[string]any, started time.Time) (*toolExec, error) {
	r := &argReader{m: args}
	switch tool {
	case "local_dns_query", "remote_dns_query", "whois_query", "resolve_hostname", "ping", "tls_certificate_check",
		"http_ping", "mac_vendor_lookup", "traceroute", "tcp_port_scan", "dns_reverse_batch", "wol_wake":
		return d.runCoreTool(ctx, tool, r, started)
	case "arp_neighbor_sweep", "mtu_path_probe", "mtr_path_quality", "mdns_ssdp_discover", "split_dns_audit", "snmp_switch_port":
		return d.runProbeTool(ctx, tool, r, started)
	case "get_cron_status", "manage_cron_watchlist", "manage_saved_destinations", "unlock_netutils", "lock_netutils":
		return d.runAdminTool(ctx, tool, r, started)
	default:
		return d.runRecipeTool(ctx, tool, r, started)
	}
}

func (d *Dispatcher) archiveOutcome(ctx context.Context, out *Outcome, source string, now, expiresAt time.Time) error {
	payloadJSON, err := encodePayloadEnvelope(out)
	if err != nil {
		return err
	}
	rec := &store.JobRecord{
		JobID: out.JobID, ToolName: out.Tool, Target: out.Target, Source: firstNonEmpty(source, "dispatch"),
		Status: out.Status, Summary: out.Summary, PayloadJSON: payloadJSON, ASCIIDefault: out.ASCII[ascii.StyleDefault],
		DurationMS: out.DurationMS, CreatedAt: now.Unix(), ExpiresAt: expiresAt.Unix(), IsIncident: out.Status != "OK",
	}
	if err := d.jobStore.SaveJob(ctx, rec); err != nil {
		return fmt.Errorf("archive job %q: %w", out.JobID, err)
	}
	return nil
}

func isArchivableTool(tool string) bool {
	return tool != "unlock_netutils" && tool != "lock_netutils" &&
		tool != "get_job_report" && tool != "get_cron_status" &&
		tool != "manage_saved_destinations"
}

func newJobID(createdAt int64) (string, error) {
	var buf [jobIDRandBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate job_id entropy: %w", err)
	}
	return fmt.Sprintf("job_%d_%s", createdAt, hex.EncodeToString(buf[:])), nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
