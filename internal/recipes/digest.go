// Package recipes implements multi-tool network diagnostic workflows and run digests.
package recipes

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/ascii"
	"github.com/FrankXLT/mcp-adv-netutils/internal/dns"
	"github.com/FrankXLT/mcp-adv-netutils/internal/http_ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/probe"
	"github.com/FrankXLT/mcp-adv-netutils/internal/resolver"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
	"github.com/FrankXLT/mcp-adv-netutils/internal/tls"
	"golang.org/x/sync/errgroup"
)

// Dependencies groups shared security, tool configuration, and persistence dependencies for recipes.
type Dependencies struct {
	Guard    *security.TargetGuard
	DNS      *dns.QueryConfig
	Ping     *ping.Config
	HTTP     *http_ping.Config
	TLS      *tls.Config
	Resolver *resolver.Config
	Store    *store.JobStore
}

// RecipeResult holds the structured output, overall severity status, and ReportCard for a recipe execution.
type RecipeResult struct {
	Status       string            `json:"status"`
	Summary      string            `json:"summary"`
	Data         any               `json:"data,omitempty"`
	Card         *ascii.ReportCard `json:"card,omitempty"`
	SparkValues  []float64         `json:"spark_values,omitempty"`
	HealthStates []string          `json:"health_states,omitempty"`
}

// RenderDigestParams specifies job IDs or time-window/status filters for rendering a consolidated run digest.
type RenderDigestParams struct {
	JobIDs        []string `json:"job_ids,omitempty"`
	Window        string   `json:"window,omitempty"`
	Since         string   `json:"since,omitempty"`
	Until         string   `json:"until,omitempty"`
	Target        string   `json:"target,omitempty"`
	ToolName      string   `json:"tool_name,omitempty"`
	Status        string   `json:"status,omitempty"`
	IncidentsOnly bool     `json:"incidents_only,omitempty"`
	Limit         int      `json:"limit,omitempty"`
}

// DigestJobEntry summarizes a single stored job within a consolidated run digest.
type DigestJobEntry struct {
	JobID      string `json:"job_id"`
	ToolName   string `json:"tool_name"`
	Target     string `json:"target"`
	Source     string `json:"source"`
	Status     string `json:"status"`
	Summary    string `json:"summary"`
	DurationMS int64  `json:"duration_ms"`
	CreatedAt  int64  `json:"created_at"`
	IsIncident bool   `json:"is_incident"`
}

// DigestData contains aggregate counts, window summary, and severity-sorted job entries for ExecuteRenderRunDigest.
type DigestData struct {
	TotalJobs     int                     `json:"total_jobs"`
	OKCount       int                     `json:"ok_count"`
	WarnCount     int                     `json:"warn_count"`
	FailCount     int                     `json:"fail_count"`
	IncidentCount int                     `json:"incident_count"`
	Window        string                  `json:"window,omitempty"`
	Since         string                  `json:"since,omitempty"`
	Until         string                  `json:"until,omitempty"`
	WindowSummary *store.JobWindowSummary `json:"window_summary,omitempty"`
	Truncated     bool                    `json:"truncated,omitempty"`
	OmittedJobs   int                     `json:"omitted_jobs,omitempty"`
	Jobs          []DigestJobEntry        `json:"jobs"`
	Timestamp     string                  `json:"timestamp"`
}

// DiffPingTCPCheck records TCP SYN-ACK/RST reachability for a specific port.
type DiffPingTCPCheck struct {
	Port  int     `json:"port"`
	State string  `json:"state"`
	RTTMs float64 `json:"rtt_ms"`
}

// DiffSnapshotEntry represents a single added, removed, or changed ARP neighbor.
type DiffSnapshotEntry struct {
	DiffType    string `json:"diff_type"`
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	PreviousMAC string `json:"previous_mac,omitempty"`
	Vendor      string `json:"vendor,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Detail      string `json:"detail"`
}

type digestCounts struct {
	ok, warn, fail, incidents int
}

type cardSpec struct {
	ToolName     string
	Title        string
	Subtitle     string
	Target       string
	Status       string
	Summary      string
	DurationMS   int64
	Metrics      []ascii.MetricKV
	Headers      []string
	Rows         []ascii.TableRow
	SparkValues  []float64
	HealthStates []string
	Notes        []string
	RawData      any
}

const (
	// StatusOK indicates all checks passed without anomalies.
	StatusOK = "OK"
	// StatusWARN indicates degraded behavior, partial divergence, or non-fatal anomalies.
	StatusWARN = "WARN"
	// StatusFAIL indicates critical failure or unreachability.
	StatusFAIL = "FAIL"
	// StatusINFO indicates informational or unclassified items.
	StatusINFO = "INFO"

	defaultDigestLimit = 25
	maxDigestLimit     = 100
	procNetRoutePath   = "/proc/net/route"
	diffTagAdded       = "[+] ADDED"
	diffTagRemoved     = "[-] REMOVED"
	diffTagChanged     = "[~] CHANGED"
)

// ExecuteRenderRunDigest loads stored JobRecords by IDs or time-window/status filters and builds a consolidated ReportCard.
//
//nolint:gocritic // Exported recipe signature accepts RenderDigestParams by value.
func ExecuteRenderRunDigest(ctx context.Context, deps Dependencies, params RenderDigestParams) (*RecipeResult, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if deps.Store == nil {
		return nil, errors.New("job store is required for render_run_digest")
	}

	started := time.Now().UTC()
	parsed, err := parseDigestWindowAndBounds(&params, started)
	if err != nil {
		return nil, err
	}
	jobs, winSummary, err := loadDigestJobsAndSummary(ctx, deps.Store, &parsed)
	if err != nil {
		return nil, err
	}

	data := buildDigestData(jobs, winSummary, &parsed)
	metrics, notes, summary, overall := buildDigestCardDecorations(&data)
	rows := make([]ascii.TableRow, 0, len(data.Jobs))
	spark := make([]float64, 0, len(data.Jobs))
	health := make([]string, 0, len(data.Jobs))
	for i := range data.Jobs {
		e := &data.Jobs[i]
		health, spark = append(health, e.Status), append(spark, float64(e.DurationMS))
		rows = append(rows, ascii.TableRow{
			Status: e.Status,
			Cells:  []string{e.JobID, e.ToolName, e.Target, e.Summary, strconv.FormatInt(e.DurationMS, 10) + "ms"},
		})
	}
	return makeRecipeResult(&cardSpec{
		ToolName: "render_run_digest", Title: "DIAGNOSTIC RUN DIGEST", Subtitle: "Stored Job Summary",
		Target: firstNonEmpty(parsed.target, parsed.window, "recent"), Status: overall,
		Summary: summary, DurationMS: time.Since(started).Milliseconds(), Metrics: metrics,
		Headers: []string{"Job ID", "Tool", "Target", "Summary", "Dur"},
		Rows:    ascii.SortRowsBySeverity(rows), SparkValues: spark, HealthStates: health,
		Notes: notes, RawData: data,
	}), nil
}

func (d *Dependencies) pingCfg() *ping.Config {
	cfg := &ping.Config{Guard: d.Guard}
	if d.Ping != nil {
		*cfg = *d.Ping
		if cfg.Guard == nil {
			cfg.Guard = d.Guard
		}
	}
	return cfg
}

func (d *Dependencies) httpCfg() *http_ping.Config {
	cfg := &http_ping.Config{Guard: d.Guard}
	if d.HTTP != nil {
		*cfg = *d.HTTP
		if cfg.Guard == nil {
			cfg.Guard = d.Guard
		}
	}
	return cfg
}

func (d *Dependencies) tlsCfg() *tls.Config {
	cfg := &tls.Config{Guard: d.Guard}
	if d.TLS != nil {
		*cfg = *d.TLS
		if cfg.Guard == nil {
			cfg.Guard = d.Guard
		}
	}
	return cfg
}

func (d *Dependencies) resolverCfg() *resolver.Config {
	cfg := &resolver.Config{Guard: d.Guard}
	if d.Resolver != nil {
		*cfg = *d.Resolver
		if cfg.Guard == nil {
			cfg.Guard = d.Guard
		}
	}
	return cfg
}

func (d *Dependencies) dnsCfg() *dns.QueryConfig {
	cfg := &dns.QueryConfig{Guard: d.Guard}
	if d.DNS != nil {
		*cfg = *d.DNS
		if cfg.Guard == nil {
			cfg.Guard = d.Guard
		}
	}
	return cfg
}

func validateContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context error: %w", err)
	}
	return nil
}

func normalizeRecipeStatus(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case StatusFAIL, "ERROR", "ERR", "CRITICAL", "DOWN":
		return StatusFAIL
	case StatusWARN, "WARNING", "DEGRADED":
		return StatusWARN
	case StatusOK, "PASS", "UP", "HEALTHY":
		return StatusOK
	default:
		return StatusINFO
	}
}

func statusSeverityRank(status string) int {
	switch normalizeRecipeStatus(status) {
	case StatusFAIL:
		return 0
	case StatusWARN:
		return 1
	case StatusOK:
		return 2
	default:
		return 3
	}
}

func worstStatus(statuses ...string) string {
	worst := StatusOK
	for _, s := range statuses {
		switch normalizeRecipeStatus(s) {
		case StatusFAIL:
			return StatusFAIL
		case StatusWARN:
			worst = StatusWARN
		}
	}
	return worst
}

func makeRecipeResult(spec *cardSpec) *RecipeResult {
	if spec == nil {
		spec = &cardSpec{}
	}
	card := &ascii.ReportCard{
		Title: spec.Title, Subtitle: spec.Subtitle, ToolName: spec.ToolName, Target: spec.Target,
		Status: spec.Status, DurationMS: spec.DurationMS, Summary: spec.Summary, Metrics: spec.Metrics,
		Headers: spec.Headers, Rows: spec.Rows, SparkValues: spec.SparkValues,
		HealthStates: spec.HealthStates, Notes: spec.Notes, RawJSON: spec.RawData,
	}
	return &RecipeResult{
		Status: spec.Status, Summary: spec.Summary, Data: spec.RawData,
		Card: card, SparkValues: spec.SparkValues, HealthStates: spec.HealthStates,
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func goRun(g *errgroup.Group, fn func()) {
	g.Go(func() error { fn(); return nil })
}

func intPtr(v int) *int {
	if v <= 0 {
		return nil
	}
	return &v
}

func resolveRecipeTarget(ctx context.Context, rawTarget string, guard *security.TargetGuard) (net.IP, string, error) {
	clean, err := security.SanitizeTarget(rawTarget)
	if err != nil {
		return nil, "", fmt.Errorf("invalid target: %w", err)
	}
	if guard != nil {
		ips, valErr := guard.ValidateHostOrIP(ctx, clean)
		if valErr != nil {
			return nil, "", fmt.Errorf("target blocked by policy: %w", valErr)
		}
		if len(ips) == 0 {
			return nil, "", fmt.Errorf("no IP addresses resolved for %s", clean)
		}
		return ips[0], clean, nil
	}
	if parsed := net.ParseIP(clean); parsed != nil {
		return parsed, clean, nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, clean)
	if err != nil || len(ips) == 0 {
		return nil, "", fmt.Errorf("resolve target %s: %w", clean, err)
	}
	return ips[0].IP, clean, nil
}

func resolveGateway(paramGW string) (string, string) {
	if trimmed := strings.TrimSpace(paramGW); trimmed != "" {
		return trimmed, "param"
	}
	f, err := os.Open(procNetRoutePath)
	if err != nil {
		return "", ""
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	for first := true; scanner.Scan(); {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || fields[1] != "00000000" || fields[7] != "00000000" || fields[2] == "00000000" {
			continue
		}
		if val, parseErr := strconv.ParseUint(fields[2], 16, 32); parseErr == nil {
			return net.IPv4(byte(val&0xff), byte((val>>8)&0xff), byte((val>>16)&0xff), byte((val>>24)&0xff)).String(), "proc_net_route"
		}
	}
	return "", ""
}

func probeTCPReachability(ctx context.Context, ip net.IP, ports []int) []DiffPingTCPCheck {
	checks := make([]DiffPingTCPCheck, len(ports))
	dialer := &net.Dialer{Timeout: 1500 * time.Millisecond}
	var g errgroup.Group
	for idx, p := range ports {
		g.Go(func() error {
			start := time.Now()
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(p)))
			rtt := float64(time.Since(start)) / float64(time.Millisecond)
			state := "TIMEOUT"
			if err == nil {
				_ = conn.Close()
				state = "SYN-ACK"
			} else if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(strings.ToLower(err.Error()), "connection refused") {
				state = "RST"
			}
			checks[idx] = DiffPingTCPCheck{Port: p, State: state, RTTMs: rtt}
			return nil
		})
	}
	_ = g.Wait()
	return checks
}

func saveARPSnapshot(ctx context.Context, st *store.JobStore, name, cidr string, sweep *probe.ARPSweepResult) error {
	payload, err := json.Marshal(sweep)
	if err != nil {
		return fmt.Errorf("marshal ARP snapshot %q: %w", name, err)
	}
	if err := st.SaveSnapshot(ctx, &store.SnapshotRecord{Name: name, Target: cidr, PayloadJSON: string(payload)}); err != nil {
		return fmt.Errorf("save snapshot %q: %w", name, err)
	}
	return nil
}

func computeARPSnapshotDiff(baseline, current []probe.ARPNeighbor) ([]DiffSnapshotEntry, int, int, int) {
	baseMap, currMap := make(map[string]*probe.ARPNeighbor, len(baseline)), make(map[string]*probe.ARPNeighbor, len(current))
	for i := range baseline {
		baseMap[baseline[i].IP] = &baseline[i]
	}
	for i := range current {
		currMap[current[i].IP] = &current[i]
	}
	var diffs []DiffSnapshotEntry
	var added, removed, changed int
	for ip, curr := range currMap {
		if base, exists := baseMap[ip]; !exists {
			added++
			diffs = append(diffs, DiffSnapshotEntry{DiffType: diffTagAdded, IP: ip, MAC: curr.MAC, Vendor: curr.Vendor, Interface: curr.Interface, Detail: "new neighbor detected"})
		} else if !strings.EqualFold(base.MAC, curr.MAC) || base.Interface != curr.Interface {
			changed++
			diffs = append(diffs, DiffSnapshotEntry{DiffType: diffTagChanged, IP: ip, MAC: curr.MAC, PreviousMAC: base.MAC, Vendor: curr.Vendor, Interface: curr.Interface, Detail: fmt.Sprintf("MAC %s -> %s", base.MAC, curr.MAC)})
		}
	}
	for ip, base := range baseMap {
		if _, exists := currMap[ip]; !exists {
			removed++
			diffs = append(diffs, DiffSnapshotEntry{DiffType: diffTagRemoved, IP: ip, MAC: base.MAC, Vendor: base.Vendor, Interface: base.Interface, Detail: "neighbor disappeared"})
		}
	}
	slices.SortFunc(diffs, func(a, b DiffSnapshotEntry) int {
		if a.DiffType != b.DiffType {
			return strings.Compare(a.DiffType, b.DiffType)
		}
		return strings.Compare(a.IP, b.IP)
	})
	return diffs, added, removed, changed
}
