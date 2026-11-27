package recipes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/ascii"
	"github.com/FrankXLT/mcp-adv-netutils/internal/http_ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/probe"
	"github.com/FrankXLT/mcp-adv-netutils/internal/resolver"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
	"github.com/FrankXLT/mcp-adv-netutils/internal/tls"
	"golang.org/x/sync/errgroup"
)

// DiffPingParams configures a multi-hop comparative reachability diagnostic ladder.
type DiffPingParams struct {
	Target        string `json:"target"`
	Gateway       string `json:"gateway,omitempty"`
	WireGuardPeer string `json:"wireguard_peer,omitempty"`
	Canary        string `json:"canary,omitempty"`
	Count         int    `json:"count,omitempty"`
}

// DiffPingHop records probe results for a single stage of the DiffPing ladder.
type DiffPingHop struct {
	Stage      string  `json:"stage"`
	Address    string  `json:"address"`
	ProbeMode  string  `json:"probe_mode,omitempty"`
	LossPct    float64 `json:"loss_pct"`
	AvgRTTMs   float64 `json:"avg_rtt_ms"`
	Status     string  `json:"status"`
	Detail     string  `json:"detail,omitempty"`
	ARPMAC     string  `json:"arp_mac,omitempty"`
	ARPPresent bool    `json:"arp_present,omitempty"`
}

// DiffPingData contains hop-by-hop results, TCP L3 verification, ARP findings, and diagnosis.
type DiffPingData struct {
	Target        string             `json:"target"`
	ResolvedIP    string             `json:"resolved_ip"`
	Diagnosis     string             `json:"diagnosis"`
	Hops          []DiffPingHop      `json:"hops"`
	TCPChecks     []DiffPingTCPCheck `json:"tcp_checks"`
	ARPNeighbors  int                `json:"arp_neighbors"`
	GatewaySource string             `json:"gateway_source,omitempty"`
}

// DiffDNSParams configures split-horizon DNS comparison plus system resolver verification.
type DiffDNSParams struct {
	Domain      string   `json:"domain"`
	RecordTypes []string `json:"record_types,omitempty"`
}

// DiffDNSData combines SplitDNSAudit comparisons with system resolver results.
type DiffDNSData struct {
	Domain         string                     `json:"domain"`
	OverallStatus  string                     `json:"overall_status"`
	SplitDetected  bool                       `json:"split_detected"`
	Comparisons    []probe.SplitDNSComparison `json:"comparisons"`
	SystemResolver *resolver.ResolverResponse `json:"system_resolver,omitempty"`
	ResolverError  string                     `json:"resolver_error,omitempty"`
}

// DiffHTTPParams configures side-by-side HTTP timing and TLS certificate comparison across URLs.
type DiffHTTPParams struct {
	URL         string   `json:"url"`
	CompareURLs []string `json:"compare_urls,omitempty"`
	Method      string   `json:"method,omitempty"`
	Count       int      `json:"count,omitempty"`
}

// DiffHTTPEndpoint holds HTTP timing and TLS inspection metrics for one endpoint.
type DiffHTTPEndpoint struct {
	URL         string  `json:"url"`
	StatusCode  int     `json:"status_code"`
	DNSMs       float64 `json:"dns_ms"`
	TCPMs       float64 `json:"tcp_ms"`
	TLSMs       float64 `json:"tls_ms"`
	TTFBMs      float64 `json:"ttfb_ms"`
	TotalMs     float64 `json:"total_ms"`
	ChainValid  *bool   `json:"chain_valid,omitempty"`
	ExpiresDays *int    `json:"expires_in_days,omitempty"`
	Subject     string  `json:"subject,omitempty"`
	Issuer      string  `json:"issuer,omitempty"`
	TLSVersion  string  `json:"tls_version,omitempty"`
	CipherSuite string  `json:"cipher_suite,omitempty"`
	NotAfter    string  `json:"not_after,omitempty"`
	Status      string  `json:"status"`
	Detail      string  `json:"detail,omitempty"`
}

// DiffHTTPData holds side-by-side HTTP/TLS comparisons across all requested URLs.
type DiffHTTPData struct {
	Endpoints []DiffHTTPEndpoint `json:"endpoints"`
}

// DiffSnapshotParams configures baseline ARP snapshot comparison and optional persistence.
type DiffSnapshotParams struct {
	Baseline string `json:"baseline"`
	CIDR     string `json:"cidr,omitempty"`
	SaveAs   string `json:"save_as,omitempty"`
}

// DiffSnapshotData summarizes baseline vs current ARP sweep differences.
type DiffSnapshotData struct {
	Baseline   string              `json:"baseline"`
	SavedAs    string              `json:"saved_as,omitempty"`
	IsFirstRun bool                `json:"is_first_run"`
	Added      int                 `json:"added"`
	Removed    int                 `json:"removed"`
	Changed    int                 `json:"changed"`
	TotalCurr  int                 `json:"total_current"`
	TotalBase  int                 `json:"total_baseline"`
	Diffs      []DiffSnapshotEntry `json:"diffs"`
}

type pingHopSpec struct{ stage, address string }

const (
	defaultCanaryIP    = "1.1.1.1"
	defaultDiffPingCnt = 2
)

// ExecuteDiffPing probes loopback, gateway, optional WireGuard peer, canary, and target concurrently,
// alongside TCP 80/443 RST/SYN-ACK and ARP neighbor verification to localize path failures.
func ExecuteDiffPing(ctx context.Context, deps Dependencies, params DiffPingParams) (*RecipeResult, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	targetIP, cleanTarget, err := resolveRecipeTarget(ctx, params.Target, deps.Guard)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	gw, gwSrc := resolveGateway(params.Gateway)
	cnt := params.Count
	if cnt <= 0 {
		cnt = defaultDiffPingCnt
	}
	specs := buildDiffPingSpecs(gw, params.WireGuardPeer, firstNonEmpty(params.Canary, defaultCanaryIP), cleanTarget)
	hops := make([]DiffPingHop, len(specs))
	var tcpChecks []DiffPingTCPCheck
	var arpRes *probe.ARPSweepResult
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(6)
	for i, sp := range specs {
		g.Go(func() error { hops[i] = runHopPing(gctx, sp, cnt, deps.pingCfg()); return nil })
	}
	g.Go(func() error { tcpChecks = probeTCPReachability(gctx, targetIP, []int{80, 443}); return nil })
	g.Go(func() error {
		arpRes, _ = probe.ExecuteARPSweep(gctx, probe.ARPSweepParams{}, deps.Guard, deps.dnsCfg())
		return nil
	})
	_ = g.Wait()

	rows, spark, health, arpCount := buildDiffPingCardData(hops, tcpChecks, arpRes)
	diag, status := diagnoseDiffPing(hops, tcpChecks)
	var notes []string
	if gw == "" {
		notes = append(notes, "Default gateway not detected (pass gateway explicitly if needed)")
	}
	return makeRecipeResult(&cardSpec{
		ToolName: "diff_ping", Title: "DIFF PING LADDER", Subtitle: "Hop-by-Hop + TCP L3", Target: cleanTarget,
		Status: status, Summary: diag, DurationMS: time.Since(started).Milliseconds(),
		Metrics: []ascii.MetricKV{{Label: "Target IP", Value: targetIP.String()}, {Label: "ARP Cache", Value: strconv.Itoa(arpCount)}},
		Headers: []string{"Stage", "Address", "Mode", "Loss%", "RTT", "Detail"}, Rows: rows, SparkValues: spark, HealthStates: health, Notes: notes,
		RawData: DiffPingData{Target: cleanTarget, ResolvedIP: targetIP.String(), Diagnosis: diag, Hops: hops, TCPChecks: tcpChecks, ARPNeighbors: arpCount, GatewaySource: gwSrc},
	}), nil
}

// ExecuteDiffDNS compares local vs public DoH DNS records and verifies OS resolver output concurrently.
func ExecuteDiffDNS(ctx context.Context, deps Dependencies, params DiffDNSParams) (*RecipeResult, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	started := time.Now()
	var splitRes *probe.SplitDNSResult
	var splitErr, resErr error
	var resResp *resolver.ResolverResponse
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		splitRes, splitErr = probe.ExecuteSplitDNSAudit(gctx, probe.SplitDNSParams{Domain: params.Domain, RecordTypes: params.RecordTypes}, deps.dnsCfg())
		return nil
	})
	g.Go(func() error {
		resResp, resErr = resolver.Execute(gctx, resolver.ResolverParams{Hostname: params.Domain, IPVersion: "both"}, deps.resolverCfg())
		return nil
	})
	_ = g.Wait()
	if splitErr != nil {
		return nil, fmt.Errorf("split DNS audit failed: %w", splitErr)
	}
	rows, health, status := buildDiffDNSRows(splitRes)
	var notes []string
	var resErrMsg string
	if resErr != nil {
		resErrMsg = resErr.Error()
		notes = append(notes, "System resolver error: "+resErrMsg)
	} else if resResp != nil {
		notes = append(notes, fmt.Sprintf("System resolver: IPv4=%v IPv6=%v", resResp.IPv4Addresses, resResp.IPv6Addresses))
	}
	summary := fmt.Sprintf("%s: %s (%d record types checked)", splitRes.Domain, splitRes.OverallStatus, len(splitRes.Comparisons))
	return makeRecipeResult(&cardSpec{
		ToolName: "diff_dns", Title: "DIFF DNS AUDIT", Subtitle: "Local vs Public DoH", Target: splitRes.Domain,
		Status: status, Summary: summary, DurationMS: time.Since(started).Milliseconds(),
		Metrics: []ascii.MetricKV{{Label: "Audit Status", Value: splitRes.OverallStatus}, {Label: "Split DNS", Value: strconv.FormatBool(splitRes.SplitDetected)}},
		Headers: []string{"Type", "Classification", "Local", "Remote"}, Rows: rows, HealthStates: health, Notes: notes,
		RawData: DiffDNSData{Domain: splitRes.Domain, OverallStatus: splitRes.OverallStatus, SplitDetected: splitRes.SplitDetected, Comparisons: splitRes.Comparisons, SystemResolver: resResp, ResolverError: resErrMsg},
	}), nil
}

// ExecuteDiffHTTP compares HTTP/TLS latency phases and certificate validity across multiple URLs concurrently.
func ExecuteDiffHTTP(ctx context.Context, deps Dependencies, params DiffHTTPParams) (*RecipeResult, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	urls := make([]string, 0, 1+len(params.CompareURLs))
	seen := make(map[string]struct{}, 1+len(params.CompareURLs))
	for _, raw := range append([]string{params.URL}, params.CompareURLs...) {
		if u := strings.TrimSpace(raw); u != "" {
			if _, ok := seen[u]; !ok {
				seen[u], urls = struct{}{}, append(urls, u)
			}
		}
	}
	if len(urls) == 0 {
		return nil, errors.New("parameter \"url\" is required")
	}
	started := time.Now()
	endpoints := make([]DiffHTTPEndpoint, len(urls))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(6)
	for idx, rawURL := range urls {
		g.Go(func() error {
			endpoints[idx] = probeDiffHTTPEndpoint(gctx, rawURL, params.Method, params.Count, deps)
			return nil
		})
	}
	_ = g.Wait()

	rows, spark, health, statuses := make([]ascii.TableRow, 0, len(endpoints)), make([]float64, 0, len(endpoints)), make([]string, 0, len(endpoints)), make([]string, 0, len(endpoints))
	for i := range endpoints {
		ep := &endpoints[i]
		certText := "n/a"
		if ep.ChainValid != nil {
			days := 0
			if ep.ExpiresDays != nil {
				days = *ep.ExpiresDays
			}
			certText = fmt.Sprintf("valid=%v(%dd)", *ep.ChainValid, days)
		}
		rows = append(rows, ascii.TableRow{Status: ep.Status, Cells: []string{ep.URL, strconv.Itoa(ep.StatusCode), fmt.Sprintf("%.1f", ep.DNSMs), fmt.Sprintf("%.1f", ep.TCPMs), fmt.Sprintf("%.1f", ep.TLSMs), fmt.Sprintf("%.1f", ep.TTFBMs), fmt.Sprintf("%.1f", ep.TotalMs), certText}})
		spark, health, statuses = append(spark, ep.TotalMs), append(health, ep.Status), append(statuses, ep.Status)
	}
	overall := worstStatus(statuses...)
	summary := formatDiffHTTPSummary(endpoints, overall)
	return makeRecipeResult(&cardSpec{
		ToolName: "diff_http", Title: "DIFF HTTP / TLS", Subtitle: "Phase Timing & Certs", Target: urls[0],
		Status: overall, Summary: summary, DurationMS: time.Since(started).Milliseconds(),
		Metrics: []ascii.MetricKV{{Label: "Endpoints", Value: strconv.Itoa(len(endpoints))}, {Label: "Status", Value: overall}},
		Headers: []string{"URL", "Code", "DNS", "TCP", "TLS", "TTFB", "Total", "Cert"}, Rows: rows,
		SparkValues: spark, HealthStates: health, RawData: DiffHTTPData{Endpoints: endpoints},
	}), nil
}

func formatDiffHTTPSummary(endpoints []DiffHTTPEndpoint, overall string) string {
	proto := "HTTP"
	for i := range endpoints {
		if strings.HasPrefix(strings.ToLower(endpoints[i].URL), "https://") || endpoints[i].ChainValid != nil {
			proto = "HTTPS"
			break
		}
	}
	phrase := "failed"
	switch overall {
	case StatusOK:
		phrase = "healthy"
	case StatusWARN:
		phrase = "needs attention"
	}
	if len(endpoints) == 1 {
		return fmt.Sprintf("Checked 1 %s endpoint — %s", proto, phrase)
	}
	return fmt.Sprintf("Compared %d %s endpoints — %s", len(endpoints), proto, phrase)
}

// ExecuteDiffSnapshot compares the current ARP sweep against a stored baseline snapshot,
// emitting only [+] ADDED, [-] REMOVED, and [~] CHANGED neighbor rows in Card.
func ExecuteDiffSnapshot(ctx context.Context, deps Dependencies, params DiffSnapshotParams) (*RecipeResult, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if deps.Store == nil {
		return nil, errors.New("job store is required for diff_snapshot")
	}
	baselineName := firstNonEmpty(params.Baseline, params.SaveAs)
	if baselineName == "" {
		return nil, errors.New("parameter \"baseline\" or \"save_as\" is required")
	}
	started := time.Now()
	currSweep, err := probe.ExecuteARPSweep(ctx, probe.ARPSweepParams{CIDR: params.CIDR}, deps.Guard, deps.dnsCfg())
	if err != nil {
		return nil, fmt.Errorf("ARP sweep failed: %w", err)
	}
	baseSnap, getErr := deps.Store.GetSnapshot(ctx, baselineName)
	if getErr != nil {
		if !errors.Is(getErr, store.ErrNotFound) {
			return nil, fmt.Errorf("load baseline snapshot %q: %w", baselineName, getErr)
		}
		saveName := firstNonEmpty(params.SaveAs, baselineName)
		if err := saveARPSnapshot(ctx, deps.Store, saveName, params.CIDR, currSweep); err != nil {
			return nil, err
		}
		summary := fmt.Sprintf("Saved initial baseline %q (%d neighbors)", saveName, len(currSweep.Neighbors))
		return makeRecipeResult(&cardSpec{
			ToolName: "diff_snapshot", Title: "DIFF SNAPSHOT", Subtitle: "Baseline Initialized", Target: baselineName,
			Status: StatusOK, Summary: summary, DurationMS: time.Since(started).Milliseconds(),
			Metrics: []ascii.MetricKV{{Label: "Baseline", Value: saveName}, {Label: "Neighbors", Value: strconv.Itoa(len(currSweep.Neighbors))}},
			RawData: DiffSnapshotData{Baseline: baselineName, SavedAs: saveName, IsFirstRun: true, TotalCurr: len(currSweep.Neighbors)},
		}), nil
	}
	var baseSweep probe.ARPSweepResult
	if err := json.Unmarshal([]byte(baseSnap.PayloadJSON), &baseSweep); err != nil {
		return nil, fmt.Errorf("decode baseline snapshot %q: %w", baselineName, err)
	}
	if saveName := strings.TrimSpace(params.SaveAs); saveName != "" {
		if err := saveARPSnapshot(ctx, deps.Store, saveName, params.CIDR, currSweep); err != nil {
			return nil, err
		}
	}
	diffs, added, removed, changed := computeARPSnapshotDiff(baseSweep.Neighbors, currSweep.Neighbors)
	rows, health := make([]ascii.TableRow, 0, len(diffs)), make([]string, 0, len(diffs))
	for i := range diffs {
		d := &diffs[i]
		rows = append(rows, ascii.TableRow{Status: StatusWARN, Cells: []string{d.DiffType, d.IP, d.MAC, d.Vendor, d.Detail}})
		health = append(health, StatusWARN)
	}
	status, summary := StatusOK, fmt.Sprintf("No neighbor changes since baseline %q (%d neighbors)", baselineName, len(currSweep.Neighbors))
	if len(diffs) > 0 {
		status = StatusWARN
		summary = fmt.Sprintf("Baseline %q diff: +%d added, -%d removed, ~%d changed", baselineName, added, removed, changed)
	}
	return makeRecipeResult(&cardSpec{
		ToolName: "diff_snapshot", Title: "DIFF SNAPSHOT", Subtitle: "ARP Neighbor Delta", Target: baselineName,
		Status: status, Summary: summary, DurationMS: time.Since(started).Milliseconds(),
		Metrics: []ascii.MetricKV{{Label: "Baseline", Value: baselineName}, {Label: "+/-/~", Value: fmt.Sprintf("+%d / -%d / ~%d", added, removed, changed)}},
		Headers: []string{"Diff", "IP", "MAC", "Vendor", "Detail"}, Rows: rows, HealthStates: health,
		RawData: DiffSnapshotData{Baseline: baselineName, SavedAs: strings.TrimSpace(params.SaveAs), Added: added, Removed: removed, Changed: changed, TotalCurr: len(currSweep.Neighbors), TotalBase: len(baseSweep.Neighbors), Diffs: diffs},
	}), nil
}

func buildDiffPingSpecs(gw, wgPeer, canary, target string) []pingHopSpec {
	specs := []pingHopSpec{{stage: "[1] Local Adapter", address: "127.0.0.1"}}
	for _, item := range []pingHopSpec{{stage: "[2] Gateway", address: gw}, {stage: "[3] WG/WAN Peer", address: wgPeer}} {
		if addr := strings.TrimSpace(item.address); addr != "" {
			specs = append(specs, pingHopSpec{stage: item.stage, address: addr})
		}
	}
	if canary != "" && canary != target {
		specs = append(specs, pingHopSpec{stage: "[4] Public DNS", address: canary})
	}
	return append(specs, pingHopSpec{stage: "[5] Target", address: target})
}

func runHopPing(ctx context.Context, sp pingHopSpec, cnt int, cfg *ping.Config) DiffPingHop {
	res, err := ping.Execute(ctx, ping.PingParams{Target: sp.address, Count: &cnt}, cfg)
	if err != nil {
		return DiffPingHop{Stage: sp.stage, Address: sp.address, LossPct: 100, Status: StatusFAIL, Detail: err.Error()}
	}
	st := StatusOK
	if res.PacketsReceived == 0 {
		st = StatusFAIL
	} else if res.PacketLoss > 0 {
		st = StatusWARN
	}
	return DiffPingHop{Stage: sp.stage, Address: sp.address, ProbeMode: res.ProbeMode, LossPct: res.PacketLoss, AvgRTTMs: res.AvgRTT, Status: st, Detail: fmt.Sprintf("%d/%d ok", res.PacketsReceived, res.PacketsSent)}
}

func diagnoseDiffPing(hops []DiffPingHop, tcpChecks []DiffPingTCPCheck) (string, string) {
	targetHop := hops[len(hops)-1]
	if targetHop.Status == StatusFAIL && slices.ContainsFunc(tcpChecks, func(c DiffPingTCPCheck) bool { return c.State == "SYN-ACK" || c.State == "RST" }) {
		return "ICMP filtered — TCP RST/SYN-ACK proves bidirectional L3 routing", StatusWARN
	}
	for i := range hops[:len(hops)-1] {
		if hops[i].Status != StatusFAIL {
			continue
		}
		switch hops[i].Stage[:3] {
		case "[1]":
			return "Local adapter/loopback stack failure", StatusFAIL
		case "[2]":
			return "L2/Gateway unreachable (check local ARP and link)", StatusFAIL
		case "[3]":
			return "WireGuard/WAN peer unreachable", StatusFAIL
		case "[4]":
			if targetHop.Status == StatusFAIL {
				return "Upstream reference host and target both unreachable", StatusFAIL
			}
		}
	}
	if targetHop.Status == StatusFAIL {
		return "Target unreachable across ICMP and TCP 80/443 probes", StatusFAIL
	}
	if slices.ContainsFunc(hops, func(h DiffPingHop) bool { return h.Status == StatusWARN }) {
		return "Path degraded: partial packet loss detected", StatusWARN
	}
	return "All probed path hops healthy", StatusOK
}

func buildDiffPingCardData(hops []DiffPingHop, tcpChecks []DiffPingTCPCheck, arpRes *probe.ARPSweepResult) ([]ascii.TableRow, []float64, []string, int) {
	byIP, arpCount := make(map[string]probe.ARPNeighbor), 0
	if arpRes != nil {
		arpCount = arpRes.TotalCount
		for i := range arpRes.Neighbors {
			byIP[arpRes.Neighbors[i].IP] = arpRes.Neighbors[i]
		}
	}
	rows, spark, health := make([]ascii.TableRow, 0, len(hops)+len(tcpChecks)), make([]float64, 0, len(hops)), make([]string, 0, len(hops)+len(tcpChecks))
	for i := range hops {
		h, detail := &hops[i], hops[i].Detail
		if n, ok := byIP[h.Address]; ok {
			h.ARPPresent, h.ARPMAC, detail = true, n.MAC, detail+" arp="+n.MAC
		}
		rows = append(rows, ascii.TableRow{Status: h.Status, Cells: []string{h.Stage, h.Address, h.ProbeMode, fmt.Sprintf("%.0f%%", h.LossPct), fmt.Sprintf("%.2fms", h.AvgRTTMs), detail}})
		spark, health = append(spark, h.AvgRTTMs), append(health, h.Status)
	}
	for _, c := range tcpChecks {
		st := StatusOK
		if c.State == "TIMEOUT" {
			st = StatusWARN
		}
		rows = append(rows, ascii.TableRow{Status: st, Cells: []string{"TCP Check", ":" + strconv.Itoa(c.Port), "tcp", "-", fmt.Sprintf("%.2fms", c.RTTMs), c.State}})
		health = append(health, st)
	}
	return rows, spark, health, arpCount
}

func buildDiffDNSRows(res *probe.SplitDNSResult) ([]ascii.TableRow, []string, string) {
	rows, health, errCount := make([]ascii.TableRow, 0, len(res.Comparisons)), make([]string, 0, len(res.Comparisons)), 0
	for i := range res.Comparisons {
		c, rowStatus := &res.Comparisons[i], StatusINFO
		switch c.Status {
		case "MATCH":
			rowStatus = StatusOK
		case "SPLIT-LOCAL", "LOCAL-ONLY", "PUBLIC-ONLY":
			rowStatus = StatusWARN
		case "ERROR":
			rowStatus, errCount = StatusFAIL, errCount+1
		}
		rows = append(rows, ascii.TableRow{Status: rowStatus, Cells: []string{c.RecordType, c.Status, firstNonEmpty(strings.Join(c.LocalAnswers, ", "), c.LocalErr, "-"), firstNonEmpty(strings.Join(c.RemoteAnswers, ", "), c.RemoteErr, "-")}})
		health = append(health, rowStatus)
	}
	overall := StatusOK
	if errCount == len(res.Comparisons) && errCount > 0 {
		overall = StatusFAIL
	} else if res.SplitDetected || errCount > 0 {
		overall = StatusWARN
	}
	return rows, health, overall
}

func probeDiffHTTPEndpoint(ctx context.Context, rawURL, method string, count int, deps Dependencies) DiffHTTPEndpoint {
	ep := DiffHTTPEndpoint{URL: rawURL, Status: StatusOK}
	var cntPtr *int
	if count > 0 {
		c := count
		cntPtr = &c
	}
	httpRes, httpErr := http_ping.Execute(ctx, http_ping.HTTPPingParams{URL: rawURL, Method: method, Count: cntPtr}, deps.httpCfg())
	if httpErr != nil {
		ep.Status, ep.Detail = StatusFAIL, httpErr.Error()
		return ep
	}
	ep.DNSMs, ep.TCPMs, ep.TLSMs, ep.TTFBMs, ep.TotalMs = httpRes.AvgDNSTime, httpRes.AvgConnTime, httpRes.AvgTLSTime, httpRes.AvgTTFBTime, httpRes.AvgTotalTime
	if len(httpRes.Results) > 0 {
		ep.StatusCode, ep.Detail = httpRes.Results[0].StatusCode, httpRes.Results[0].Error
	}
	if httpRes.SuccessCount == 0 {
		ep.Status = StatusFAIL
	}
	parsed, err := url.Parse(rawURL)
	if err == nil && parsed.Scheme == "" && !strings.Contains(rawURL, "://") {
		parsed, err = url.Parse("https://" + rawURL)
	}
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" {
		return ep
	}
	port := 443
	if pNum, pErr := strconv.Atoi(parsed.Port()); pErr == nil && pNum > 0 {
		port = pNum
	}
	tlsRes, tlsErr := tls.Execute(ctx, tls.TLSCheckParams{Domain: parsed.Hostname(), Port: port}, deps.tlsCfg())
	if tlsErr != nil {
		ep.Status, ep.Detail = worstStatus(ep.Status, StatusWARN), tlsErr.Error()
		return ep
	}
	valid := tlsRes.ChainValid
	ep.ChainValid = &valid
	ep.TLSVersion = tlsRes.TLSVersion
	ep.CipherSuite = tlsRes.CipherSuite
	if len(tlsRes.PeerCertificates) > 0 {
		cert := tlsRes.PeerCertificates[0]
		days := cert.ExpiresInDays
		ep.ExpiresDays = &days
		ep.Subject = cert.Subject
		ep.Issuer = cert.Issuer
		if !cert.NotAfter.IsZero() {
			ep.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
		}
		if cert.IsExpired {
			ep.Status = StatusFAIL
		} else if !valid || days <= 30 {
			ep.Status = worstStatus(ep.Status, StatusWARN)
		}
	} else if !valid {
		ep.Status = worstStatus(ep.Status, StatusWARN)
	}
	return ep
}
