package dispatch

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/ascii"
	"github.com/FrankXLT/mcp-adv-netutils/internal/cronmon"
	"github.com/FrankXLT/mcp-adv-netutils/internal/probe"
	"github.com/FrankXLT/mcp-adv-netutils/internal/recipes"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
)

func (d *Dispatcher) runProbeTool(ctx context.Context, tool string, r *argReader, started time.Time) (*toolExec, error) {
	switch tool {
	case "arp_neighbor_sweep":
		p := probe.ARPSweepParams{CIDR: r.str("cidr", "target"), Interface: r.str("interface"), ActiveProbe: r.b("active_probe"), ResolvePTR: r.b("resolve_ptr"), TimeoutMS: r.i("timeout_ms")}
		if r.err != nil {
			return nil, r.err
		}
		res, err := probe.ExecuteARPSweep(ctx, p, d.guard, d.dnsCfg)
		return wrapExec(tool, err, func() *toolExec { return buildARPSweepExec(res, msSince(started)) })
	case "mtu_path_probe":
		p := probe.MTUProbeParams{Target: r.str("target"), MinMTU: r.i("min_mtu"), MaxMTU: r.i("max_mtu"), Protocol: r.str("protocol")}
		if r.err != nil {
			return nil, r.err
		}
		res, err := probe.ExecuteMTUProbe(ctx, p, d.guard)
		return wrapExec(tool, err, func() *toolExec { return buildMTUProbeExec(res, msSince(started)) })
	case "mtr_path_quality":
		p := probe.MTRParams{Target: r.str("target"), MaxHops: r.i("max_hops"), Cycles: r.i("cycles"), TimeoutMS: r.i("timeout_ms")}
		if r.err != nil {
			return nil, r.err
		}
		res, err := probe.ExecuteMTRQuality(ctx, p, d.guard)
		return wrapExec(tool, err, func() *toolExec { return buildMTRExec(res, msSince(started)) })
	case "mdns_ssdp_discover":
		p := probe.DiscoverParams{Protocol: r.str("protocol"), Service: r.str("service"), TimeoutMS: r.i("timeout_ms"), MaxResults: r.i("max_results")}
		if r.err != nil {
			return nil, r.err
		}
		res, err := probe.ExecuteMDNSSSDPDiscover(ctx, p, d.guard)
		return wrapExec(tool, err, func() *toolExec { return buildDiscoverExec(res, msSince(started)) })
	case "split_dns_audit":
		p := probe.SplitDNSParams{Domain: r.str("domain", "target"), RecordTypes: r.strs("record_types")}
		if r.err != nil {
			return nil, r.err
		}
		res, err := probe.ExecuteSplitDNSAudit(ctx, p, d.dnsCfg)
		return wrapExec(tool, err, func() *toolExec { return buildSplitDNSExec(res, msSince(started)) })
	default:
		p, err := r.snmpParams()
		if err != nil {
			return nil, err
		}
		res, err := probe.ExecuteSNMPSwitchPort(ctx, p, d.guard)
		return wrapExec(tool, err, func() *toolExec { return buildSNMPExec(res, msSince(started)) })
	}
}

func (d *Dispatcher) runRecipeTool(ctx context.Context, tool string, r *argReader, started time.Time) (*toolExec, error) {
	deps := recipes.Dependencies{Guard: d.guard, DNS: d.dnsCfg, Ping: d.pingCfg, HTTP: d.httpCfg, TLS: d.tlsCfg, Resolver: d.resCfg, Store: d.jobStore}
	var res *recipes.RecipeResult
	var target string
	var err error
	switch tool {
	case "recipe_diff_ping":
		target = r.str("target")
		p := recipes.DiffPingParams{Target: target, Gateway: r.str("gateway"), WireGuardPeer: r.str("wireguard_peer"), Canary: r.str("canary"), Count: r.i("count")}
		if r.err == nil {
			res, err = recipes.ExecuteDiffPing(ctx, deps, p)
		}
	case "recipe_diff_dns":
		target = r.str("domain", "target")
		p := recipes.DiffDNSParams{Domain: target, RecordTypes: r.strs("record_types")}
		if r.err == nil {
			res, err = recipes.ExecuteDiffDNS(ctx, deps, p)
		}
	case "recipe_diff_http":
		target = r.str("url", "target")
		p := recipes.DiffHTTPParams{URL: target, CompareURLs: r.strs("compare_urls"), Method: r.str("method"), Count: r.i("count")}
		if r.err == nil {
			res, err = recipes.ExecuteDiffHTTP(ctx, deps, p)
		}
	case "recipe_diff_snapshot":
		target = r.str("baseline", "target")
		res, err = recipes.ExecuteDiffSnapshot(ctx, deps, recipes.DiffSnapshotParams{Baseline: target, CIDR: r.str("cidr"), SaveAs: r.str("save_as")})
	case "recipe_host_card":
		target = r.str("target")
		chkSNMP := r.b("check_snmp")
		var snmpPtr *probe.SNMPParams
		if m := r.obj("snmp_params"); len(m) > 0 {
			if sp, spErr := (&argReader{m: m}).snmpParams(); spErr != nil {
				r.err = spErr
			} else {
				snmpPtr = &sp
			}
		}
		if r.err == nil {
			res, err = recipes.ExecuteHostCard(ctx, deps, recipes.HostCardParams{Target: target, PortPreset: r.str("port_preset", "ports"), CheckSNMP: chkSNMP, SNMPParams: snmpPtr})
		}
	case "recipe_lan_radar":
		target = r.str("cidr", "target")
		p := recipes.LANRadarParams{CIDR: target, ActiveARP: r.b("active_arp"), ResolvePTR: r.b("resolve_ptr"), DiscoverServices: r.b("discover_services")}
		if r.err == nil {
			res, err = recipes.ExecuteLANRadar(ctx, deps, p)
		}
	case "recipe_path_autopsy":
		target = r.str("target")
		p := recipes.PathAutopsyParams{Target: target, MaxHops: r.i("max_hops"), Cycles: r.i("cycles")}
		if r.err == nil {
			res, err = recipes.ExecutePathAutopsy(ctx, deps, p)
		}
	case "recipe_wake_verify":
		macVal, hostVal := r.str("mac"), r.str("target")
		if macVal == "" {
			if parts := strings.Fields(hostVal); len(parts) == 2 {
				macVal, hostVal = parts[0], parts[1]
			} else {
				macVal = hostVal
			}
		}
		target = firstNonEmpty(hostVal, macVal)
		p := recipes.WakeVerifyParams{MAC: macVal, Target: hostVal, BroadcastIP: r.str("broadcast_ip"), Port: r.i("port"), WaitSeconds: r.i("wait_seconds"), Ports: r.str("ports")}
		if r.err == nil {
			res, err = recipes.ExecuteWakeVerify(ctx, deps, p)
		}
	default:
		target = r.str("target")
		p := recipes.RenderDigestParams{JobIDs: r.strs("job_ids"), Limit: r.i("limit")}
		if r.err == nil {
			res, err = recipes.ExecuteRenderRunDigest(ctx, deps, p)
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	return wrapExec(tool, err, func() *toolExec { return buildRecipeExec(tool, res, target, msSince(started), time.Now().UTC()) })
}

func (d *Dispatcher) runAdminTool(ctx context.Context, tool string, r *argReader, started time.Time) (*toolExec, error) {
	switch tool {
	case "get_cron_status":
		period := r.str("period", "target")
		if sched := d.Scheduler(); sched != nil {
			summary, card, err := sched.BuildCronStatusCard(ctx, period)
			return wrapExec(tool, err, func() *toolExec { return buildCronStatusExec(summary, card, msSince(started)) })
		}
		summary, err := d.loadCronSummary(ctx, period)
		return wrapExec(tool, err, func() *toolExec { return buildCronStatusExec(summary, nil, msSince(started)) })
	case "manage_cron_watchlist":
		sched := d.Scheduler()
		if sched == nil {
			return nil, errors.New("cron scheduler is not configured")
		}
		action := strings.ToLower(r.str("action"))
		if action == "" {
			return nil, fmt.Errorf("%w: parameter \"action\" is required", ErrInvalidArgs)
		}
		p := cronmon.ManageParams{
			Action: action, Key: r.str("key", "id"), Schedule: r.str("schedule"),
			Tool: r.str("tool", "watch_tool"), Target: r.str("target"),
			Args: r.obj("args", "item_args"), Enabled: r.optB("enabled"), TimeoutSeconds: r.i("timeout_seconds"),
		}
		if r.err != nil {
			return nil, r.err
		}
		res, err := sched.ManageWatchlist(ctx, p)
		return wrapExec(tool, err, func() *toolExec { return buildManageWatchlistExec(res, msSince(started)) })
	case "manage_saved_destinations":
		p := DestinationParams{
			Action: strings.ToLower(r.str("action")), ID: r.str("id"), Name: r.str("name"),
			Target: r.str("target"), Category: r.str("category"), MAC: r.str("mac"),
			DefaultCheck: r.str("default_check"), Pinned: r.optB("pinned"),
			MonitorEnabled: r.optB("monitor_enabled"), MonitorSchedule: r.str("monitor_schedule"),
			Style: r.str("style"),
		}
		if rawMAC, present := r.m["mac"]; present {
			if macStr, ok := rawMAC.(string); ok && strings.TrimSpace(macStr) == "" {
				p.ClearMAC = true
			}
		}
		if clearMAC := r.optB("clear_mac"); clearMAC != nil && *clearMAC {
			p.ClearMAC = true
		}
		if r.err != nil {
			return nil, r.err
		}
		res, err := d.manageSavedDestinations(ctx, &p, true)
		return wrapExec(tool, err, func() *toolExec { return buildManageDestinationsExec(res, msSince(started)) })
	case "unlock_netutils":
		pass := r.str("passphrase", "password", "passcode")
		if d.deadbolt != nil && d.deadbolt.IsEnabled() {
			if _, ok := r.m["passphrase"]; !ok && pass == "" {
				return nil, fmt.Errorf("%w: parameter \"passphrase\" is required", ErrInvalidArgs)
			}
		}
		ok, expiresAt, reason := d.deadbolt.Unlock(pass)
		st := d.deadbolt.Status()
		status, summary := "OK", reason
		if !ok {
			status = "FAIL"
		} else if !expiresAt.IsZero() {
			summary = fmt.Sprintf("%s (expires %s)", reason, expiresAt.UTC().Format(time.RFC3339))
		}
		return buildDeadboltExec(tool, status, summary, &st, msSince(started)), nil
	default:
		d.deadbolt.Lock()
		st := d.deadbolt.Status()
		summary := "deadbolt locked"
		if !st.Enabled {
			summary = "deadbolt disabled"
		}
		return buildDeadboltExec(tool, "OK", summary, &st, msSince(started)), nil
	}
}

func buildARPSweepExec(res *probe.ARPSweepResult, durMS int64) *toolExec {
	rows := make([]ascii.TableRow, 0, len(res.Neighbors))
	phys, virt := make([]LANHostView, 0, res.PhysicalCount), make([]LANHostView, 0, res.VirtualCount)
	for i := range res.Neighbors {
		n := &res.Neighbors[i]
		if n.IsLAA {
			virt = append(virt, LANHostView{IP: n.IP, Hostname: n.Hostname, MAC: n.MAC, Vendor: n.Vendor, Runtime: "LAA / Virtual", Segment: "laa"})
		} else {
			phys = append(phys, LANHostView{IP: n.IP, Hostname: n.Hostname, MAC: n.MAC, Vendor: n.Vendor, Segment: "uaa"})
		}
	}
	for i := range phys {
		rows = append(rows, ascii.TableRow{Status: statusOK, Cells: []string{"[PHYSICAL - UAA]", phys[i].IP, phys[i].MAC, firstNonEmpty(phys[i].Hostname, phys[i].Vendor)}})
	}
	for i := range virt {
		rows = append(rows, ascii.TableRow{Status: statusINFO, Cells: []string{"[DOCKER/VM - LAA]", virt[i].IP, virt[i].MAC, firstNonEmpty(virt[i].Hostname, virt[i].Vendor)}})
	}
	target := firstNonEmpty(res.CIDR, "local-arp")
	return makeExecCard(&cardSpec{
		tool: "arp_neighbor_sweep", title: "ARP NEIGHBOR SWEEP", subtitle: res.ProbeMode, target: target, status: statusOK, durMS: durMS, raw: res,
		summary: formatARPSweepSummary(res),
		metrics: []ascii.MetricKV{{Label: "Physical UAA", Value: strconv.Itoa(res.PhysicalCount)}, {Label: "Virtual LAA", Value: strconv.Itoa(res.VirtualCount)}},
		headers: []string{"Group", "IP", "MAC", "Vendor"}, rows: rows,
		lan: &LANInventoryView{CapturedAt: res.Timestamp, Physical: phys, Virtual: virt},
	})
}

func buildMTUProbeExec(res *probe.MTUProbeResult, durMS int64) *toolExec {
	status := statusOK
	if res.BlackholeDetected || res.DiscoveredMTU == 0 {
		status = statusFAIL
	}
	rows, spark, wf := make([]ascii.TableRow, 0, len(res.Steps)), make([]float64, 0, len(res.Steps)), make([]WaterfallPhase, 0, len(res.Steps))
	cursor := 0.0
	for i := range res.Steps {
		s, st, outcome := &res.Steps[i], statusOK, "ok"
		if !s.Success {
			st, outcome = statusWARN, firstNonEmpty(s.Error, "fail")
		}
		rows = append(rows, ascii.TableRow{Status: st, Cells: []string{strconv.Itoa(s.WireMTU), strconv.Itoa(s.PayloadSize), fmt.Sprintf("%.2fms", s.RTTMs), outcome}})
		spark, wf = append(spark, s.RTTMs), append(wf, WaterfallPhase{Label: strconv.Itoa(s.WireMTU) + "B Probe", StartMs: cursor, DurationMs: s.RTTMs})
		cursor += s.RTTMs
	}
	return makeExecCard(&cardSpec{
		tool: "mtu_path_probe", title: "MTU PATH PROBE", subtitle: res.ProbeMode, target: res.Target, status: status, durMS: durMS, raw: res,
		summary: formatMTUSummary(res),
		metrics: []ascii.MetricKV{{Label: "MTU", Value: strconv.Itoa(res.DiscoveredMTU)}, {Label: "WG Safe", Value: strconv.Itoa(res.WireGuardSafeMTU)}, {Label: "Blackhole", Value: strconv.FormatBool(res.BlackholeDetected)}},
		headers: []string{"WireMTU", "Payload", "RTT", "Outcome"}, rows: rows, spark: spark, waterfall: wf,
	})
}

func buildMTRExec(res *probe.MTRResult, durMS int64) *toolExec {
	rows, spark, health := make([]ascii.TableRow, 0, len(res.Hops)), make([]float64, 0, len(res.Hops)), make([]string, 0, len(res.Hops))
	whiskers, status := make([]WhiskerPoint, 0, len(res.Hops)), statusOK
	if !res.Reached && len(res.Hops) == 0 {
		status = statusFAIL
	}
	hasIssue := false
	for i := range res.Hops {
		h, st := &res.Hops[i], statusOK
		if h.LossPct >= 50 {
			st = statusFAIL
			hasIssue = true
		} else if h.LossPct > 0 || h.StDevMs >= 20 {
			st = statusWARN
			hasIssue = true
		}
		status = worstStatusVal(status, st)
		rows = append(rows, ascii.TableRow{Status: st, Cells: []string{strconv.Itoa(h.Hop), h.IP, fmt.Sprintf("%.0f%%", h.LossPct), fmt.Sprintf("%.2f", h.AvgMs), fmt.Sprintf("%.2f", h.StDevMs)}})
		spark, health = append(spark, h.AvgMs), append(health, st)
		whiskers = append(whiskers, WhiskerPoint{Label: fmt.Sprintf("Hop %d (%s)", h.Hop, h.IP), MinMs: h.BestMs, AvgMs: h.AvgMs, MaxMs: h.WorstMs, LossPct: h.LossPct})
	}
	if !res.Reached && status == statusOK {
		status = statusWARN
	}
	return makeExecCard(&cardSpec{
		tool: "mtr_path_quality", title: "MTR PATH QUALITY", subtitle: res.ProbeMode, target: res.Target, status: status, durMS: durMS, raw: res,
		summary: formatMTRSummary(res, hasIssue),
		metrics: []ascii.MetricKV{{Label: "Cycles", Value: strconv.Itoa(res.Cycles)}, {Label: "Hops", Value: strconv.Itoa(len(res.Hops))}, {Label: "Reached", Value: strconv.FormatBool(res.Reached)}},
		headers: []string{"Hop", "IP", "Loss%", "Avg", "StDev"}, rows: rows, spark: spark, health: health, whiskers: whiskers,
	})
}

func buildDiscoverExec(res *probe.DiscoverResult, durMS int64) *toolExec {
	status := statusOK
	if res.Count == 0 && len(res.Warnings) > 0 {
		status = statusWARN
	}
	rows := make([]ascii.TableRow, 0, len(res.Services))
	for i := range res.Services {
		s := &res.Services[i]
		rows = append(rows, ascii.TableRow{Status: statusINFO, Cells: []string{strings.ToUpper(s.Protocol), s.IP, strconv.Itoa(s.Port), firstNonEmpty(s.Name, s.ServiceType, s.Server)}})
	}
	return makeExecCard(&cardSpec{
		tool: "mdns_ssdp_discover", title: "mDNS / SSDP DISCOVER", subtitle: res.Protocol, target: res.Protocol, status: status, durMS: durMS, raw: res,
		summary: formatDiscoverSummary(res),
		metrics: []ascii.MetricKV{{Label: "Protocol", Value: res.Protocol}, {Label: "Services", Value: strconv.Itoa(res.Count)}},
		headers: []string{"Proto", "IP", "Port", "Service"}, rows: rows, notes: res.Warnings,
	})
}

func buildSplitDNSExec(res *probe.SplitDNSResult, durMS int64) *toolExec {
	status := statusOK
	if res.OverallStatus == "ERROR" {
		status = statusFAIL
	} else if res.SplitDetected || res.OverallStatus == "PARTIAL-ERROR" {
		status = statusWARN
	}
	rows, health := make([]ascii.TableRow, 0, len(res.Comparisons)), make([]string, 0, len(res.Comparisons))
	for i := range res.Comparisons {
		c, st := &res.Comparisons[i], statusOK
		switch c.Status {
		case "ERROR":
			st = statusFAIL
		case "SPLIT-LOCAL", "LOCAL-ONLY", "PUBLIC-ONLY":
			st = statusWARN
		}
		rows = append(rows, ascii.TableRow{Status: st, Cells: []string{c.RecordType, c.Status, firstNonEmpty(strings.Join(c.LocalAnswers, ", "), c.LocalErr, "-"), firstNonEmpty(strings.Join(c.RemoteAnswers, ", "), c.RemoteErr, "-")}})
		health = append(health, st)
	}
	return makeExecCard(&cardSpec{
		tool: "split_dns_audit", title: "SPLIT DNS AUDIT", subtitle: res.OverallStatus, target: res.Domain, status: status, durMS: durMS, raw: res,
		summary: formatSplitDNSSummary(res),
		metrics: []ascii.MetricKV{{Label: "Overall", Value: res.OverallStatus}, {Label: "Split", Value: strconv.FormatBool(res.SplitDetected)}},
		headers: []string{"Type", "Status", "Local", "Remote"}, rows: rows, health: health,
		dnsComparisons: extractSplitDNSComparisons(res.Comparisons),
	})
}

func buildSNMPExec(res *probe.SNMPResult, durMS int64) *toolExec {
	status := statusOK
	if len(res.Warnings) > 0 {
		status = statusWARN
	}
	rows := make([]ascii.TableRow, 0, len(res.Interfaces))
	for i := range res.Interfaces {
		ifc, st := &res.Interfaces[i], statusOK
		if ifc.OperStatus != "up" {
			st = statusWARN
		}
		rows = append(rows, ascii.TableRow{Status: st, Cells: []string{strconv.Itoa(ifc.Index), ifc.Name, ifc.OperStatus, strconv.FormatUint(ifc.SpeedMbps, 10) + "Mbps"}})
	}
	return makeExecCard(&cardSpec{
		tool: "snmp_switch_port", title: "SNMP SWITCH PORT", subtitle: res.SysName, target: res.Target, status: status, durMS: durMS, raw: res,
		summary: formatSNMPSummary(res),
		metrics: []ascii.MetricKV{{Label: "UpTime", Value: res.SysUpTime}, {Label: "Ifaces", Value: strconv.Itoa(len(res.Interfaces))}, {Label: "FDB", Value: strconv.Itoa(len(res.FDB))}},
		headers: []string{"Idx", "Name", "Oper", "Speed"}, rows: rows, notes: res.Warnings,
	})
}

func buildManageDestinationsExec(res *DestinationResult, durMS int64) *toolExec {
	if res.Action == "run" && res.Outcome != nil && res.Item != nil {
		out := res.Outcome
		return makeExecCard(&cardSpec{
			tool: "manage_saved_destinations", title: "SAVED DESTINATIONS", subtitle: res.Action,
			target: firstNonEmpty(out.Target, res.Item.Target), status: firstNonEmpty(out.Status, statusOK),
			durMS: durMS, raw: res,
			summary:  fmt.Sprintf("Ran %q (%s) -> %s: %s", res.Item.Name, out.Tool, out.Status, out.Summary),
			metrics:  []ascii.MetricKV{{Label: "Action", Value: res.Action}, {Label: "Check", Value: out.Tool}, {Label: "JobID", Value: firstNonEmpty(out.JobID, "-")}},
			headers:  []string{"Name", "Check", "Target", "Status", "JobID"},
			rows:     []ascii.TableRow{{Status: out.Status, Cells: []string{res.Item.Name, out.Tool, out.Target, out.Status, firstNonEmpty(out.JobID, "-")}}},
			whiskers: out.Whiskers, waterfall: out.Waterfall, lan: out.LANInventory, diff: out.SnapshotDiff,
			tlsHealth: out.TLSHealth, dnsComparisons: out.DNSComparisons,
		})
	}
	rows := make([]ascii.TableRow, 0, len(res.Items))
	for i := range res.Items {
		it := &res.Items[i]
		st := statusINFO
		if it.MonitorEnabled {
			st = statusOK
		}
		rows = append(rows, ascii.TableRow{Status: st, Cells: []string{it.ID, it.Name, it.Target, it.DefaultCheck, destinationFlags(it)}})
	}
	target := ""
	if res.Item != nil {
		target = res.Item.Target
	}
	summary := fmt.Sprintf("Saved destinations %s: %d item(s)", res.Action, len(res.Items))
	if res.Action == "save" && res.Item != nil {
		summary = fmt.Sprintf("Saved %q (%s) [%s]", res.Item.Name, res.Item.Target, res.Item.DefaultCheck)
	}
	return makeExecCard(&cardSpec{
		tool: "manage_saved_destinations", title: "SAVED DESTINATIONS", subtitle: res.Action,
		target: target, status: statusOK, durMS: durMS, raw: res, summary: summary,
		metrics: []ascii.MetricKV{{Label: "Action", Value: res.Action}, {Label: "Items", Value: strconv.Itoa(len(res.Items))}},
		headers: []string{"ID", "Name", "Target", "Check", "Flags"}, rows: rows,
	})
}

func destinationFlags(it *store.SavedDestination) string {
	switch {
	case it.Pinned && it.MonitorEnabled:
		return "pinned,monitor"
	case it.Pinned:
		return "pinned"
	case it.MonitorEnabled:
		return "monitor"
	default:
		return "-"
	}
}

func validateDestinationTarget(ctx context.Context, guard *security.TargetGuard, target string) error {
	lower := strings.ToLower(target)
	switch {
	case strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://"):
		u, err := url.Parse(target)
		if err != nil || u.Hostname() == "" {
			return fmt.Errorf("%w: invalid target URL %q", ErrInvalidArgs, target)
		}
		if _, err := guard.ValidateHostOrIP(ctx, u.Hostname()); err != nil {
			return fmt.Errorf("target URL blocked by guard: %w", err)
		}
	case strings.Contains(target, "/"):
		if _, _, err := guard.ValidateCIDR(target); err != nil {
			return fmt.Errorf("target CIDR blocked by guard: %w", err)
		}
	default:
		if _, err := guard.ValidateHostOrIP(ctx, target); err != nil {
			return fmt.Errorf("target host blocked by guard: %w", err)
		}
	}
	return nil
}
