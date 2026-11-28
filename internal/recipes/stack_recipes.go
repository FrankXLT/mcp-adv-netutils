package recipes

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/ascii"
	"github.com/FrankXLT/mcp-adv-netutils/internal/http_ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/port_scan"
	"github.com/FrankXLT/mcp-adv-netutils/internal/probe"
	"github.com/FrankXLT/mcp-adv-netutils/internal/resolver"
	"github.com/FrankXLT/mcp-adv-netutils/internal/tls"
	"github.com/FrankXLT/mcp-adv-netutils/internal/traceroute"
	"github.com/FrankXLT/mcp-adv-netutils/internal/wol"
	"golang.org/x/sync/errgroup"
)

// HostCardParams configures L2-L7 single-host inspection.
type HostCardParams struct {
	Target     string            `json:"target"`
	PortPreset string            `json:"port_preset,omitempty"`
	CheckSNMP  bool              `json:"check_snmp,omitempty"`
	SNMPParams *probe.SNMPParams `json:"snmp_params,omitempty"`
}

// HostCardData aggregates L2-L7 probe responses for a target host.
type HostCardData struct {
	Target     string                      `json:"target"`
	ResolvedIP string                      `json:"resolved_ip"`
	DNS        *resolver.ResolverResponse  `json:"dns,omitempty"`
	ARP        *probe.ARPNeighbor          `json:"arp,omitempty"`
	Ping       *ping.PingResponse          `json:"ping,omitempty"`
	Ports      *port_scan.PortScanResponse `json:"ports,omitempty"`
	TLS        *tls.CheckResult            `json:"tls,omitempty"`
	HTTP       *http_ping.HTTPPingResponse `json:"http,omitempty"`
	SNMP       *probe.SNMPResult           `json:"snmp,omitempty"`
}

// LANRadarParams configures LAN ARP discovery and mDNS/SSDP service enumeration.
type LANRadarParams struct {
	CIDR             string `json:"cidr,omitempty"`
	ActiveARP        bool   `json:"active_arp,omitempty"`
	ResolvePTR       bool   `json:"resolve_ptr,omitempty"`
	DiscoverServices bool   `json:"discover_services,omitempty"`
}

// LANRadarData separates physical UAA neighbors from virtual/Docker LAA neighbors and discovered services.
type LANRadarData struct {
	CIDR             string                    `json:"cidr,omitempty"`
	PhysicalUAA      []probe.ARPNeighbor       `json:"physical_uaa"`
	VirtualLAA       []probe.ARPNeighbor       `json:"virtual_laa"`
	Services         []probe.DiscoveredService `json:"services,omitempty"`
	DiscoveryWarning string                    `json:"discovery_warning,omitempty"`
}

// PathAutopsyParams configures end-to-end path quality, MTU, and traceroute inspection.
type PathAutopsyParams struct {
	Target  string `json:"target"`
	MaxHops int    `json:"max_hops,omitempty"`
	Cycles  int    `json:"cycles,omitempty"`
}

// PathAutopsyData aggregates DNS, ping, MTU, MTR, and traceroute diagnostics plus flagged anomalies.
type PathAutopsyData struct {
	Target            string                         `json:"target"`
	ResolvedIP        string                         `json:"resolved_ip"`
	ProbeMode         string                         `json:"probe_mode,omitempty"`
	Reached           bool                           `json:"reached"`
	SilentTransitHops int                            `json:"silent_transit_hops,omitempty"`
	DestLossPct       float64                        `json:"dest_loss_pct"`
	DNS               *resolver.ResolverResponse     `json:"dns,omitempty"`
	Ping              *ping.PingResponse             `json:"ping,omitempty"`
	MTU               *probe.MTUProbeResult          `json:"mtu,omitempty"`
	MTR               *probe.MTRResult               `json:"mtr,omitempty"`
	Traceroute        *traceroute.TracerouteResponse `json:"traceroute,omitempty"`
	LossHops          []int                          `json:"loss_hops,omitempty"`
	HighJitterHop     []int                          `json:"high_jitter_hops,omitempty"`
	Blackhole         bool                           `json:"pmtud_blackhole"`
}

// WakeVerifyParams configures Wake-on-LAN transmission followed by readiness polling.
type WakeVerifyParams struct {
	MAC         string `json:"mac"`
	Target      string `json:"target"`
	BroadcastIP string `json:"broadcast_ip,omitempty"`
	Port        int    `json:"port,omitempty"`
	WaitSeconds int    `json:"wait_seconds,omitempty"`
	Ports       string `json:"ports,omitempty"`
}

// WakeVerifyData records WoL dispatch and readiness polling metrics.
type WakeVerifyData struct {
	MAC          string                      `json:"mac"`
	Target       string                      `json:"target"`
	Ready        bool                        `json:"ready"`
	ReadyVia     string                      `json:"ready_via,omitempty"`
	WakeToReadyM int64                       `json:"wake_to_ready_ms"`
	Attempts     int                         `json:"attempts"`
	WOL          *wol.WOLResponse            `json:"wol"`
	LastPing     *ping.PingResponse          `json:"last_ping,omitempty"`
	LastPortScan *port_scan.PortScanResponse `json:"last_port_scan,omitempty"`
}

const (
	groupLabelPhysicalUAA = "[PHYSICAL - UAA]"
	groupLabelVirtualLAA  = "[DOCKER/VM - LAA]"
	defaultWakeWaitSec    = 15
	maxWakeWaitSec        = 60
	jitterWarnThresholdMs = 20.0
	jitterSpreadWarnMs    = 50.0
)

// ExecuteHostCard assembles an L2-L7 host diagnostic card via resolver, ARP, ping, port scan, TLS, HTTP, and optional SNMP.
func ExecuteHostCard(ctx context.Context, deps Dependencies, params HostCardParams) (*RecipeResult, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	targetIP, cleanTarget, err := resolveRecipeTarget(ctx, params.Target, deps.Guard)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	preset := firstNonEmpty(params.PortPreset, "common")
	data := HostCardData{Target: cleanTarget, ResolvedIP: targetIP.String()}
	var arpRes *probe.ARPSweepResult
	g, gctx := errgroup.WithContext(ctx)
	goRun(g, func() {
		data.DNS, _ = resolver.Execute(gctx, resolver.ResolverParams{Hostname: cleanTarget, IPVersion: "both"}, deps.resolverCfg())
	})
	goRun(g, func() { arpRes, _ = probe.ExecuteARPSweep(gctx, probe.ARPSweepParams{}, deps.Guard, deps.dnsCfg()) })
	goRun(g, func() {
		data.Ping, _ = ping.Execute(gctx, ping.PingParams{Target: cleanTarget, Count: intPtr(2)}, deps.pingCfg())
	})
	goRun(g, func() {
		data.Ports, _ = port_scan.Execute(gctx, port_scan.PortScanParams{Target: cleanTarget, Ports: preset}, deps.Guard)
	})
	_ = g.Wait()
	for i := 0; arpRes != nil && i < len(arpRes.Neighbors); i++ {
		if arpRes.Neighbors[i].IP == data.ResolvedIP {
			data.ARP = &arpRes.Neighbors[i]
			break
		}
	}
	runHostCardUpperLayers(ctx, deps, &params, cleanTarget, &data)
	rows, health, spark, status, summary := buildHostCardSummary(&data)
	return makeRecipeResult(&cardSpec{
		ToolName: "host_card", Title: "HOST CARD (L2-L7)", Subtitle: "Full-Stack Inspection", Target: cleanTarget, Status: status, Summary: summary, DurationMS: time.Since(started).Milliseconds(),
		Metrics: []ascii.MetricKV{{Label: "IP", Value: data.ResolvedIP}, {Label: "Status", Value: status}}, Headers: []string{"Layer", "Check", "Result", "Detail"},
		Rows: rows, SparkValues: spark, HealthStates: health, RawData: data,
	}), nil
}

// ExecuteLANRadar runs ARP sweep and optional mDNS/SSDP discovery concurrently, grouping [PHYSICAL - UAA] before [DOCKER/VM - LAA].
func ExecuteLANRadar(ctx context.Context, deps Dependencies, params LANRadarParams) (*RecipeResult, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	started := time.Now()
	var arpRes *probe.ARPSweepResult
	var arpErr, discErr error
	var discRes *probe.DiscoverResult
	g, gctx := errgroup.WithContext(ctx)
	goRun(g, func() {
		arpRes, arpErr = probe.ExecuteARPSweep(gctx, probe.ARPSweepParams{CIDR: params.CIDR, ActiveProbe: params.ActiveARP, ResolvePTR: params.ResolvePTR}, deps.Guard, deps.dnsCfg())
	})
	if params.DiscoverServices {
		goRun(g, func() {
			discRes, discErr = probe.ExecuteMDNSSSDPDiscover(gctx, probe.DiscoverParams{Protocol: "both", TimeoutMS: 800}, deps.Guard)
		})
	}
	_ = g.Wait()
	if arpErr != nil {
		return nil, fmt.Errorf("LAN ARP sweep failed: %w", arpErr)
	}
	phys, virt, rows, health := buildLANRadarRows(arpRes, discRes)
	discWarn, status, services, notes := "", StatusOK, []probe.DiscoveredService(nil), []string(nil)
	if discErr != nil {
		discWarn, status, notes = discErr.Error(), StatusWARN, append(notes, "Service discovery warning: "+discErr.Error())
	}
	if discRes != nil {
		services = discRes.Services
	}
	summary := fmt.Sprintf("LAN Radar: %d physical UAA, %d docker/VM LAA, %d service(s)", len(phys), len(virt), len(services))
	return makeRecipeResult(&cardSpec{
		ToolName: "lan_radar", Title: "LAN RADAR", Subtitle: "UAA Physical vs LAA Virtual", Target: firstNonEmpty(arpRes.CIDR, "local-arp"),
		Status: status, Summary: summary, DurationMS: time.Since(started).Milliseconds(),
		Metrics: []ascii.MetricKV{{Label: "Physical UAA", Value: strconv.Itoa(len(phys))}, {Label: "Docker/VM LAA", Value: strconv.Itoa(len(virt))}, {Label: "Services", Value: strconv.Itoa(len(services))}},
		Headers: []string{"Group", "IP", "MAC", "Vendor / Service"}, Rows: rows, HealthStates: health, Notes: notes,
		RawData: LANRadarData{CIDR: arpRes.CIDR, PhysicalUAA: phys, VirtualLAA: virt, Services: services, DiscoveryWarning: discWarn},
	}), nil
}

// ExecutePathAutopsy diagnoses end-to-end path quality across DNS, ping, MTU/PMTUD, MTR quality, and traceroute.
func ExecutePathAutopsy(ctx context.Context, deps Dependencies, params PathAutopsyParams) (*RecipeResult, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	targetIP, cleanTarget, err := resolveRecipeTarget(ctx, params.Target, deps.Guard)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	data := PathAutopsyData{Target: cleanTarget, ResolvedIP: targetIP.String()}
	var mtuErr, mtrErr, trErr error
	g, gctx := errgroup.WithContext(ctx)
	goRun(g, func() {
		data.DNS, _ = resolver.Execute(gctx, resolver.ResolverParams{Hostname: cleanTarget, IPVersion: "both"}, deps.resolverCfg())
	})
	goRun(g, func() {
		data.Ping, _ = ping.Execute(gctx, ping.PingParams{Target: cleanTarget, Count: intPtr(2)}, deps.pingCfg())
	})
	goRun(g, func() {
		data.MTU, mtuErr = probe.ExecuteMTUProbe(gctx, probe.MTUProbeParams{Target: cleanTarget}, deps.Guard)
	})
	goRun(g, func() {
		data.MTR, mtrErr = probe.ExecuteMTRQuality(gctx, probe.MTRParams{Target: cleanTarget, MaxHops: params.MaxHops, Cycles: params.Cycles}, deps.Guard)
	})
	goRun(g, func() {
		data.Traceroute, trErr = traceroute.Execute(gctx, traceroute.TracerouteParams{Target: cleanTarget, MaxHops: intPtr(params.MaxHops)}, deps.Guard)
	})
	_ = g.Wait()

	rows, spark, health, notes, status := analyzePathAutopsy(&data, mtuErr, mtrErr, trErr)
	summary := fmt.Sprintf("Path autopsy for %s (%s): status %s", cleanTarget, data.ResolvedIP, status)
	if data.MTU != nil {
		summary += fmt.Sprintf(", MTU=%d (WG=%d)", data.MTU.DiscoveredMTU, data.MTU.WireGuardSafeMTU)
	}
	return makeRecipeResult(&cardSpec{
		ToolName: "path_autopsy", Title: "PATH AUTOPSY", Subtitle: "MTR + PMTUD + Trace", Target: cleanTarget, Status: status, Summary: summary, DurationMS: time.Since(started).Milliseconds(),
		Metrics: []ascii.MetricKV{
			{Label: "IP", Value: data.ResolvedIP},
			{Label: "Probe Mode", Value: firstNonEmpty(data.ProbeMode, "unknown")},
			{Label: "Dest Loss", Value: fmt.Sprintf("%.0f%%", data.DestLossPct)},
			{Label: "Silent Transit", Value: strconv.Itoa(data.SilentTransitHops)},
			{Label: "Loss Hops", Value: strconv.Itoa(len(data.LossHops))},
			{Label: "Blackhole", Value: strconv.FormatBool(data.Blackhole)},
		},
		Headers: []string{"Hop", "IP", "Loss%", "AvgMs", "StDev", "Flag"}, Rows: rows, SparkValues: spark, HealthStates: health, Notes: notes, RawData: data,
	}), nil
}

// ExecuteWakeVerify sends a Wake-on-LAN magic packet and polls ping/port_scan until the host responds or WaitSeconds (1..60s) elapses.
//
//nolint:gocritic // Exported recipe signature accepts WakeVerifyParams by value.
func ExecuteWakeVerify(ctx context.Context, deps Dependencies, params WakeVerifyParams) (*RecipeResult, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	_, cleanTarget, err := resolveRecipeTarget(ctx, params.Target, deps.Guard)
	if err != nil {
		return nil, err
	}
	params.Target = cleanTarget
	waitSec := defaultWakeWaitSec
	if params.WaitSeconds > 0 {
		waitSec = min(params.WaitSeconds, maxWakeWaitSec)
	}
	wolRes, err := wol.Execute(ctx, wol.WOLParams{MAC: params.MAC, BroadcastIP: params.BroadcastIP, Port: intPtr(params.Port)}, deps.Guard)
	if err != nil {
		return nil, fmt.Errorf("WoL dispatch failed: %w", err)
	}
	started := time.Now()
	ready, readyVia, attempts, lastPing, lastScan := pollWakeReadiness(ctx, deps, &params, time.Duration(waitSec)*time.Second)
	elapsedMS := time.Since(started).Milliseconds()
	status, summary := StatusFAIL, fmt.Sprintf("Host %s did not respond within %ds after WoL (%d attempts)", params.Target, waitSec, attempts)
	if ready {
		status, summary = StatusOK, fmt.Sprintf("Host %s ready via %s in %dms (%d attempt(s))", params.Target, readyVia, elapsedMS, attempts)
	}
	return makeRecipeResult(&cardSpec{
		ToolName: "wake_verify", Title: "WAKE & VERIFY", Subtitle: "WoL + Readiness Poll", Target: params.Target, Status: status, Summary: summary, DurationMS: elapsedMS,
		Metrics: []ascii.MetricKV{{Label: "MAC", Value: wolRes.Normalized}, {Label: "Wake-to-Ready", Value: strconv.FormatInt(elapsedMS, 10) + "ms"}},
		Headers: []string{"Phase", "Target", "Channel", "Outcome"}, HealthStates: []string{StatusOK, status},
		Rows: []ascii.TableRow{
			{Status: StatusOK, Cells: []string{"WoL Packet", wolRes.Normalized, wolRes.BroadcastIP + ":" + strconv.Itoa(wolRes.Port), "sent"}},
			{Status: status, Cells: []string{"Readiness", params.Target, firstNonEmpty(readyVia, "timeout"), fmt.Sprintf("%dms (%d tries)", elapsedMS, attempts)}},
		},
		RawData: WakeVerifyData{MAC: wolRes.Normalized, Target: params.Target, Ready: ready, ReadyVia: readyVia, WakeToReadyM: elapsedMS, Attempts: attempts, WOL: wolRes, LastPing: lastPing, LastPortScan: lastScan},
	}), nil
}

func runHostCardUpperLayers(ctx context.Context, deps Dependencies, params *HostCardParams, target string, data *HostCardData) {
	open80, open443 := false, false
	if data.Ports != nil {
		for _, pr := range data.Ports.Ports {
			open80, open443 = open80 || (pr.State == "open" && pr.Port == 80), open443 || (pr.State == "open" && pr.Port == 443)
		}
	}
	var g errgroup.Group
	if open443 {
		goRun(&g, func() { data.TLS, _ = tls.Execute(ctx, tls.TLSCheckParams{Domain: target, Port: 443}, deps.tlsCfg()) })
	}
	if open80 || open443 {
		url := map[bool]string{false: "http://", true: "https://"}[open443] + target
		goRun(&g, func() {
			data.HTTP, _ = http_ping.Execute(ctx, http_ping.HTTPPingParams{URL: url, Count: intPtr(1)}, deps.httpCfg())
		})
	}
	if params.CheckSNMP || params.SNMPParams != nil {
		sp := probe.SNMPParams{Target: target}
		if params.SNMPParams != nil {
			sp = *params.SNMPParams
			sp.Target = firstNonEmpty(sp.Target, target)
		}
		goRun(&g, func() { data.SNMP, _ = probe.ExecuteSNMPSwitchPort(ctx, sp, deps.Guard) })
	}
	_ = g.Wait()
}

func buildHostCardSummary(data *HostCardData) ([]ascii.TableRow, []string, []float64, string, string) {
	rows, health, spark := make([]ascii.TableRow, 0, 6), make([]string, 0, 6), make([]float64, 0, 2)
	add := func(st string, cells ...string) {
		rows, health = append(rows, ascii.TableRow{Status: st, Cells: cells}), append(health, st)
	}
	if data.ARP != nil {
		add(StatusOK, "L2 ARP", data.ARP.MAC, data.ARP.AddressType, data.ARP.Vendor)
	} else {
		add(StatusINFO, "L2 ARP", "-", "not in cache", "-")
	}
	pingSt := StatusFAIL
	if data.Ping != nil {
		if data.Ping.PacketsReceived > 0 {
			pingSt = map[bool]string{false: StatusWARN, true: StatusOK}[data.Ping.PacketLoss == 0]
		}
		spark = append(spark, data.Ping.AvgRTT)
		add(pingSt, "L3 Ping", data.ResolvedIP, data.Ping.ProbeMode, fmt.Sprintf("loss=%.0f%% rtt=%.2fms", data.Ping.PacketLoss, data.Ping.AvgRTT))
	} else {
		add(StatusFAIL, "L3 Ping", data.ResolvedIP, "error", "unavailable")
	}
	var openPorts []string
	if data.Ports != nil {
		for _, p := range data.Ports.Ports {
			if p.State == "open" {
				openPorts = append(openPorts, strconv.Itoa(p.Port))
			}
		}
	}
	add(map[bool]string{false: StatusINFO, true: StatusOK}[len(openPorts) > 0], "L4 TCP", strconv.Itoa(len(openPorts))+" open", strings.Join(openPorts, ","), "-")
	tlsSt := StatusOK
	if data.TLS != nil {
		exp, expired := 0, false
		if len(data.TLS.PeerCertificates) > 0 {
			exp, expired = data.TLS.PeerCertificates[0].ExpiresInDays, data.TLS.PeerCertificates[0].IsExpired
		}
		if expired {
			tlsSt = StatusFAIL
		} else if !data.TLS.ChainValid {
			tlsSt = StatusWARN
		}
		add(tlsSt, "L6 TLS", data.TLS.TLSVersion, data.TLS.CipherSuite, fmt.Sprintf("valid=%v exp=%dd", data.TLS.ChainValid, exp))
	}
	if data.HTTP != nil {
		spark = append(spark, data.HTTP.AvgTotalTime)
		add(map[bool]string{false: StatusFAIL, true: StatusOK}[data.HTTP.SuccessCount > 0], "L7 HTTP", data.HTTP.Target, fmt.Sprintf("%d/%d ok", data.HTTP.SuccessCount, data.HTTP.RequestsSent), fmt.Sprintf("total=%.1fms", data.HTTP.AvgTotalTime))
	}
	if data.SNMP != nil {
		add(StatusOK, "L7 SNMP", data.SNMP.SysName, strconv.Itoa(len(data.SNMP.Interfaces))+" ifaces", data.SNMP.SysDescr)
	}
	overall := worstStatus(pingSt, tlsSt)
	if pingSt == StatusFAIL && len(openPorts) > 0 {
		overall = StatusWARN
	}
	return rows, health, spark, overall, fmt.Sprintf("Host %s (%s): ping=%s, %d open port(s)", data.Target, data.ResolvedIP, pingSt, len(openPorts))
}

func buildLANRadarRows(arpRes *probe.ARPSweepResult, discRes *probe.DiscoverResult) ([]probe.ARPNeighbor, []probe.ARPNeighbor, []ascii.TableRow, []string) {
	var phys, virt []probe.ARPNeighbor
	var rows, virtRows []ascii.TableRow
	var health, virtHealth []string
	if arpRes != nil {
		for i := range arpRes.Neighbors {
			n := &arpRes.Neighbors[i]
			if n.IsLAA {
				virt, virtRows, virtHealth = append(virt, *n), append(virtRows, ascii.TableRow{Status: StatusINFO, Cells: []string{groupLabelVirtualLAA, n.IP, n.MAC, firstNonEmpty(n.Hostname, n.Vendor)}}), append(virtHealth, StatusINFO)
			} else {
				phys, rows, health = append(phys, *n), append(rows, ascii.TableRow{Status: StatusOK, Cells: []string{groupLabelPhysicalUAA, n.IP, n.MAC, firstNonEmpty(n.Hostname, n.Vendor)}}), append(health, StatusOK)
			}
		}
	}
	rows, health = append(rows, virtRows...), append(health, virtHealth...)
	if discRes != nil {
		for i := range discRes.Services {
			s := &discRes.Services[i]
			rows, health = append(rows, ascii.TableRow{Status: StatusINFO, Cells: []string{"[SERVICE - " + strings.ToUpper(s.Protocol) + "]", s.IP, ":" + strconv.Itoa(s.Port), firstNonEmpty(s.Name, s.ServiceType, s.Server)}}), append(health, StatusINFO)
		}
	}
	return phys, virt, rows, health
}

func selectPathAutopsyHops(data *PathAutopsyData) ([]probe.MTRHop, bool) {
	var hops []probe.MTRHop
	useMTR := false
	if data.MTR != nil {
		data.ProbeMode, data.Reached, data.SilentTransitHops, data.DestLossPct = data.MTR.ProbeMode, data.MTR.Reached, data.MTR.SilentTransitHops, data.MTR.DestLossPct
		if useMTR = data.MTR.Reached || data.Traceroute == nil || (!data.Traceroute.ReachedDestination && (len(data.MTR.Hops) > 0 || len(data.Traceroute.Hops) == 0)); useMTR {
			hops = data.MTR.Hops
		}
	}
	if !useMTR && data.Traceroute != nil {
		data.ProbeMode, data.Reached, data.SilentTransitHops, data.DestLossPct = firstNonEmpty(data.Traceroute.ProbeMode, data.ProbeMode), data.Traceroute.ReachedDestination, data.Traceroute.SilentTransitHops, data.Traceroute.DestLossPct
		hops = make([]probe.MTRHop, len(data.Traceroute.Hops))
		for i := range data.Traceroute.Hops {
			h := &data.Traceroute.Hops[i]
			loss := map[bool]float64{true: 100}[h.TimedOut && !h.Silent]
			if !h.Silent && !h.TimedOut && data.DestLossPct > 0 && (h.Segment == "Destination" || (data.ResolvedIP != "" && h.IP == data.ResolvedIP) || (data.Reached && i == len(data.Traceroute.Hops)-1)) {
				loss = data.DestLossPct
			}
			hops[i] = probe.MTRHop{Hop: h.Hop, IP: h.IP, Segment: h.Segment, Silent: h.Silent, LossPct: loss, AvgMs: h.AvgRTTMs}
		}
	}
	if !data.Reached && data.DestLossPct == 0 && (data.MTR != nil || data.Traceroute != nil) {
		data.DestLossPct = 100
	}
	return hops, useMTR
}

func analyzePathAutopsy(data *PathAutopsyData, mtuErr, mtrErr, trErr error) ([]ascii.TableRow, []float64, []string, []string, string) {
	hops, useMTR := selectPathAutopsyHops(data)
	rows, spark, health, overall, silent := make([]ascii.TableRow, 0, len(hops)), make([]float64, 0, len(hops)), make([]string, 0, len(hops)), StatusOK, 0
	for i := range hops {
		h, st, flag := &hops[i], StatusOK, "ok"
		if h.Silent {
			silent++
			rows, spark, health = append(rows, ascii.TableRow{Status: StatusOK, Cells: []string{strconv.Itoa(h.Hop), firstNonEmpty(h.IP, "*"), "*", "*", "*", "silent (CoPP)"}}), append(spark, 0), append(health, StatusOK)
			continue
		}
		isDest := h.Segment == "Destination" || (data.ResolvedIP != "" && h.IP == data.ResolvedIP) || (data.Reached && i == len(hops)-1)
		if h.LossPct >= 20 || (!data.Reached && h.LossPct >= 50) {
			data.LossHops, flag = append(data.LossHops, h.Hop), "loss"
			st = map[bool]string{true: StatusFAIL, false: StatusWARN}[h.LossPct >= 50 && (isDest || !data.Reached)]
		}
		if useMTR && (h.StDevMs >= jitterWarnThresholdMs || (h.WorstMs-h.BestMs) >= jitterSpreadWarnMs) {
			data.HighJitterHop, st, flag = append(data.HighJitterHop, h.Hop), worstStatus(st, StatusWARN), map[bool]string{true: "jitter", false: flag + "+jitter"}[flag == "ok"]
		}
		avgCell, stdevCell := map[bool]string{true: "*", false: fmt.Sprintf("%.2f", h.AvgMs)}[!useMTR && h.LossPct >= 100], map[bool]string{true: fmt.Sprintf("%.2f", h.StDevMs), false: "-"}[useMTR]
		overall, rows, spark, health = worstStatus(overall, st), append(rows, ascii.TableRow{Status: st, Cells: []string{strconv.Itoa(h.Hop), firstNonEmpty(h.IP, "*"), fmt.Sprintf("%.0f%%", h.LossPct), avgCell, stdevCell, flag}}), append(spark, h.AvgMs), append(health, st)
	}
	data.SilentTransitHops = max(data.SilentTransitHops, silent)
	var notes []string
	if mtrErr != nil && data.MTR == nil {
		notes, overall = append(notes, "MTR unavailable: "+mtrErr.Error()), worstStatus(overall, StatusWARN)
	}
	if (!data.Reached && (data.MTR != nil || data.Traceroute != nil || (data.Ping != nil && data.Ping.PacketsReceived == 0 && (mtrErr == nil || trErr == nil)))) || (data.Reached && data.DestLossPct >= 50) {
		overall = StatusFAIL
	} else if data.Reached && data.DestLossPct >= 20 {
		overall = worstStatus(overall, StatusWARN)
	}
	if data.SilentTransitHops > 0 {
		suffix := map[bool]string{false: "hop(s) did not reply before the unreachable tail.", true: "router(s) dropped ICMP TTL replies under CoPP while traffic reached the destination."}[data.Reached]
		notes = append(notes, fmt.Sprintf("%d silent transit %s", data.SilentTransitHops, suffix))
	}
	if data.MTU != nil {
		if data.Blackhole = data.MTU.BlackholeDetected; data.Blackhole && (!data.Reached || data.MTU.DiscoveredMTU == 0) {
			overall = StatusFAIL
		} else if data.Blackhole || (data.MTU.DiscoveredMTU > 0 && data.MTU.DiscoveredMTU < 1500) {
			overall = worstStatus(overall, StatusWARN)
		}
		notes = append(notes, fmt.Sprintf("Path MTU=%d WG=%d blackhole=%v", data.MTU.DiscoveredMTU, data.MTU.WireGuardSafeMTU, data.Blackhole))
	} else if mtuErr != nil {
		notes = append(notes, "MTU probe warning: "+mtuErr.Error())
	}
	if trErr != nil {
		notes = append(notes, "Traceroute note: "+trErr.Error())
	} else if data.Traceroute != nil {
		notes = append(notes, fmt.Sprintf("Traceroute hops=%d reached=%v", len(data.Traceroute.Hops), data.Traceroute.ReachedDestination))
	}
	return rows, spark, health, notes, overall
}

func pollWakeReadiness(ctx context.Context, deps Dependencies, params *WakeVerifyParams, waitDur time.Duration) (bool, string, int, *ping.PingResponse, *port_scan.PortScanResponse) {
	deadline, attempts, pingCfg := time.Now().Add(waitDur), 0, *deps.pingCfg()
	pingCfg.Timeout = time.Second
	var lastPing *ping.PingResponse
	var lastScan *port_scan.PortScanResponse
	for ctx.Err() == nil {
		attempts++
		iterCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
		readyVia := ""
		if strings.TrimSpace(params.Ports) != "" {
			if lastScan, _ = port_scan.Execute(iterCtx, port_scan.PortScanParams{Target: params.Target, Ports: params.Ports, TimeoutMS: intPtr(500)}, deps.Guard); lastScan != nil && lastScan.OpenCount > 0 {
				readyVia = "tcp_port_scan"
			}
		} else if lastPing, _ = ping.Execute(iterCtx, ping.PingParams{Target: params.Target, Count: intPtr(1)}, &pingCfg); lastPing != nil && lastPing.PacketsReceived > 0 {
			readyVia = lastPing.ProbeMode
		}
		cancel()
		if readyVia != "" || !time.Now().Before(deadline) {
			return readyVia != "", readyVia, attempts, lastPing, lastScan
		}
		select {
		case <-ctx.Done():
			return false, "", attempts, lastPing, lastScan
		case <-time.After(min(250*time.Millisecond, time.Until(deadline))):
		}
	}
	return false, "", attempts, lastPing, lastScan
}
