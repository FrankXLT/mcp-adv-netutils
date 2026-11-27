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
	Target        string                         `json:"target"`
	ResolvedIP    string                         `json:"resolved_ip"`
	DNS           *resolver.ResolverResponse     `json:"dns,omitempty"`
	Ping          *ping.PingResponse             `json:"ping,omitempty"`
	MTU           *probe.MTUProbeResult          `json:"mtu,omitempty"`
	MTR           *probe.MTRResult               `json:"mtr,omitempty"`
	Traceroute    *traceroute.TracerouteResponse `json:"traceroute,omitempty"`
	LossHops      []int                          `json:"loss_hops,omitempty"`
	HighJitterHop []int                          `json:"high_jitter_hops,omitempty"`
	Blackhole     bool                           `json:"pmtud_blackhole"`
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
	if arpRes != nil {
		for i := range arpRes.Neighbors {
			if arpRes.Neighbors[i].IP == data.ResolvedIP {
				data.ARP = &arpRes.Neighbors[i]
				break
			}
		}
	}
	runHostCardUpperLayers(ctx, deps, &params, cleanTarget, &data)
	rows, health, spark, status, summary := buildHostCardSummary(&data)
	return makeRecipeResult(&cardSpec{
		ToolName: "host_card", Title: "HOST CARD (L2-L7)", Subtitle: "Full-Stack Inspection", Target: cleanTarget,
		Status: status, Summary: summary, DurationMS: time.Since(started).Milliseconds(),
		Metrics: []ascii.MetricKV{{Label: "IP", Value: data.ResolvedIP}, {Label: "Status", Value: status}},
		Headers: []string{"Layer", "Check", "Result", "Detail"}, Rows: rows, SparkValues: spark, HealthStates: health, RawData: data,
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
	var notes []string
	discWarn, status := "", StatusOK
	if discErr != nil {
		discWarn, status, notes = discErr.Error(), StatusWARN, append(notes, "Service discovery warning: "+discErr.Error())
	}
	if discRes == nil {
		discRes = &probe.DiscoverResult{}
	}
	summary := fmt.Sprintf("LAN Radar: %d physical UAA, %d docker/VM LAA, %d service(s)", len(phys), len(virt), len(discRes.Services))
	return makeRecipeResult(&cardSpec{
		ToolName: "lan_radar", Title: "LAN RADAR", Subtitle: "UAA Physical vs LAA Virtual", Target: firstNonEmpty(arpRes.CIDR, "local-arp"),
		Status: status, Summary: summary, DurationMS: time.Since(started).Milliseconds(),
		Metrics: []ascii.MetricKV{{Label: "Physical UAA", Value: strconv.Itoa(len(phys))}, {Label: "Docker/VM LAA", Value: strconv.Itoa(len(virt))}, {Label: "Services", Value: strconv.Itoa(len(discRes.Services))}},
		Headers: []string{"Group", "IP", "MAC", "Vendor / Service"}, Rows: rows, HealthStates: health, Notes: notes,
		RawData: LANRadarData{CIDR: arpRes.CIDR, PhysicalUAA: phys, VirtualLAA: virt, Services: discRes.Services, DiscoveryWarning: discWarn},
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
		ToolName: "path_autopsy", Title: "PATH AUTOPSY", Subtitle: "MTR + PMTUD + Trace", Target: cleanTarget,
		Status: status, Summary: summary, DurationMS: time.Since(started).Milliseconds(),
		Metrics: []ascii.MetricKV{{Label: "IP", Value: data.ResolvedIP}, {Label: "Loss Hops", Value: strconv.Itoa(len(data.LossHops))}, {Label: "Blackhole", Value: strconv.FormatBool(data.Blackhole)}},
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
	waitSec := min(max(params.WaitSeconds, 1), maxWakeWaitSec)
	if params.WaitSeconds == 0 {
		waitSec = defaultWakeWaitSec
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
		ToolName: "wake_verify", Title: "WAKE & VERIFY", Subtitle: "WoL + Readiness Poll", Target: params.Target,
		Status: status, Summary: summary, DurationMS: elapsedMS,
		Metrics: []ascii.MetricKV{{Label: "MAC", Value: wolRes.Normalized}, {Label: "Wake-to-Ready", Value: strconv.FormatInt(elapsedMS, 10) + "ms"}},
		Headers: []string{"Phase", "Target", "Channel", "Outcome"}, HealthStates: []string{StatusOK, status},
		Rows: []ascii.TableRow{
			{Status: StatusOK, Cells: []string{"WoL Packet", wolRes.Normalized, wolRes.BroadcastIP + ":" + strconv.Itoa(wolRes.Port), "sent"}},
			{Status: status, Cells: []string{"Readiness", params.Target, firstNonEmpty(readyVia, "timeout"), fmt.Sprintf("%dms (%d tries)", elapsedMS, attempts)}},
		},
		RawData: WakeVerifyData{MAC: wolRes.Normalized, Target: params.Target, Ready: ready, ReadyVia: readyVia, WakeToReadyM: elapsedMS, Attempts: attempts, WOL: wolRes, LastPing: lastPing, LastPortScan: lastScan},
	}), nil
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

func runHostCardUpperLayers(ctx context.Context, deps Dependencies, params *HostCardParams, target string, data *HostCardData) {
	open80, open443 := false, false
	if data.Ports != nil {
		for _, pr := range data.Ports.Ports {
			if pr.State == "open" {
				open80, open443 = open80 || pr.Port == 80, open443 || pr.Port == 443
			}
		}
	}
	var g errgroup.Group
	if open443 {
		goRun(&g, func() { data.TLS, _ = tls.Execute(ctx, tls.TLSCheckParams{Domain: target, Port: 443}, deps.tlsCfg()) })
	}
	if open80 || open443 {
		scheme := "http://"
		if open443 {
			scheme = "https://"
		}
		goRun(&g, func() {
			data.HTTP, _ = http_ping.Execute(ctx, http_ping.HTTPPingParams{URL: scheme + target, Count: intPtr(1)}, deps.httpCfg())
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
	addRow := func(st string, cells ...string) {
		rows, health = append(rows, ascii.TableRow{Status: st, Cells: cells}), append(health, st)
	}
	if data.ARP != nil {
		addRow(StatusOK, "L2 ARP", data.ARP.MAC, data.ARP.AddressType, data.ARP.Vendor)
	} else {
		addRow(StatusINFO, "L2 ARP", "-", "not in cache", "-")
	}
	pingSt := StatusFAIL
	if data.Ping != nil {
		if data.Ping.PacketsReceived > 0 && data.Ping.PacketLoss == 0 {
			pingSt = StatusOK
		} else if data.Ping.PacketsReceived > 0 {
			pingSt = StatusWARN
		}
		spark = append(spark, data.Ping.AvgRTT)
		addRow(pingSt, "L3 Ping", data.ResolvedIP, data.Ping.ProbeMode, fmt.Sprintf("loss=%.0f%% rtt=%.2fms", data.Ping.PacketLoss, data.Ping.AvgRTT))
	} else {
		addRow(StatusFAIL, "L3 Ping", data.ResolvedIP, "error", "unavailable")
	}
	var openPorts []string
	if data.Ports != nil {
		for _, p := range data.Ports.Ports {
			if p.State == "open" {
				openPorts = append(openPorts, strconv.Itoa(p.Port))
			}
		}
	}
	portSt := StatusINFO
	if len(openPorts) > 0 {
		portSt = StatusOK
	}
	addRow(portSt, "L4 TCP", strconv.Itoa(len(openPorts))+" open", strings.Join(openPorts, ","), "-")
	tlsSt := StatusOK
	if data.TLS != nil {
		exp := 0
		if len(data.TLS.PeerCertificates) > 0 {
			exp = data.TLS.PeerCertificates[0].ExpiresInDays
		}
		if len(data.TLS.PeerCertificates) > 0 && data.TLS.PeerCertificates[0].IsExpired {
			tlsSt = StatusFAIL
		} else if !data.TLS.ChainValid {
			tlsSt = StatusWARN
		}
		addRow(tlsSt, "L6 TLS", data.TLS.TLSVersion, data.TLS.CipherSuite, fmt.Sprintf("valid=%v exp=%dd", data.TLS.ChainValid, exp))
	}
	if data.HTTP != nil {
		httpSt := StatusOK
		if data.HTTP.SuccessCount == 0 {
			httpSt = StatusFAIL
		}
		spark = append(spark, data.HTTP.AvgTotalTime)
		addRow(httpSt, "L7 HTTP", data.HTTP.Target, fmt.Sprintf("%d/%d ok", data.HTTP.SuccessCount, data.HTTP.RequestsSent), fmt.Sprintf("total=%.1fms", data.HTTP.AvgTotalTime))
	}
	if data.SNMP != nil {
		addRow(StatusOK, "L7 SNMP", data.SNMP.SysName, strconv.Itoa(len(data.SNMP.Interfaces))+" ifaces", data.SNMP.SysDescr)
	}
	overall := worstStatus(pingSt, tlsSt)
	if pingSt == StatusFAIL && len(openPorts) > 0 {
		overall = StatusWARN
	}
	return rows, health, spark, overall, fmt.Sprintf("Host %s (%s): ping=%s, %d open port(s)", data.Target, data.ResolvedIP, pingSt, len(openPorts))
}

func buildLANRadarRows(arpRes *probe.ARPSweepResult, discRes *probe.DiscoverResult) ([]probe.ARPNeighbor, []probe.ARPNeighbor, []ascii.TableRow, []string) {
	var phys, virt []probe.ARPNeighbor
	if arpRes != nil {
		for i := range arpRes.Neighbors {
			if arpRes.Neighbors[i].IsLAA {
				virt = append(virt, arpRes.Neighbors[i])
			} else {
				phys = append(phys, arpRes.Neighbors[i])
			}
		}
	}
	rows, health := make([]ascii.TableRow, 0, len(phys)+len(virt)), make([]string, 0, len(phys)+len(virt))
	appendARP := func(list []probe.ARPNeighbor, label, st string) {
		for i := range list {
			n := &list[i]
			rows, health = append(rows, ascii.TableRow{Status: st, Cells: []string{label, n.IP, n.MAC, firstNonEmpty(n.Hostname, n.Vendor)}}), append(health, st)
		}
	}
	appendARP(phys, groupLabelPhysicalUAA, StatusOK)
	appendARP(virt, groupLabelVirtualLAA, StatusINFO)
	if discRes != nil {
		for i := range discRes.Services {
			s := &discRes.Services[i]
			rows, health = append(rows, ascii.TableRow{Status: StatusINFO, Cells: []string{"[SERVICE - " + strings.ToUpper(s.Protocol) + "]", s.IP, ":" + strconv.Itoa(s.Port), firstNonEmpty(s.Name, s.ServiceType, s.Server)}}), append(health, StatusINFO)
		}
	}
	return phys, virt, rows, health
}

func analyzePathAutopsy(data *PathAutopsyData, mtuErr, mtrErr, trErr error) ([]ascii.TableRow, []float64, []string, []string, string) {
	var rows []ascii.TableRow
	var spark []float64
	var healthStr, notes []string
	overall := StatusOK
	if data.MTR != nil {
		for i := range data.MTR.Hops {
			h, st, flag := &data.MTR.Hops[i], StatusOK, "ok"
			if h.LossPct > 0 {
				data.LossHops, st, flag = append(data.LossHops, h.Hop), StatusWARN, "loss"
				if h.LossPct >= 50 {
					st = StatusFAIL
				}
			}
			if h.StDevMs >= jitterWarnThresholdMs || (h.WorstMs-h.BestMs) >= jitterSpreadWarnMs {
				data.HighJitterHop, st, flag = append(data.HighJitterHop, h.Hop), worstStatus(st, StatusWARN), flag+"+jitter"
			}
			overall = worstStatus(overall, st)
			rows = append(rows, ascii.TableRow{Status: st, Cells: []string{strconv.Itoa(h.Hop), h.IP, fmt.Sprintf("%.0f%%", h.LossPct), fmt.Sprintf("%.2f", h.AvgMs), fmt.Sprintf("%.2f", h.StDevMs), flag}})
			spark, healthStr = append(spark, h.AvgMs), append(healthStr, st)
		}
	} else if mtrErr != nil {
		notes, overall = append(notes, "MTR unavailable: "+mtrErr.Error()), worstStatus(overall, StatusWARN)
	}
	if data.MTU != nil {
		data.Blackhole = data.MTU.BlackholeDetected
		if data.Blackhole {
			overall = StatusFAIL
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
	if data.Ping != nil && data.Ping.PacketsReceived == 0 && (data.MTR == nil || !data.MTR.Reached) {
		overall = StatusFAIL
	}
	return rows, spark, healthStr, notes, overall
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
			if scanRes, err := port_scan.Execute(iterCtx, port_scan.PortScanParams{Target: params.Target, Ports: params.Ports, TimeoutMS: intPtr(500)}, deps.Guard); err == nil {
				lastScan = scanRes
				if scanRes.OpenCount > 0 {
					readyVia = "tcp_port_scan"
				}
			}
		} else if pingRes, err := ping.Execute(iterCtx, ping.PingParams{Target: params.Target, Count: intPtr(1)}, &pingCfg); err == nil {
			lastPing = pingRes
			if pingRes.PacketsReceived > 0 {
				readyVia = pingRes.ProbeMode
			}
		}
		cancel()
		if readyVia != "" {
			return true, readyVia, attempts, lastPing, lastScan
		}
		if !time.Now().Before(deadline) {
			break
		}
		timer := time.NewTimer(min(250*time.Millisecond, time.Until(deadline)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return false, "", attempts, lastPing, lastScan
		case <-timer.C:
		}
	}
	return false, "", attempts, lastPing, lastScan
}
