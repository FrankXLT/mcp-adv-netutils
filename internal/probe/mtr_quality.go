package probe

import (
	"context"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sync/errgroup"
)

// MTRParams defines configuration for multi-cycle MTR path quality probing.
type MTRParams struct {
	Target    string `json:"target"`
	MaxHops   int    `json:"max_hops,omitempty"`
	Cycles    int    `json:"cycles,omitempty"`
	TimeoutMS int    `json:"timeout_ms,omitempty"`
}

// MTRHop holds packet loss and RTT distribution statistics for one path hop.
type MTRHop struct {
	Hop      int     `json:"hop"`
	IP       string  `json:"ip"`
	Hostname string  `json:"hostname,omitempty"`
	Segment  string  `json:"segment,omitempty"`
	Silent   bool    `json:"silent,omitempty"`
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	LossPct  float64 `json:"loss_pct"`
	LastMs   float64 `json:"last_ms"`
	AvgMs    float64 `json:"avg_ms"`
	BestMs   float64 `json:"best_ms"`
	WorstMs  float64 `json:"worst_ms"`
	StDevMs  float64 `json:"stdev_ms"`
}

// MTRResult summarizes hop-by-hop quality metrics across multiple probe cycles.
type MTRResult struct {
	Target            string   `json:"target"`
	ResolvedIP        string   `json:"resolved_ip"`
	ProbeMode         string   `json:"probe_mode"`
	Cycles            int      `json:"cycles"`
	MaxHops           int      `json:"max_hops"`
	Reached           bool     `json:"reached"`
	SilentTransitHops int      `json:"silent_transit_hops,omitempty"`
	DestLossPct       float64  `json:"dest_loss_pct"`
	Hops              []MTRHop `json:"hops"`
	Timestamp         string   `json:"timestamp"`
}

type hopAccumulator struct {
	ip     string
	sent   int
	rttsMs []float64
}

type icmpTransport struct {
	conn     *icmp.PacketConn
	p4       *ipv4.PacketConn
	p6       *ipv6.PacketConn
	isIPv4   bool
	protoNum int
	echoType icmp.Type
}

const (
	mtrICMPProtoV4      = 1
	mtrICMPProtoV6      = 58
	ptrConcurrencyLimit = 8
	ptrLookupTimeout    = time.Second
)

// ExecuteMTRQuality probes hops 1..MaxHops across Cycles rounds to measure per-hop packet
// loss and latency jitter, escalating automatically to concurrent TCP probing when ICMP fails.
func ExecuteMTRQuality(ctx context.Context, params MTRParams, guard *security.TargetGuard) (*MTRResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", security.ErrTargetInvalid)
	}

	resolvedIP, err := validateProbeTarget(ctx, params.Target, guard)
	if err != nil {
		return nil, err
	}

	maxHops, cycles, timeout := normalizeMTRParams(params)
	result, ok := executeICMPMTR(ctx, resolvedIP, maxHops, cycles, timeout)
	if !ok || !result.Reached {
		tcpRes := executeTCPWaveMTR(ctx, resolvedIP, maxHops, cycles, timeout)
		result = selectWinningMTRResult(result, ok, tcpRes)
	}

	finalizeMTRMetadata(result, resolvedIP)
	resolveMTRHopHostnames(ctx, result.Hops)

	result.Target = strings.TrimSpace(params.Target)
	result.ResolvedIP = resolvedIP.String()
	if result.Cycles == 0 {
		result.Cycles = cycles
	}
	result.MaxHops = maxHops
	result.Timestamp = time.Now().UTC().Format(time.RFC3339)
	return result, nil
}

// ExecuteTCPTraceroute executes pure-Go IP_TTL TCP wave probing (443/80 with fallback)
// and populates hop segmentation, CoPP silence metadata, and destination loss.
func ExecuteTCPTraceroute(ctx context.Context, targetIP net.IP, maxHops, cycles int, timeout time.Duration) *MTRResult {
	if ctx == nil || targetIP == nil || targetIP.To16() == nil {
		return &MTRResult{ProbeMode: "tcp_traceroute_fallback", DestLossPct: 100}
	}
	res := executeTCPWaveMTR(ctx, targetIP, maxHops, cycles, timeout)
	finalizeMTRMetadata(res, targetIP)
	res.ResolvedIP = targetIP.String()
	res.MaxHops = clampMTRParam(maxHops, 15, 1, 30)
	if res.Cycles == 0 {
		res.Cycles = clampMTRParam(cycles, 4, 1, 10)
	}
	res.Timestamp = time.Now().UTC().Format(time.RFC3339)
	return res
}

func normalizeMTRParams(params MTRParams) (int, int, time.Duration) {
	maxHops := clampMTRParam(params.MaxHops, 15, 1, 30)
	cycles := clampMTRParam(params.Cycles, 4, 1, 10)
	timeoutMS := clampMTRParam(params.TimeoutMS, 900, 100, 5000)
	return maxHops, cycles, time.Duration(timeoutMS) * time.Millisecond
}

func clampMTRParam(val, fallback, minVal, maxVal int) int {
	switch {
	case val == 0:
		return fallback
	case val < minVal:
		return minVal
	case val > maxVal:
		return maxVal
	default:
		return val
	}
}

func openICMPTransport(targetIP net.IP) (*icmpTransport, bool) {
	isIPv4 := targetIP.To4() != nil
	network, listenAddr, protoNum := "ip4:icmp", "0.0.0.0", mtrICMPProtoV4
	var echoType icmp.Type = ipv4.ICMPTypeEcho
	if !isIPv4 {
		network, listenAddr, protoNum = "ip6:ipv6-icmp", "::", mtrICMPProtoV6
		echoType = ipv6.ICMPTypeEchoRequest
	}

	conn, err := icmp.ListenPacket(network, listenAddr)
	if err != nil {
		return nil, false
	}

	tr := &icmpTransport{conn: conn, isIPv4: isIPv4, protoNum: protoNum, echoType: echoType}
	if isIPv4 {
		tr.p4 = conn.IPv4PacketConn()
	} else {
		tr.p6 = conn.IPv6PacketConn()
	}
	if (isIPv4 && tr.p4 == nil) || (!isIPv4 && tr.p6 == nil) {
		_ = conn.Close()
		return nil, false
	}
	return tr, true
}

func (t *icmpTransport) setHopLimit(ttl int) error {
	if t.isIPv4 {
		if err := t.p4.SetTTL(ttl); err != nil {
			return fmt.Errorf("set TTL %d failed: %w", ttl, err)
		}
		return nil
	}
	if err := t.p6.SetHopLimit(ttl); err != nil {
		return fmt.Errorf("set hop limit %d failed: %w", ttl, err)
	}
	return nil
}

func selectWinningMTRResult(icmpRes *MTRResult, hasICMP bool, tcpRes *MTRResult) *MTRResult {
	if !hasICMP || icmpRes == nil {
		if tcpRes != nil {
			return tcpRes
		}
		return &MTRResult{ProbeMode: "tcp_traceroute_fallback"}
	}
	if tcpRes != nil && tcpRes.Reached {
		return tcpRes
	}
	icmpCount := countRespondingHops(icmpRes.Hops)
	var tcpCount int
	if tcpRes != nil {
		tcpCount = countRespondingHops(tcpRes.Hops)
	}
	if icmpCount > 0 && icmpCount > tcpCount {
		return icmpRes
	}
	if tcpRes != nil {
		return tcpRes
	}
	return icmpRes
}

func countRespondingHops(hops []MTRHop) int {
	count := 0
	for i := range hops {
		if hops[i].Received > 0 {
			count++
		}
	}
	return count
}

func trimTrailingSilentHops(hops []MTRHop, reached bool, targetStr string) []MTRHop {
	if !reached || len(hops) == 0 {
		return hops
	}
	lastRespIdx := -1
	destIdx := -1
	for i := range hops {
		if hops[i].Received <= 0 {
			continue
		}
		lastRespIdx = i
		if targetStr != "" && hops[i].IP == targetStr && destIdx == -1 {
			destIdx = i
		}
	}
	trimIdx := lastRespIdx
	if destIdx >= 0 {
		trimIdx = destIdx
	}
	if trimIdx >= 0 && trimIdx+1 < len(hops) {
		return hops[:trimIdx+1]
	}
	return hops
}

func finalizeMTRMetadata(res *MTRResult, resolvedIP net.IP) {
	if res == nil {
		return
	}
	var targetStr string
	if resolvedIP != nil {
		targetStr = resolvedIP.String()
	} else {
		targetStr = res.ResolvedIP
	}

	res.Hops = trimTrailingSilentHops(res.Hops, res.Reached, targetStr)

	lastRespIdx := -1
	for i := range res.Hops {
		if res.Hops[i].Received > 0 {
			lastRespIdx = i
		}
	}

	silentCount := 0
	totalHops := len(res.Hops)
	for i := range res.Hops {
		h := &res.Hops[i]
		isSilent := h.Received == 0 && (i < lastRespIdx || (res.Reached && i < totalHops-1))
		h.Silent = isSilent
		if isSilent {
			silentCount++
		}
		h.Segment = assignHopSegment(i, h, targetStr, totalHops, res.Reached)
	}
	res.SilentTransitHops = silentCount

	if !res.Reached {
		res.DestLossPct = 100.0
		return
	}
	if totalHops > 0 {
		res.DestLossPct = res.Hops[totalHops-1].LossPct
		return
	}
	res.DestLossPct = 0.0
}

func assignHopSegment(hopIdx int, h *MTRHop, targetStr string, totalHops int, reached bool) string {
	if (targetStr != "" && h.IP == targetStr) || (reached && hopIdx == totalHops-1) {
		return "Destination"
	}
	if hopIdx == 0 && isGatewayHopIP(h.IP) {
		return "Gateway"
	}
	return "Transit"
}

func isGatewayHopIP(ipStr string) bool {
	if ipStr == "" || ipStr == "*" {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLoopback()
}

func computeMTRHopStats(hopNum, sent int, ip string, rttsMs []float64) MTRHop {
	received := len(rttsMs)
	lossPct := 0.0
	if sent > 0 {
		lossPct = float64(sent-received) / float64(sent) * 100.0
	}
	if received == 0 {
		if ip == "" {
			ip = "*"
		}
		return MTRHop{Hop: hopNum, IP: ip, Sent: sent, LossPct: lossPct}
	}

	bestRTT, worstRTT, sumRTT := rttsMs[0], rttsMs[0], 0.0
	for _, rtt := range rttsMs {
		sumRTT += rtt
		if rtt < bestRTT {
			bestRTT = rtt
		}
		if rtt > worstRTT {
			worstRTT = rtt
		}
	}
	avgRTT := sumRTT / float64(received)
	sumSq := 0.0
	for _, rtt := range rttsMs {
		diff := rtt - avgRTT
		sumSq += diff * diff
	}
	return MTRHop{
		Hop: hopNum, IP: ip, Sent: sent, Received: received, LossPct: lossPct,
		LastMs: rttsMs[received-1], AvgMs: avgRTT, BestMs: bestRTT, WorstMs: worstRTT,
		StDevMs: math.Sqrt(sumSq / float64(received)),
	}
}

func resolveMTRHopHostnames(ctx context.Context, hops []MTRHop) {
	if len(hops) == 0 || ctx.Err() != nil {
		return
	}
	uniqueIPs := make([]string, 0, len(hops))
	seen := make(map[string]int, len(hops))
	for i := range hops {
		ipStr := hops[i].IP
		if ipStr == "" || ipStr == "*" {
			continue
		}
		if _, ok := seen[ipStr]; !ok {
			seen[ipStr] = len(uniqueIPs)
			uniqueIPs = append(uniqueIPs, ipStr)
		}
	}
	if len(uniqueIPs) == 0 {
		return
	}

	resolved := make([]string, len(uniqueIPs))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(ptrConcurrencyLimit)
	for idx, ipStr := range uniqueIPs {
		g.Go(func() error {
			lookupCtx, cancel := context.WithTimeout(gctx, ptrLookupTimeout)
			defer cancel()
			if names, err := net.DefaultResolver.LookupAddr(lookupCtx, ipStr); err == nil && len(names) > 0 {
				resolved[idx] = strings.TrimSuffix(names[0], ".")
			}
			return nil
		})
	}
	_ = g.Wait()

	for i := range hops {
		if idx, ok := seen[hops[i].IP]; ok {
			hops[i].Hostname = resolved[idx]
		}
	}
}

func peerIPString(peer net.Addr) string {
	if peer == nil {
		return ""
	}
	if addr, ok := peer.(*net.IPAddr); ok {
		return addr.IP.String()
	}
	if host, _, err := net.SplitHostPort(peer.String()); err == nil {
		return host
	}
	return peer.String()
}
