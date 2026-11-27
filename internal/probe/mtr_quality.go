package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"os"
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
	Target     string   `json:"target"`
	ResolvedIP string   `json:"resolved_ip"`
	ProbeMode  string   `json:"probe_mode"`
	Cycles     int      `json:"cycles"`
	MaxHops    int      `json:"max_hops"`
	Reached    bool     `json:"reached"`
	Hops       []MTRHop `json:"hops"`
	Timestamp  string   `json:"timestamp"`
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
// loss and latency jitter, falling back gracefully to TCP connect probing if unprivileged.
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
	if !ok {
		result = executeTCPTracerouteFallback(ctx, resolvedIP, cycles, timeout)
	}

	resolveMTRHopHostnames(ctx, result.Hops)

	result.Target = strings.TrimSpace(params.Target)
	result.ResolvedIP = resolvedIP.String()
	result.Cycles = cycles
	result.MaxHops = maxHops
	result.Timestamp = time.Now().UTC().Format(time.RFC3339)
	return result, nil
}

func normalizeMTRParams(params MTRParams) (int, int, time.Duration) {
	maxHops := clampMTRParam(params.MaxHops, 15, 1, 30)
	cycles := clampMTRParam(params.Cycles, 5, 1, 10)
	timeoutMS := clampMTRParam(params.TimeoutMS, 1500, 100, 5000)
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

func executeICMPMTR(ctx context.Context, targetIP net.IP, maxHops, cycles int, timeout time.Duration) (*MTRResult, bool) {
	tr, ok := openICMPTransport(targetIP)
	if !ok {
		return nil, false
	}
	defer func() { _ = tr.conn.Close() }()

	if err := tr.setHopLimit(1); err != nil {
		return nil, false
	}

	accs := make([]*hopAccumulator, maxHops)
	for i := range accs {
		accs[i] = &hopAccumulator{rttsMs: make([]float64, 0, cycles)}
	}

	pid := os.Getpid()
	if pid < 0 {
		pid = 1
	}
	probeID := pid & 0xffff
	activeMaxHops := maxHops
	reached := false
	buf := make([]byte, 1500)

	for cycle := range cycles {
		for hop := 1; hop <= activeMaxHops && ctx.Err() == nil; hop++ {
			seq := cycle*maxHops + hop
			acc := accs[hop-1]
			acc.sent++

			responderIP, rttMs, reachedDest, gotReply := probeICMPHop(ctx, tr, targetIP, hop, probeID, seq, timeout, buf)
			if !gotReply {
				continue
			}
			if acc.ip == "" {
				acc.ip = responderIP
			}
			acc.rttsMs = append(acc.rttsMs, rttMs)
			if reachedDest {
				reached = true
				if hop < activeMaxHops {
					activeMaxHops = hop
				}
				break
			}
		}
		if ctx.Err() != nil {
			break
		}
	}

	hops := make([]MTRHop, 0, activeMaxHops)
	for i := range activeMaxHops {
		hops = append(hops, computeMTRHopStats(i+1, accs[i].sent, accs[i].ip, accs[i].rttsMs))
	}
	return &MTRResult{ProbeMode: "icmp", Reached: reached, Hops: hops}, true
}

func probeICMPHop(
	ctx context.Context,
	tr *icmpTransport,
	targetIP net.IP,
	hop, probeID, seq int,
	timeout time.Duration,
	buf []byte,
) (string, float64, bool, bool) {
	if err := tr.setHopLimit(hop); err != nil {
		return "", 0, false, false
	}

	msg := icmp.Message{
		Type: tr.echoType,
		Body: &icmp.Echo{ID: probeID, Seq: seq, Data: []byte("mcp-adv-netutils-mtr")},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return "", 0, false, false
	}

	start := time.Now()
	if _, err := tr.conn.WriteTo(msgBytes, &net.IPAddr{IP: targetIP}); err != nil {
		return "", 0, false, false
	}

	deadline := start.Add(timeout)
	if ctxDeadline, hasDeadline := ctx.Deadline(); hasDeadline && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = tr.conn.SetReadDeadline(deadline)

	for ctx.Err() == nil {
		n, peer, readErr := tr.conn.ReadFrom(buf)
		if readErr != nil {
			return "", 0, false, false
		}
		rttMs := float64(time.Since(start)) / float64(time.Millisecond)

		rm, parseErr := icmp.ParseMessage(tr.protoNum, buf[:n])
		if parseErr != nil {
			continue
		}

		peerIP := peerIPString(peer)
		if matched, reachedDest := matchICMPMTRReply(rm, tr.isIPv4, probeID, seq, peerIP, targetIP.String()); matched {
			return peerIP, rttMs, reachedDest, true
		}
	}
	return "", 0, false, false
}

func matchICMPMTRReply(rm *icmp.Message, isIPv4 bool, probeID, seq int, peerIP, targetIP string) (bool, bool) {
	var echoReplyType icmp.Type = ipv4.ICMPTypeEchoReply
	var timeExceededType icmp.Type = ipv4.ICMPTypeTimeExceeded
	var dstUnreachType icmp.Type = ipv4.ICMPTypeDestinationUnreachable
	if !isIPv4 {
		echoReplyType = ipv6.ICMPTypeEchoReply
		timeExceededType = ipv6.ICMPTypeTimeExceeded
		dstUnreachType = ipv6.ICMPTypeDestinationUnreachable
	}

	switch rm.Type {
	case echoReplyType:
		echo, ok := rm.Body.(*icmp.Echo)
		return ok && echo.ID == probeID && echo.Seq == seq, true
	case timeExceededType:
		te, ok := rm.Body.(*icmp.TimeExceeded)
		if !ok {
			return false, false
		}
		id, embeddedSeq, valid := extractEmbeddedEchoIDSeq(te.Data, isIPv4)
		return valid && id == probeID && embeddedSeq == seq, false
	case dstUnreachType:
		du, ok := rm.Body.(*icmp.DstUnreach)
		if !ok {
			return false, false
		}
		id, embeddedSeq, valid := extractEmbeddedEchoIDSeq(du.Data, isIPv4)
		return valid && id == probeID && embeddedSeq == seq, peerIP == targetIP
	default:
		return false, false
	}
}

func extractEmbeddedEchoIDSeq(data []byte, isIPv4 bool) (int, int, bool) {
	if isIPv4 {
		if len(data) < ipv4HeaderLen {
			return 0, 0, false
		}
		ihl := int(data[0]&0x0f) * 4
		if ihl < ipv4HeaderLen || len(data) < ihl+l4HeaderLen || data[9] != mtrICMPProtoV4 {
			return 0, 0, false
		}
		return int(binary.BigEndian.Uint16(data[ihl+4 : ihl+6])), int(binary.BigEndian.Uint16(data[ihl+6 : ihl+8])), true
	}

	if len(data) < ipv6HeaderLen+l4HeaderLen || data[6] != mtrICMPProtoV6 {
		return 0, 0, false
	}
	return int(binary.BigEndian.Uint16(data[ipv6HeaderLen+4 : ipv6HeaderLen+6])),
		int(binary.BigEndian.Uint16(data[ipv6HeaderLen+6 : ipv6HeaderLen+8])), true
}

func executeTCPTracerouteFallback(ctx context.Context, targetIP net.IP, cycles int, timeout time.Duration) *MTRResult {
	ports := []string{"443", "80", "22", "53"}
	rttsMs := make([]float64, 0, cycles)
	sent := 0
	preferredPort := ""
	reached := false

	for range cycles {
		if ctx.Err() != nil {
			break
		}
		sent++

		rttMs, usedPort, ok := probeTCPFallbackCycle(ctx, targetIP, ports, preferredPort, timeout)
		if ok {
			reached = true
			if preferredPort == "" {
				preferredPort = usedPort
			}
			rttsMs = append(rttsMs, rttMs)
		}
	}

	hop := computeMTRHopStats(1, sent, targetIP.String(), rttsMs)
	if !reached {
		hop.IP = "*"
	}

	return &MTRResult{
		ProbeMode: "tcp_traceroute_fallback",
		Reached:   reached,
		Hops:      []MTRHop{hop},
	}
}

func probeTCPFallbackCycle(ctx context.Context, targetIP net.IP, ports []string, preferredPort string, timeout time.Duration) (float64, string, bool) {
	candidates := ports
	if preferredPort != "" {
		candidates = []string{preferredPort}
	}

	perAttempt := timeout / time.Duration(len(candidates))
	if perAttempt < 25*time.Millisecond {
		perAttempt = 25 * time.Millisecond
	}

	var refusedRTT float64
	var refusedPort string

	for _, port := range candidates {
		if ctx.Err() != nil {
			break
		}
		dialCtx, cancel := context.WithTimeout(ctx, perAttempt)
		start := time.Now()
		conn, err := (&net.Dialer{Timeout: perAttempt}).DialContext(dialCtx, "tcp", net.JoinHostPort(targetIP.String(), port))
		cancel()
		rttMs := float64(time.Since(start)) / float64(time.Millisecond)

		if err == nil {
			_ = conn.Close()
			return rttMs, port, true
		}
		if isConnRefusedErr(err) && refusedPort == "" {
			refusedPort = port
			refusedRTT = rttMs
		}
	}

	if refusedPort != "" {
		return refusedRTT, refusedPort, true
	}
	return 0, "", false
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
