package ping

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	resp "github.com/FrankXLT/mcp-adv-netutils/internal/response"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Config holds ping configuration.
type Config struct {
	Timeout time.Duration
	Count   int
	Guard   *security.TargetGuard
}

// PingParams represents the parameters for ping operations.
type PingParams struct {
	Target string `json:"target"`
	Count  *int   `json:"count"`
}

// PingResult represents the result of a single ping.
type PingResult struct {
	Sequence     int     `json:"sequence"`
	ResponseTime float64 `json:"response_time_ms"`
	TTL          int     `json:"ttl,omitempty"`
	Success      bool    `json:"success"`
	Error        string  `json:"error,omitempty"`
}

// PingResponse represents the complete ping response.
type PingResponse struct {
	Target          string       `json:"target"`
	ResolvedIP      string       `json:"resolved_ip"`
	ProbeMode       string       `json:"probe_mode"`
	PacketsSent     int          `json:"packets_sent"`
	PacketsReceived int          `json:"packets_received"`
	PacketLoss      float64      `json:"packet_loss_percent"`
	Results         []PingResult `json:"results"`
	MinRTT          float64      `json:"min_rtt_ms"`
	MaxRTT          float64      `json:"max_rtt_ms"`
	AvgRTT          float64      `json:"avg_rtt_ms"`
	Timestamp       string       `json:"timestamp"`
}

type rttStats struct {
	totalRTT     time.Duration
	minRTT       time.Duration
	maxRTT       time.Duration
	successCount int
}

const (
	probeModeICMP        = "icmp"
	probeModeTCPFallback = "tcp_fallback"
	defaultPingTimeout   = 5 * time.Second
	defaultPingCount     = 4
	pingInterval         = time.Second
	icmpReadBufferSize   = 1500
	echoPayload          = "mcp-netutils ping"
)

var (
	echoIDOnce    sync.Once
	echoIDBase    uint32
	echoIDCounter atomic.Uint32
)

// HandlePing performs ping operations to test connectivity to a host.
//
//nolint:gocritic // Exported handler mirrors mcp-go ToolHandlerFunc value parameter.
func HandlePing(ctx context.Context, request mcp.CallToolRequest, config *Config) (*mcp.CallToolResult, error) {
	var params PingParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	pingResponse, err := Execute(ctx, params, config)
	if err != nil {
		return nil, fmt.Errorf("ping failed: %w", err)
	}

	toolResult, err := resp.JSON(pingResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ping response: %w", err)
	}
	return toolResult, nil
}

// Execute validates target and configuration, resolves the target IP, and performs the ping operation.
func Execute(ctx context.Context, params PingParams, cfg *Config) (*PingResponse, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ping canceled: %w", err)
	}

	timeout, count := defaultPingTimeout, defaultPingCount
	var guard *security.TargetGuard
	if cfg != nil {
		if cfg.Timeout > 0 {
			timeout = cfg.Timeout
		}
		if cfg.Count > 0 {
			count = cfg.Count
		}
		guard = cfg.Guard
	}
	if params.Count != nil && *params.Count > 0 {
		count = *params.Count
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cleanTarget, parsedIP, err := resolveTarget(ctxWithTimeout, params.Target, guard)
	if err != nil {
		return nil, err
	}

	return performPing(ctxWithTimeout, cleanTarget, parsedIP, count, timeout)
}

func resolveTarget(ctx context.Context, rawTarget string, guard *security.TargetGuard) (string, net.IP, error) {
	cleanTarget := strings.TrimSpace(rawTarget)
	if cleanTarget == "" {
		return "", nil, errors.New("parameter \"target\" is required")
	}

	if guard != nil {
		ips, err := guard.ValidateHostOrIP(ctx, cleanTarget)
		if err != nil {
			return "", nil, fmt.Errorf("target blocked by security policy: %w", err)
		}
		if len(ips) == 0 {
			return "", nil, fmt.Errorf("no IP addresses found for target %s", cleanTarget)
		}
		return cleanTarget, ips[0], nil
	}

	if parsedIP := net.ParseIP(cleanTarget); parsedIP != nil {
		return cleanTarget, parsedIP, nil
	}

	resolvedIPs, err := net.DefaultResolver.LookupHost(ctx, cleanTarget)
	if err != nil {
		return "", nil, fmt.Errorf("failed to resolve target %s: %w", cleanTarget, err)
	}
	if len(resolvedIPs) == 0 {
		return "", nil, fmt.Errorf("no IP addresses found for target %s", cleanTarget)
	}

	parsedIP := net.ParseIP(resolvedIPs[0])
	if parsedIP == nil {
		return "", nil, fmt.Errorf("invalid IP address: %s", resolvedIPs[0])
	}
	return cleanTarget, parsedIP, nil
}

func nextEchoID() uint16 {
	echoIDOnce.Do(func() {
		var buf [2]byte
		if _, err := rand.Read(buf[:]); err == nil {
			echoIDBase = uint32(binary.BigEndian.Uint16(buf[:]))
		}
		if pid := os.Getpid(); pid > 0 {
			echoIDBase ^= uint32(pid & math.MaxUint16)
		}
	})

	val := (echoIDBase + echoIDCounter.Add(1)) & math.MaxUint16
	if val > math.MaxUint16 {
		return 0
	}
	return uint16(val)
}

func effectiveDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return deadline
}

func calculateFinalStats(response *PingResponse, stats *rttStats) {
	response.PacketsSent = len(response.Results)
	response.PacketsReceived = stats.successCount
	if response.PacketsSent > 0 {
		response.PacketLoss = float64(response.PacketsSent-stats.successCount) / float64(response.PacketsSent) * 100
	}
	if stats.successCount > 0 {
		response.MinRTT = float64(stats.minRTT) / float64(time.Millisecond)
		response.MaxRTT = float64(stats.maxRTT) / float64(time.Millisecond)
		response.AvgRTT = float64(stats.totalRTT) / float64(stats.successCount) / float64(time.Millisecond)
	}
}

func runProbeLoop(ctx context.Context, target string, ip net.IP, count int, probeMode string, probe func(seq int) (PingResult, time.Duration, bool)) (*PingResponse, error) {
	response := &PingResponse{
		Target:      target,
		ResolvedIP:  ip.String(),
		ProbeMode:   probeMode,
		PacketsSent: count,
		Results:     make([]PingResult, 0, count),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}
	var stats rttStats

	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		result, rtt, canceled := probe(i + 1)
		if canceled {
			break
		}
		if result.Success {
			stats.totalRTT += rtt
			if stats.successCount == 0 || rtt < stats.minRTT {
				stats.minRTT = rtt
			}
			if stats.successCount == 0 || rtt > stats.maxRTT {
				stats.maxRTT = rtt
			}
			stats.successCount++
		}
		response.Results = append(response.Results, result)
		if !waitBetweenPings(ctx, i, count) {
			break
		}
	}

	if err := ctx.Err(); err != nil && (errors.Is(err, context.Canceled) || len(response.Results) == 0) {
		return nil, fmt.Errorf("ping canceled: %w", err)
	}
	calculateFinalStats(response, &stats)
	return response, nil
}

// waitBetweenPings waits for the appropriate interval between pings while respecting ctx.Done().
func waitBetweenPings(ctx context.Context, i, count int) bool {
	if i >= count-1 {
		return true
	}
	timer := time.NewTimer(pingInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func watchContextDeadline(ctx context.Context, conn *icmp.PacketConn) func() {
	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stopCh:
		}
	}()
	return func() {
		close(stopCh)
		wg.Wait()
	}
}

func matchICMPEchoReply(proto int, packet []byte, expectedID, expectedSeq int) bool {
	msg, err := icmp.ParseMessage(proto, packet)
	if err != nil {
		return false
	}
	if proto == ipv4.ICMPTypeEchoReply.Protocol() {
		if msg.Type != ipv4.ICMPTypeEchoReply {
			return false
		}
	} else if msg.Type != ipv6.ICMPTypeEchoReply {
		return false
	}
	echoBody, ok := msg.Body.(*icmp.Echo)
	return ok && echoBody != nil && echoBody.ID == expectedID && echoBody.Seq == expectedSeq
}

func readICMPPacket(conn *icmp.PacketConn, isIPv4 bool, reply []byte) (int, int, error) {
	if isIPv4 {
		v4Conn := conn.IPv4PacketConn()
		if v4Conn == nil {
			return 0, 0, errors.New("IPv4 packet connection unavailable")
		}
		n, cm, _, err := v4Conn.ReadFrom(reply)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to read IPv4 ICMP packet: %w", err)
		}
		if cm != nil {
			return n, cm.TTL, nil
		}
		return n, 0, nil
	}
	v6Conn := conn.IPv6PacketConn()
	if v6Conn == nil {
		return 0, 0, errors.New("IPv6 packet connection unavailable")
	}
	n, cm, _, err := v6Conn.ReadFrom(reply)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read IPv6 ICMP packet: %w", err)
	}
	if cm != nil {
		return n, cm.HopLimit, nil
	}
	return n, 0, nil
}

func readMatchingICMPReply(ctx context.Context, conn *icmp.PacketConn, isIPv4 bool, echoID, seq int, deadline time.Time) (int, error) {
	if err := conn.SetReadDeadline(deadline); err != nil {
		return 0, fmt.Errorf("failed to set read deadline: %w", err)
	}
	proto := ipv4.ICMPTypeEchoReply.Protocol()
	if !isIPv4 {
		proto = ipv6.ICMPTypeEchoReply.Protocol()
	}
	reply := make([]byte, icmpReadBufferSize)
	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, fmt.Errorf("ping canceled: %w", ctxErr)
		}
		if !time.Now().Before(deadline) {
			return 0, fmt.Errorf("ICMP reply timed out: %w", os.ErrDeadlineExceeded)
		}
		n, ttl, err := readICMPPacket(conn, isIPv4, reply)
		if err != nil {
			return 0, err
		}
		if matchICMPEchoReply(proto, reply[:n], echoID, seq) {
			return ttl, nil
		}
	}
}

func probeICMPOnce(ctx context.Context, conn *icmp.PacketConn, ip net.IP, isIPv4 bool, echoID, seq int, timeout time.Duration) (PingResult, time.Duration, bool) {
	result := PingResult{Sequence: seq}
	var msgType icmp.Type = ipv4.ICMPTypeEcho
	if !isIPv4 {
		msgType = ipv6.ICMPTypeEchoRequest
	}
	messageBytes, err := (&icmp.Message{
		Type: msgType,
		Code: 0,
		Body: &icmp.Echo{ID: echoID, Seq: seq, Data: []byte(echoPayload)},
	}).Marshal(nil)
	if err != nil {
		result.Error = err.Error()
		return result, 0, false
	}

	deadline := effectiveDeadline(ctx, timeout)
	if err := conn.SetWriteDeadline(deadline); err != nil {
		result.Error = fmt.Sprintf("failed to set write deadline: %v", err)
		return result, 0, false
	}

	start := time.Now()
	_, err = conn.WriteTo(messageBytes, &net.IPAddr{IP: ip})
	var ttl int
	if err == nil {
		ttl, err = readMatchingICMPReply(ctx, conn, isIPv4, echoID, seq, deadline)
	}
	duration := time.Since(start)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return result, 0, true
		}
		result.Error = err.Error()
		return result, 0, false
	}

	result.ResponseTime = float64(duration) / float64(time.Millisecond)
	result.TTL = ttl
	result.Success = true
	return result, duration, false
}

// performPing executes the actual ping operation.
func performPing(ctx context.Context, target string, ip net.IP, count int, timeout time.Duration) (*PingResponse, error) {
	isIPv4 := ip.To4() != nil
	network := "ip4:icmp"
	if !isIPv4 {
		network = "ip6:ipv6-icmp"
	}

	conn, err := icmp.ListenPacket(network, "")
	if err != nil {
		return performSimplePing(ctx, target, ip, count, timeout)
	}
	defer func() { _ = conn.Close() }()

	if isIPv4 {
		if v4Conn := conn.IPv4PacketConn(); v4Conn != nil {
			if cmErr := v4Conn.SetControlMessage(ipv4.FlagTTL, true); cmErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to enable IPv4 TTL control message: %v\n", cmErr)
			}
		}
	} else if v6Conn := conn.IPv6PacketConn(); v6Conn != nil {
		if cmErr := v6Conn.SetControlMessage(ipv6.FlagHopLimit, true); cmErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to enable IPv6 HopLimit control message: %v\n", cmErr)
		}
	}

	stopWatch := watchContextDeadline(ctx, conn)
	defer stopWatch()

	echoID := int(nextEchoID())
	return runProbeLoop(ctx, target, ip, count, probeModeICMP, func(seq int) (PingResult, time.Duration, bool) {
		return probeICMPOnce(ctx, conn, ip, isIPv4, echoID, seq, timeout)
	})
}

// performSimplePing performs a simple connectivity test using TCP connection when ICMP is not available.
func performSimplePing(ctx context.Context, target string, ip net.IP, count int, timeout time.Duration) (*PingResponse, error) {
	return performSimplePingPorts(ctx, target, ip, count, timeout, []string{"80", "443", "22", "25", "53"})
}

func performSimplePingPorts(ctx context.Context, target string, ip net.IP, count int, timeout time.Duration, ports []string) (*PingResponse, error) {
	if len(ports) == 0 {
		return nil, errors.New("no TCP fallback ports configured")
	}
	if timeout <= 0 {
		timeout = defaultPingTimeout
	}
	portTimeout := timeout / time.Duration(len(ports))
	if portTimeout <= 0 {
		portTimeout = timeout
	}
	dialer := &net.Dialer{Timeout: portTimeout}

	return runProbeLoop(ctx, target, ip, count, probeModeTCPFallback, func(seq int) (PingResult, time.Duration, bool) {
		return probeTCPPorts(ctx, dialer, ip, seq, ports)
	})
}

func probeTCPPorts(ctx context.Context, dialer *net.Dialer, ip net.IP, seq int, ports []string) (PingResult, time.Duration, bool) {
	result := PingResult{Sequence: seq}
	var lastErr error
	for _, port := range ports {
		if ctxErr := ctx.Err(); ctxErr != nil {
			if lastErr == nil || errors.Is(ctxErr, context.Canceled) {
				return result, 0, true
			}
			break
		}
		start := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		duration := time.Since(start)
		if err == nil {
			_ = conn.Close()
			result.Success = true
			result.ResponseTime = float64(duration) / float64(time.Millisecond)
			return result, duration, false
		}
		lastErr = err
		if errors.Is(ctx.Err(), context.Canceled) {
			return result, 0, true
		}
		if ctx.Err() != nil {
			break
		}
	}
	result.Error = "connection failed to all tested ports"
	if lastErr != nil {
		result.Error = fmt.Sprintf("connection failed to all tested ports: %v", lastErr)
	}
	return result, 0, false
}
