package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
)

// MTUProbeParams defines configuration for path MTU discovery probes.
type MTUProbeParams struct {
	Target   string `json:"target"`
	MinMTU   int    `json:"min_mtu,omitempty"`
	MaxMTU   int    `json:"max_mtu,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// MTUStep records the outcome of probing a single wire MTU candidate.
type MTUStep struct {
	PayloadSize int     `json:"payload_size"`
	WireMTU     int     `json:"wire_mtu"`
	Success     bool    `json:"success"`
	Error       string  `json:"error,omitempty"`
	RTTMs       float64 `json:"rtt_ms"`
}

// MTUProbeResult summarizes discovered path MTU, WireGuard recommendation, and probe steps.
type MTUProbeResult struct {
	Target            string    `json:"target"`
	ResolvedIP        string    `json:"resolved_ip"`
	ProbeMode         string    `json:"probe_mode"`
	DiscoveredMTU     int       `json:"discovered_mtu"`
	WireGuardSafeMTU  int       `json:"wireguard_safe_mtu"`
	Steps             []MTUStep `json:"steps"`
	BlackholeDetected bool      `json:"blackhole_detected"`
	Timestamp         string    `json:"timestamp"`
}

type mtuStepAttempt struct {
	step       MTUStep
	emsgsize   bool
	timedOut   bool
	permDenied bool
	confirmed  bool
}

type mtuProbeFunc func(ctx context.Context, ip net.IP, wireMTU int) mtuStepAttempt

const (
	defaultMinMTU      = 576
	defaultMaxMTU      = 1500
	absMinMTU          = 68
	absMaxMTU          = 9000
	wireGuardOverhead  = 80
	ipv4HeaderLen      = 20
	ipv6HeaderLen      = 40
	l4HeaderLen        = 8
	tcpHeaderLen       = 20
	defaultProbePort   = "33434"
	defaultStepTimeout = 350 * time.Millisecond
)

var errInvalidMTUProtocol = errors.New("protocol must be 'udp' or 'icmp'")

// ExecuteMTUProbe discovers the maximum unfragmented path MTU to a target host.
// It validates targets with TargetGuard, probes key candidate MTUs, and binary searches
// the exact path ceiling using DF probing or an unprivileged fallback.
func ExecuteMTUProbe(ctx context.Context, params MTUProbeParams, guard *security.TargetGuard) (*MTUProbeResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", security.ErrTargetInvalid)
	}

	minMTU, maxMTU, proto, err := normalizeMTUParams(params)
	if err != nil {
		return nil, err
	}

	resolvedIP, err := validateProbeTarget(ctx, params.Target, guard)
	if err != nil {
		return nil, err
	}

	result, err := probePathMTU(ctx, resolvedIP, minMTU, maxMTU, proto)
	if err != nil {
		return nil, err
	}

	result.Target = strings.TrimSpace(params.Target)
	result.ResolvedIP = resolvedIP.String()
	result.WireGuardSafeMTU = computeWireGuardSafeMTU(result.DiscoveredMTU)
	result.Timestamp = time.Now().UTC().Format(time.RFC3339)
	return result, nil
}

func validateProbeTarget(ctx context.Context, target string, guard *security.TargetGuard) (net.IP, error) {
	if guard == nil {
		if _, err := security.SanitizeTarget(target); err != nil {
			return nil, fmt.Errorf("target sanitization failed: %w", err)
		}
	}

	ips, err := guard.ValidateHostOrIP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("target validation failed: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no IP addresses resolved", security.ErrTargetInvalid)
	}

	return selectPreferredIP(ips), nil
}

func selectPreferredIP(ips []net.IP) net.IP {
	for _, candidate := range ips {
		if candidate.To4() != nil {
			return candidate
		}
	}
	return ips[0]
}

func normalizeMTUParams(params MTUProbeParams) (int, int, string, error) {
	proto := strings.ToLower(strings.TrimSpace(params.Protocol))
	if proto == "" {
		proto = "udp"
	}
	if proto != "udp" && proto != "icmp" {
		return 0, 0, "", fmt.Errorf("%w: got %q", errInvalidMTUProtocol, params.Protocol)
	}

	maxMTU := params.MaxMTU
	if maxMTU <= 0 {
		maxMTU = defaultMaxMTU
	}
	if maxMTU < absMinMTU {
		maxMTU = absMinMTU
	}
	if maxMTU > absMaxMTU {
		maxMTU = absMaxMTU
	}

	minMTU := params.MinMTU
	if minMTU <= 0 {
		minMTU = defaultMinMTU
		if maxMTU < minMTU {
			minMTU = maxMTU
		}
	}
	if minMTU < absMinMTU {
		minMTU = absMinMTU
	}
	if minMTU > absMaxMTU {
		minMTU = absMaxMTU
	}
	if minMTU > maxMTU {
		return 0, 0, "", fmt.Errorf("min_mtu (%d) cannot exceed max_mtu (%d)", minMTU, maxMTU)
	}

	return minMTU, maxMTU, proto, nil
}

func buildQuickMTUCandidates(minMTU, maxMTU int) []int {
	raw := []int{maxMTU, 1500, 1492, 1420, 1280, minMTU}
	candidates := make([]int, 0, len(raw))
	seen := make(map[int]struct{}, len(raw))

	for _, mtu := range raw {
		if mtu < minMTU || mtu > maxMTU {
			continue
		}
		if _, exists := seen[mtu]; exists {
			continue
		}
		seen[mtu] = struct{}{}
		candidates = append(candidates, mtu)
	}
	return candidates
}

func headerSizeForIP(ip net.IP) int {
	if ip != nil && ip.To4() == nil {
		return ipv6HeaderLen + l4HeaderLen
	}
	return ipv4HeaderLen + l4HeaderLen
}

func maxPayloadForMTU(wireMTU, hdrBytes int) int {
	payload := wireMTU - hdrBytes
	if payload < 0 {
		return 0
	}
	return payload
}

func computeWireGuardSafeMTU(discoveredMTU int) int {
	if discoveredMTU <= wireGuardOverhead {
		return 0
	}
	return discoveredMTU - wireGuardOverhead
}

func discoverMTUWithProber(
	ctx context.Context,
	ip net.IP,
	minMTU, maxMTU int,
	probeFn mtuProbeFunc,
) (int, []MTUStep, bool, bool) {
	hdrBytes := headerSizeForIP(ip)
	candidates := buildQuickMTUCandidates(minMTU, maxMTU)
	steps := make([]MTUStep, 0, len(candidates)+12)

	bestPass := 0
	lowestFail := maxMTU + 1
	hasSilentDrop := false
	anyConfirmed := false
	permDenied := false

	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break
		}
		attempt := probeFn(ctx, ip, candidate)
		attempt.step.WireMTU = candidate
		attempt.step.PayloadSize = maxPayloadForMTU(candidate, hdrBytes)
		steps = append(steps, attempt.step)

		if attempt.permDenied {
			permDenied = true
			break
		}
		if attempt.confirmed {
			anyConfirmed = true
		}
		if attempt.step.Success {
			bestPass = candidate
			break
		}
		lowestFail = candidate
		if attempt.timedOut && !attempt.emsgsize {
			hasSilentDrop = true
		}
	}

	if permDenied {
		return 0, steps, false, true
	}
	if bestPass == 0 {
		return 0, steps, false, !anyConfirmed && hasSilentDrop
	}

	lo := bestPass + 1
	hi := lowestFail - 1
	for lo <= hi {
		if ctx.Err() != nil {
			break
		}
		mid := lo + (hi-lo)/2
		attempt := probeFn(ctx, ip, mid)
		attempt.step.WireMTU = mid
		attempt.step.PayloadSize = maxPayloadForMTU(mid, hdrBytes)
		steps = append(steps, attempt.step)

		if attempt.step.Success {
			bestPass = mid
			lo = mid + 1
			continue
		}
		if attempt.timedOut && !attempt.emsgsize {
			hasSilentDrop = true
		}
		hi = mid - 1
	}

	blackhole := bestPass > 0 && hasSilentDrop
	return bestPass, steps, blackhole, false
}

func discoverOutboundInterfaceMTU(ctx context.Context, ip net.IP) int {
	dialCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()

	network := "udp4"
	if ip != nil && ip.To4() == nil {
		network = "udp6"
	}

	conn, err := (&net.Dialer{}).DialContext(dialCtx, network, net.JoinHostPort(ip.String(), "80"))
	if err != nil {
		return 0
	}
	defer func() { _ = conn.Close() }()

	localUDP, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localUDP.IP == nil {
		return 0
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}

	for i := range ifaces {
		addrs, addrErr := ifaces[i].Addrs()
		if addrErr != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, isNet := addr.(*net.IPNet)
			if isNet && ipNet.IP.Equal(localUDP.IP) {
				return ifaces[i].MTU
			}
		}
	}
	return 0
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isConnRefusedErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") || strings.Contains(msg, "actively refused")
}
