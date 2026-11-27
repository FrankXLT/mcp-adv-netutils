package traceroute

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/response"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"golang.org/x/sync/errgroup"
)

const (
	defaultMaxHops       = 15
	maxAllowedHops       = 30
	defaultTimeoutSec    = 2
	maxAllowedTimeoutSec = 10
	ptrConcurrencyLimit  = 8
	ptrTimeout           = time.Second
)

// TracerouteParams defines the input parameters for a traceroute execution.
type TracerouteParams struct {
	Target  string `json:"target"`
	MaxHops *int   `json:"max_hops,omitempty"`
	Timeout *int   `json:"timeout_seconds,omitempty"`
}

// HopResult represents a single hop discovered during a traceroute.
type HopResult struct {
	Hop      int       `json:"hop"`
	IP       string    `json:"ip"`
	Hostname string    `json:"hostname,omitempty"`
	RTTMs    []float64 `json:"rtt_ms"`
	AvgRTTMs float64   `json:"avg_rtt_ms"`
	TimedOut bool      `json:"timed_out"`
}

// TracerouteResponse contains the complete traceroute output and metadata.
type TracerouteResponse struct {
	Target             string      `json:"target"`
	ResolvedIP         string      `json:"resolved_ip,omitempty"`
	MaxHops            int         `json:"max_hops"`
	Hops               []HopResult `json:"hops"`
	ReachedDestination bool        `json:"reached_destination"`
	Timestamp          string      `json:"timestamp"`
}

type execDeps struct {
	lookPath       func(file string) (string, error)
	commandContext func(ctx context.Context, name string, arg ...string) *exec.Cmd
	lookupIPAddr   func(ctx context.Context, host string) ([]net.IPAddr, error)
	lookupAddr     func(ctx context.Context, addr string) ([]string, error)
}

func defaultDeps() execDeps {
	return execDeps{
		lookPath:       exec.LookPath,
		commandContext: exec.CommandContext,
		lookupIPAddr:   net.DefaultResolver.LookupIPAddr,
		lookupAddr:     net.DefaultResolver.LookupAddr,
	}
}

var (
	hopLineRegex = regexp.MustCompile(`^\s*(\d+)\s+(.+)$`)
	msRegex      = regexp.MustCompile(`(\d+(?:\.\d+)?)\s*ms`)
)

// HandleTraceroute executes a multi-hop route trace to the target.
//
//nolint:gocritic // Exported handler mirrors mcp-go ToolHandlerFunc value parameter.
func HandleTraceroute(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var params TracerouteParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	res, err := Execute(ctx, params, nil)
	if err != nil {
		return nil, err
	}

	out, err := response.JSON(res)
	if err != nil {
		return nil, fmt.Errorf("failed to encode traceroute result: %w", err)
	}

	return out, nil
}

// Execute validates the target, runs traceroute, parses hops, and resolves PTR records concurrently.
func Execute(ctx context.Context, params TracerouteParams, guard *security.TargetGuard) (*TracerouteResponse, error) {
	return executeWithDeps(ctx, params, guard, defaultDeps())
}

func executeWithDeps(ctx context.Context, params TracerouteParams, guard *security.TargetGuard, deps execDeps) (*TracerouteResponse, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}

	target, resolvedIP, err := validateAndResolveTarget(ctx, params.Target, guard, deps.lookupIPAddr)
	if err != nil {
		return nil, err
	}

	maxHops := defaultMaxHops
	if params.MaxHops != nil && *params.MaxHops > 0 && *params.MaxHops <= maxAllowedHops {
		maxHops = *params.MaxHops
	}

	timeoutSec := defaultTimeoutSec
	if params.Timeout != nil && *params.Timeout > 0 && *params.Timeout <= maxAllowedTimeoutSec {
		timeoutSec = *params.Timeout
	}

	cmdPath, err := deps.lookPath("traceroute")
	if err != nil {
		return nil, fmt.Errorf("traceroute utility not found in system PATH: %w", err)
	}

	cmdCtx, cancel := context.WithTimeout(ctx, time.Duration(maxHops*timeoutSec+5)*time.Second)
	defer cancel()

	targetArg := target
	if resolvedIP != "" {
		targetArg = resolvedIP
	}

	cmd := deps.commandContext(
		cmdCtx,
		cmdPath,
		"-n",
		"-w", strconv.Itoa(timeoutSec),
		"-m", strconv.Itoa(maxHops),
		"--",
		targetArg,
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to execute traceroute: %w", err)
	}

	hops, reached, scanErr := parseTracerouteOutput(stdout, target, resolvedIP)
	waitErr := cmd.Wait()

	if scanErr != nil {
		return nil, fmt.Errorf("failed reading traceroute output: %w", scanErr)
	}
	if err := evaluateWaitError(ctx, cmdCtx, waitErr, len(hops)); err != nil {
		return nil, err
	}

	if err := resolveHopHostnames(ctx, hops, deps.lookupAddr); err != nil {
		return nil, err
	}

	return &TracerouteResponse{
		Target:             target,
		ResolvedIP:         resolvedIP,
		MaxHops:            maxHops,
		Hops:               hops,
		ReachedDestination: reached,
		Timestamp:          time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func validateAndResolveTarget(
	ctx context.Context,
	rawTarget string,
	guard *security.TargetGuard,
	lookupIPAddr func(context.Context, string) ([]net.IPAddr, error),
) (string, string, error) {
	trimmed := strings.TrimSpace(rawTarget)
	if strings.HasPrefix(trimmed, "-") {
		return "", "", fmt.Errorf("%w: target %q must not start with '-'", security.ErrTargetInvalid, trimmed)
	}

	target, err := security.SanitizeTarget(trimmed)
	if err != nil {
		return "", "", fmt.Errorf("target sanitization failed: %w", err)
	}

	if guard != nil {
		ips, valErr := guard.ValidateHostOrIP(ctx, target)
		if valErr != nil {
			return "", "", fmt.Errorf("target validation failed: %w", valErr)
		}
		if len(ips) > 0 {
			return target, ips[0].String(), nil
		}
		return target, "", nil
	}

	if addr, parseErr := netip.ParseAddr(target); parseErr == nil {
		if valErr := (*security.TargetGuard)(nil).ValidateIP(net.IP(addr.Unmap().AsSlice())); valErr != nil {
			return "", "", fmt.Errorf("target validation failed: %w", valErr)
		}
		return target, addr.Unmap().String(), nil
	}

	if isAlternateOrUnvalidatedIPTarget(target) {
		return "", "", fmt.Errorf("%w: unvalidated or alternate-radix IP target %q", security.ErrTargetInvalid, target)
	}

	if ips, lookupErr := lookupIPAddr(ctx, target); lookupErr == nil && len(ips) > 0 {
		for _, ipAddr := range ips {
			if valErr := (*security.TargetGuard)(nil).ValidateIP(ipAddr.IP); valErr != nil {
				return "", "", fmt.Errorf("resolved IP for %q blocked: %w", target, valErr)
			}
		}
		return target, ips[0].IP.String(), nil
	}

	return target, "", nil
}

func isAlternateOrUnvalidatedIPTarget(target string) bool {
	if net.ParseIP(target) != nil || strings.ContainsAny(target, ":[]%") {
		return true
	}

	trimmed := strings.TrimSuffix(target, ".")
	if trimmed == "" {
		return true
	}

	labels := strings.Split(trimmed, ".")
	allNumeric := true
	for _, label := range labels {
		if label == "" || !isValidDNSLabelChars(label) {
			return true
		}
		if !isNumericIPLabel(label) {
			allNumeric = false
		}
	}
	return allNumeric
}

func isValidDNSLabelChars(label string) bool {
	for i := 0; i < len(label); i++ {
		c := label[i]
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		if !isAlpha && !isDigit && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func isNumericIPLabel(label string) bool {
	if label == "" {
		return false
	}
	if strings.HasPrefix(label, "0x") || strings.HasPrefix(label, "0X") {
		if len(label) == 2 {
			return false
		}
		for i := 2; i < len(label); i++ {
			c := label[i]
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(label); i++ {
		if label[i] < '0' || label[i] > '9' {
			return false
		}
	}
	return true
}

func evaluateWaitError(ctx, cmdCtx context.Context, waitErr error, hopCount int) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		if waitErr != nil {
			return fmt.Errorf("traceroute canceled: %w", waitErr)
		}
		return fmt.Errorf("traceroute canceled: %w", ctxErr)
	}
	if waitErr == nil {
		return nil
	}
	if cmdCtx.Err() != nil || hopCount == 0 {
		return fmt.Errorf("traceroute failed: %w", waitErr)
	}
	return nil
}

func parseTracerouteOutput(r io.Reader, target, resolvedIP string) ([]HopResult, bool, error) {
	scanner := bufio.NewScanner(r)
	hops := make([]HopResult, 0)
	reached := false

	for scanner.Scan() {
		line := scanner.Text()
		matches := hopLineRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			hopNum, _ := strconv.Atoi(matches[1])
			hop, lineIPs := parseHopDetails(hopNum, matches[2])
			if matchesTarget(lineIPs, target, resolvedIP) {
				reached = true
			}
			hops = append(hops, hop)
			continue
		}

		// Handle continuation lines from multi-IP hops (indented lines without a hop number).
		if len(hops) > 0 && strings.HasPrefix(line, " ") {
			if contIPs, contRTTs := extractIPsAndRTTs(line); len(contIPs) > 0 || len(contRTTs) > 0 {
				last := &hops[len(hops)-1]
				if (last.TimedOut || last.IP == "*") && len(contIPs) > 0 {
					last.IP = contIPs[0]
					last.TimedOut = false
				}
				if len(contRTTs) > 0 {
					last.RTTMs = append(last.RTTMs, contRTTs...)
					last.AvgRTTMs = averageRTT(last.RTTMs)
				}
				if matchesTarget(contIPs, target, resolvedIP) {
					reached = true
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return hops, reached, fmt.Errorf("scanner error: %w", err)
	}
	return hops, reached, nil
}

func parseHopDetails(hopNum int, rest string) (HopResult, []string) {
	ips, rtts := extractIPsAndRTTs(rest)
	if len(ips) == 0 {
		return HopResult{
			Hop:      hopNum,
			IP:       "*",
			TimedOut: true,
		}, nil
	}

	return HopResult{
		Hop:      hopNum,
		IP:       ips[0],
		RTTMs:    rtts,
		AvgRTTMs: averageRTT(rtts),
		TimedOut: false,
	}, ips
}

func extractIPsAndRTTs(rest string) ([]string, []float64) {
	var ips []string
	seenIP := make(map[string]bool)
	for _, field := range strings.Fields(rest) {
		if addr, err := netip.ParseAddr(field); err == nil {
			ipStr := addr.Unmap().String()
			if !seenIP[ipStr] {
				seenIP[ipStr] = true
				ips = append(ips, ipStr)
			}
		}
	}

	var rtts []float64
	for _, m := range msRegex.FindAllStringSubmatch(rest, -1) {
		if len(m) >= 2 {
			if val, err := strconv.ParseFloat(m[1], 64); err == nil {
				rtts = append(rtts, val)
			}
		}
	}

	return ips, rtts
}

func averageRTT(rtts []float64) float64 {
	if len(rtts) == 0 {
		return 0.0
	}
	var sum float64
	for _, v := range rtts {
		sum += v
	}
	return sum / float64(len(rtts))
}

func matchesTarget(ips []string, target, resolvedIP string) bool {
	for _, ip := range ips {
		if ip == target || (resolvedIP != "" && ip == resolvedIP) {
			return true
		}
	}
	return false
}

func resolveHopHostnames(
	ctx context.Context,
	hops []HopResult,
	lookupAddr func(context.Context, string) ([]string, error),
) error {
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(ptrConcurrencyLimit)

	for i := range hops {
		if hops[i].TimedOut || hops[i].IP == "" || hops[i].IP == "*" {
			continue
		}
		idx := i
		g.Go(func() error {
			ptrCtx, cancel := context.WithTimeout(gCtx, ptrTimeout)
			defer cancel()

			if ptrs, err := lookupAddr(ptrCtx, hops[idx].IP); err == nil && len(ptrs) > 0 {
				hops[idx].Hostname = strings.TrimSuffix(ptrs[0], ".")
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("failed during PTR lookups: %w", err)
	}
	return nil
}
