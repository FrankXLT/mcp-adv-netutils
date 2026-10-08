package traceroute

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	resp "github.com/patrickdappollonio/mcp-netutils/internal/response"
	"github.com/patrickdappollonio/mcp-netutils/internal/utils"
)

type TracerouteParams struct {
	Target  string `json:"target"`
	MaxHops *int   `json:"max_hops,omitempty"`
	Timeout *int   `json:"timeout_seconds,omitempty"`
}

type HopResult struct {
	Hop      int       `json:"hop"`
	IP       string    `json:"ip"`
	Hostname string    `json:"hostname,omitempty"`
	RTTMs    []float64 `json:"rtt_ms"`
	AvgRTTMs float64   `json:"avg_rtt_ms"`
	TimedOut bool      `json:"timed_out"`
}

type TracerouteResponse struct {
	Target             string      `json:"target"`
	ResolvedIP         string      `json:"resolved_ip,omitempty"`
	MaxHops            int         `json:"max_hops"`
	Hops               []HopResult `json:"hops"`
	ReachedDestination bool        `json:"reached_destination"`
	Timestamp          string      `json:"timestamp"`
}

var hopRegex = regexp.MustCompile(`^\s*(\d+)\s+([0-9a-fA-F.:*]+)(.*)$`)
var msRegex = regexp.MustCompile(`([0-9.]+)\s*ms`)

// HandleTraceroute executes a multi-hop route trace to the target.
func HandleTraceroute(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var params TracerouteParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	target := strings.TrimSpace(params.Target)
	if target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	maxHops := 15
	if params.MaxHops != nil && *params.MaxHops > 0 && *params.MaxHops <= 30 {
		maxHops = *params.MaxHops
	}

	timeoutSec := 2
	if params.Timeout != nil && *params.Timeout > 0 && *params.Timeout <= 10 {
		timeoutSec = *params.Timeout
	}

	// Resolve destination IP
	resolvedIP := ""
	if ips, err := net.LookupIP(target); err == nil && len(ips) > 0 {
		resolvedIP = ips[0].String()
	}

	// Check if traceroute binary exists
	cmdPath, err := exec.LookPath("traceroute")
	if err != nil {
		return nil, fmt.Errorf("traceroute utility not found in system PATH: %w", err)
	}

	cmdCtx, cancel := context.WithTimeout(ctx, time.Duration(maxHops*timeoutSec+5)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, cmdPath, "-n", "-w", strconv.Itoa(timeoutSec), "-m", strconv.Itoa(maxHops), target)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to execute traceroute: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	var hops []HopResult
	reached := false

	for scanner.Scan() {
		line := scanner.Text()
		matches := hopRegex.FindStringSubmatch(line)
		if len(matches) < 3 {
			continue
		}

		hopNum, _ := strconv.Atoi(matches[1])
		rawIP := matches[2]
		rest := matches[3]

		if rawIP == "*" {
			hops = append(hops, HopResult{
				Hop:      hopNum,
				IP:       "*",
				TimedOut: true,
			})
			continue
		}

		// Extract latencies
		var rtts []float64
		var sumRTT float64
		msMatches := msRegex.FindAllStringSubmatch(rest, -1)
		for _, m := range msMatches {
			if len(m) >= 2 {
				if val, err := strconv.ParseFloat(m[1], 64); err == nil {
					rtts = append(rtts, val)
					sumRTT += val
				}
			}
		}

		avgRTT := 0.0
		if len(rtts) > 0 {
			avgRTT = sumRTT / float64(len(rtts))
		}

		// Reverse DNS lookup
		hostname := ""
		if ptrs, err := net.LookupAddr(rawIP); err == nil && len(ptrs) > 0 {
			hostname = strings.TrimSuffix(ptrs[0], ".")
		}

		if rawIP == target || (resolvedIP != "" && rawIP == resolvedIP) {
			reached = true
		}

		hops = append(hops, HopResult{
			Hop:      hopNum,
			IP:       rawIP,
			Hostname: hostname,
			RTTMs:    rtts,
			AvgRTTMs: avgRTT,
			TimedOut: false,
		})
	}

	_ = cmd.Wait()

	response := TracerouteResponse{
		Target:             target,
		ResolvedIP:         resolvedIP,
		MaxHops:            maxHops,
		Hops:               hops,
		ReachedDestination: reached,
		Timestamp:          time.Now().UTC().Format(time.RFC3339),
	}

	return resp.JSON(response)
}
