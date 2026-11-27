package port_scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/response"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/utils"
	"github.com/mark3labs/mcp-go/mcp"
)

const (
	maxPorts         = 1024
	maxConcurrency   = 20
	defaultTimeoutMS = 1000
	minTimeoutMS     = 50
	maxTimeoutMS     = 10000
)

// PortScanParams defines the input parameters for a TCP port scan.
type PortScanParams struct {
	Target    string `json:"target"`
	Ports     string `json:"ports"` // Preset name ("common", "homelab", "web", "iot"), comma-separated, or dash range
	TimeoutMS *int   `json:"timeout_ms,omitempty"`
}

// PortResult describes the probe state and latency for a single TCP port.
type PortResult struct {
	Port    int     `json:"port"`
	State   string  `json:"state"` // "open", "closed", "filtered"
	RTTMs   float64 `json:"rtt_ms,omitempty"`
	Service string  `json:"service,omitempty"`
}

// PortScanResponse contains the aggregated results of a TCP port scan.
type PortScanResponse struct {
	Target    string       `json:"target"`
	IP        string       `json:"ip,omitempty"`
	Ports     []PortResult `json:"ports"`
	OpenCount int          `json:"open_count"`
	Timestamp string       `json:"timestamp"`
}

var portPresets = map[string][]int{
	"common":  {21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443},
	"homelab": {22, 53, 80, 443, 1883, 3000, 3306, 5000, 5001, 5432, 6379, 8000, 8080, 8123, 8443, 8883, 9000, 9090, 9443},
	"web":     {80, 443, 3000, 8000, 8080, 8443, 9000},
	"iot":     {22, 23, 53, 80, 443, 554, 1883, 5000, 5353, 8000, 8080, 8123, 8883, 49152},
}

var commonServices = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	111:   "RPCbind",
	123:   "NTP",
	135:   "MSRPC",
	139:   "NetBIOS",
	143:   "IMAP",
	161:   "SNMP",
	443:   "HTTPS",
	445:   "SMB",
	554:   "RTSP",
	993:   "IMAPS",
	995:   "POP3S",
	1723:  "PPTP",
	1883:  "MQTT",
	3000:  "Gitea / Grafana",
	3306:  "MySQL",
	3389:  "RDP",
	5000:  "Docker Registry / Synology DSM HTTP",
	5001:  "Synology DSM HTTPS",
	5353:  "mDNS",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	8000:  "MCP Server / Supergateway",
	8080:  "HTTP Alt / n8n / SearXNG",
	8123:  "Home Assistant",
	8443:  "HTTPS Alt",
	8883:  "MQTT TLS",
	9000:  "Portainer HTTP",
	9090:  "Prometheus / Web Console",
	9443:  "Portainer HTTPS",
	49152: "UPnP / Dynamic",
}

func parsePorts(input string) ([]int, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		trimmed = "common"
	}

	var ports []int
	seen := make(map[int]bool)

	addPort := func(port int) error {
		if seen[port] {
			return nil
		}
		if len(ports) >= maxPorts {
			return fmt.Errorf("port count exceeds maximum of %d", maxPorts)
		}
		seen[port] = true
		ports = append(ports, port)
		return nil
	}

	for _, rawToken := range strings.Split(trimmed, ",") {
		token := strings.TrimSpace(rawToken)
		if token == "" {
			continue
		}

		if presetPorts, ok := portPresets[strings.ToLower(token)]; ok {
			for _, p := range presetPorts {
				if err := addPort(p); err != nil {
					return nil, err
				}
			}
			continue
		}

		if strings.Contains(token, "-") {
			if err := parsePortRange(token, addPort); err != nil {
				return nil, err
			}
			continue
		}

		portNum, err := strconv.Atoi(token)
		if err != nil || portNum < 1 || portNum > 65535 {
			return nil, fmt.Errorf("invalid port number: %s", token)
		}
		if err := addPort(portNum); err != nil {
			return nil, err
		}
	}

	if len(ports) == 0 {
		return nil, errors.New("no valid ports provided")
	}

	return ports, nil
}

func parsePortRange(token string, addPort func(int) error) error {
	rangeParts := strings.Split(token, "-")
	if len(rangeParts) != 2 {
		return fmt.Errorf("invalid port range: %s", token)
	}

	start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
	end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
	if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
		return fmt.Errorf("invalid port range: %s", token)
	}

	if end-start+1 > maxPorts {
		return fmt.Errorf("port range %s exceeds maximum of %d ports", token, maxPorts)
	}

	for p := start; p <= end; p++ {
		if err := addPort(p); err != nil {
			return err
		}
	}
	return nil
}

// HandlePortScan executes a concurrent TCP port probe on the target.
//
//nolint:gocritic // Exported handler mirrors mcp-go ToolHandlerFunc value parameter.
func HandlePortScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var params PortScanParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	res, err := Execute(ctx, params, nil)
	if err != nil {
		return nil, err
	}

	toolRes, err := response.JSON(res)
	if err != nil {
		return nil, fmt.Errorf("encode port scan response: %w", err)
	}
	return toolRes, nil
}

// Execute validates inputs, resolves the target IP once, and runs bounded concurrent TCP probes.
func Execute(ctx context.Context, params PortScanParams, guard *security.TargetGuard) (*PortScanResponse, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}

	portsToScan, err := parsePorts(params.Ports)
	if err != nil {
		return nil, err
	}

	timeout, err := validateTimeout(params.TimeoutMS)
	if err != nil {
		return nil, err
	}

	target, resolvedIP, err := validateAndResolveTarget(ctx, params.Target, guard)
	if err != nil {
		return nil, err
	}

	results := make([]PortResult, len(portsToScan))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxConcurrency)
	var openCount atomic.Int64
	dialer := &net.Dialer{Timeout: timeout}

	for idx, port := range portsToScan {
		wg.Add(1)
		go func(i, p int) {
			defer wg.Done()

			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-semaphore }()

			results[i] = probePort(ctx, dialer, resolvedIP, p)
			if results[i].State == "open" {
				openCount.Add(1)
			}
		}(idx, port)
	}

	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("port scan canceled: %w", err)
	}

	return &PortScanResponse{
		Target:    target,
		IP:        resolvedIP,
		Ports:     results,
		OpenCount: int(openCount.Load()),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func validateTimeout(timeoutMS *int) (time.Duration, error) {
	if timeoutMS == nil {
		return defaultTimeoutMS * time.Millisecond, nil
	}
	if *timeoutMS < minTimeoutMS || *timeoutMS > maxTimeoutMS {
		return 0, fmt.Errorf("timeout_ms must be between %d and %d, got %d", minTimeoutMS, maxTimeoutMS, *timeoutMS)
	}
	return time.Duration(*timeoutMS) * time.Millisecond, nil
}

func validateAndResolveTarget(ctx context.Context, rawTarget string, guard *security.TargetGuard) (string, string, error) {
	trimmed := strings.TrimSpace(rawTarget)
	if strings.HasPrefix(trimmed, "-") {
		return "", "", fmt.Errorf("%w: target %q must not start with '-'", security.ErrTargetInvalid, trimmed)
	}

	target, err := security.SanitizeTarget(trimmed)
	if err != nil {
		return "", "", fmt.Errorf("sanitize target: %w", err)
	}

	if guard != nil {
		ips, valErr := guard.ValidateHostOrIP(ctx, target)
		if valErr != nil {
			return "", "", fmt.Errorf("validate target: %w", valErr)
		}
		if len(ips) == 0 {
			return "", "", fmt.Errorf("%w: no IP addresses resolved for %q", security.ErrTargetInvalid, target)
		}
		return target, ips[0].String(), nil
	}

	if addr, parseErr := netip.ParseAddr(target); parseErr == nil {
		return target, addr.Unmap().String(), nil
	}

	addrs, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, target)
	if lookupErr != nil {
		return "", "", fmt.Errorf("failed to resolve target %q: %w", target, lookupErr)
	}
	if len(addrs) == 0 {
		return "", "", fmt.Errorf("no IP addresses resolved for target %q", target)
	}

	return target, addrs[0].IP.String(), nil
}

func probePort(ctx context.Context, dialer *net.Dialer, resolvedIP string, port int) PortResult {
	addr := net.JoinHostPort(resolvedIP, strconv.Itoa(port))
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	duration := float64(time.Since(start).Microseconds()) / 1000.0

	state := "closed"
	if err == nil {
		_ = conn.Close()
		state = "open"
	} else {
		var netErr net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
			state = "filtered"
		}
	}

	return PortResult{
		Port:    port,
		State:   state,
		RTTMs:   duration,
		Service: commonServices[port],
	}
}
