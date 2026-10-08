package port_scan

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	resp "github.com/patrickdappollonio/mcp-netutils/internal/response"
	"github.com/patrickdappollonio/mcp-netutils/internal/utils"
)

type PortScanParams struct {
	Target    string `json:"target"`
	Ports     string `json:"ports"` // Comma-separated or dash range: e.g. "22,80,443,1883,8123" or "80-85"
	TimeoutMS *int   `json:"timeout_ms,omitempty"`
}

type PortResult struct {
	Port    int     `json:"port"`
	State   string  `json:"state"` // "open", "closed", "filtered"
	RTTMs   float64 `json:"rtt_ms,omitempty"`
	Service string  `json:"service,omitempty"`
}

type PortScanResponse struct {
	Target    string       `json:"target"`
	IP        string       `json:"ip,omitempty"`
	Ports     []PortResult `json:"ports"`
	OpenCount int          `json:"open_count"`
	Timestamp string       `json:"timestamp"`
}

var commonServices = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	123:  "NTP",
	161:  "SNMP",
	443:  "HTTPS",
	1883: "MQTT",
	3000: "Gitea / Grafana",
	5000: "Docker Registry / Synology DSM HTTP",
	5001: "Synology DSM HTTPS",
	8000: "MCP Server / Supergateway",
	8080: "HTTP Alt / n8n / SearXNG",
	8123: "Home Assistant",
	8883: "MQTT TLS",
	9000: "Portainer HTTP",
	9443: "Portainer HTTPS",
}

func parsePorts(input string) ([]int, error) {
	var ports []int
	seen := make(map[int]bool)

	parts := strings.Split(input, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			rangeParts := strings.Split(p, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err1 == nil && err2 == nil && start > 0 && end <= 65535 && start <= end {
					if end-start > 1000 {
						end = start + 1000 // Limit range to 1000 ports
					}
					for i := start; i <= end; i++ {
						if !seen[i] {
							seen[i] = true
							ports = append(ports, i)
						}
					}
					continue
				}
			}
		}

		portNum, err := strconv.Atoi(p)
		if err != nil || portNum < 1 || portNum > 65535 {
			return nil, fmt.Errorf("invalid port number: %s", p)
		}
		if !seen[portNum] {
			seen[portNum] = true
			ports = append(ports, portNum)
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports provided")
	}

	return ports, nil
}

// HandlePortScan executes a concurrent TCP port probe on the target.
func HandlePortScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var params PortScanParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	target := strings.TrimSpace(params.Target)
	if target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	portsToScan, err := parsePorts(params.Ports)
	if err != nil {
		return nil, err
	}

	timeout := 1000 * time.Millisecond
	if params.TimeoutMS != nil && *params.TimeoutMS > 100 && *params.TimeoutMS <= 10000 {
		timeout = time.Duration(*params.TimeoutMS) * time.Millisecond
	}

	resolvedIP := ""
	if ips, err := net.LookupIP(target); err == nil && len(ips) > 0 {
		resolvedIP = ips[0].String()
	}

	results := make([]PortResult, len(portsToScan))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 20) // max 20 concurrent probes

	openCount := 0
	var mu sync.Mutex

	for idx, port := range portsToScan {
		wg.Add(1)
		go func(i, p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			addr := net.JoinHostPort(target, strconv.Itoa(p))
			start := time.Now()
			conn, err := net.DialTimeout("tcp", addr, timeout)
			duration := float64(time.Since(start).Microseconds()) / 1000.0

			state := "closed"
			service := commonServices[p]

			if err == nil {
				_ = conn.Close()
				state = "open"
				mu.Lock()
				openCount++
				mu.Unlock()
			} else if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "i/o timeout") {
				state = "filtered"
			}

			results[i] = PortResult{
				Port:    p,
				State:   state,
				RTTMs:   duration,
				Service: service,
			}
		}(idx, port)
	}

	wg.Wait()

	response := PortScanResponse{
		Target:    target,
		IP:        resolvedIP,
		Ports:     results,
		OpenCount: openCount,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	return resp.JSON(response)
}
