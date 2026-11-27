package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/response"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/utils"
	"github.com/mark3labs/mcp-go/mcp"
)

// ReverseDNSBatchParams holds the inputs for batch reverse DNS lookups.
type ReverseDNSBatchParams struct {
	IPs       string `json:"ips"` // Comma-separated list of IP addresses
	TimeoutMS *int   `json:"timeout_ms,omitempty"`
}

// ReverseDNSBatchResponse holds the results of batch reverse DNS lookups.
type ReverseDNSBatchResponse struct {
	Results   map[string]*string `json:"results"`
	Count     int                `json:"count"`
	Timestamp string             `json:"timestamp"`
}

const (
	// MaxReverseBatchIPs caps the number of IP addresses accepted in a batch reverse DNS lookup.
	MaxReverseBatchIPs = 256

	minReverseTimeoutMS   = 50
	maxReverseTimeoutMS   = 10000
	maxBatchConcurrency   = 20
	defaultReverseTimeout = 3 * time.Second
)

// HandleReverseDNSBatch concurrently resolves PTR records for multiple IP addresses.
func HandleReverseDNSBatch(ctx context.Context, request mcp.CallToolRequest, config *QueryConfig) (*mcp.CallToolResult, error) { //nolint:gocritic // Exported handler mirrors mcp-go ToolHandlerFunc value parameter.
	var params ReverseDNSBatchParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	result, err := ExecuteReverseBatch(ctx, params, config)
	if err != nil {
		return nil, err
	}

	res, err := response.JSON(result)
	if err != nil {
		return nil, fmt.Errorf("encode DNS response: %w", err)
	}
	return res, nil
}

// ExecuteReverseBatch validates and concurrently resolves PTR records for up to MaxReverseBatchIPs addresses.
func ExecuteReverseBatch(ctx context.Context, params ReverseDNSBatchParams, config *QueryConfig) (*ReverseDNSBatchResponse, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}

	var guard *security.TargetGuard
	if config != nil {
		guard = config.Guard
	}

	ips, err := parseAndValidateBatchIPs(params.IPs, guard)
	if err != nil {
		return nil, err
	}

	timeout := defaultReverseTimeout
	if config != nil && config.Timeout > 0 {
		timeout = config.Timeout
	}
	if params.TimeoutMS != nil {
		if *params.TimeoutMS < minReverseTimeoutMS || *params.TimeoutMS > maxReverseTimeoutMS {
			return nil, fmt.Errorf("timeout_ms must be between %d and %d, got %d", minReverseTimeoutMS, maxReverseTimeoutMS, *params.TimeoutMS)
		}
		timeout = time.Duration(*params.TimeoutMS) * time.Millisecond
	}

	resolver := newReverseResolver(config)
	results := make(map[string]*string, len(ips))
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxBatchConcurrency)

	for _, ipStr := range ips {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			lookupCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			names, lookupErr := resolver.LookupAddr(lookupCtx, targetIP)
			mu.Lock()
			defer mu.Unlock()

			if lookupErr == nil && len(names) > 0 {
				host := strings.TrimSuffix(names[0], ".")
				results[targetIP] = &host
			} else {
				results[targetIP] = nil
			}
		}(ipStr)
	}

	wg.Wait()

	return &ReverseDNSBatchResponse{
		Results:   results,
		Count:     len(results),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func parseAndValidateBatchIPs(raw string, guard *security.TargetGuard) ([]string, error) {
	rawIPs := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ';'
	})
	if len(rawIPs) == 0 {
		return nil, errors.New(`parameter "ips" cannot be empty`)
	}
	if len(rawIPs) > MaxReverseBatchIPs {
		return nil, fmt.Errorf("too many IP addresses: %d exceeds maximum of %d", len(rawIPs), MaxReverseBatchIPs)
	}

	ips := make([]string, 0, len(rawIPs))
	for _, rawIP := range rawIPs {
		ipStr := strings.TrimSpace(rawIP)
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %q", ipStr)
		}
		if guard != nil {
			if err := guard.ValidateIP(ip); err != nil {
				return nil, fmt.Errorf("IP address %q blocked: %w", ipStr, err)
			}
		}
		ips = append(ips, ipStr)
	}

	if len(ips) == 0 {
		return nil, errors.New(`parameter "ips" cannot be empty`)
	}

	return ips, nil
}

func newReverseResolver(config *QueryConfig) *net.Resolver {
	if config == nil || len(config.LocalServers) == 0 {
		return &net.Resolver{}
	}

	target := formatDNSServerAddr(config.LocalServers[0])
	dialer := &net.Dialer{}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(dialCtx, "udp", target)
		},
	}
}

func formatDNSServerAddr(server string) string {
	trimmed := strings.TrimSpace(server)
	if host, port, err := net.SplitHostPort(trimmed); err == nil {
		if port == "" {
			port = "53"
		}
		return net.JoinHostPort(host, port)
	}

	host := strings.TrimPrefix(strings.TrimSuffix(trimmed, "]"), "[")
	return net.JoinHostPort(host, "53")
}

func validateServerHost(ctx context.Context, guard *security.TargetGuard, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if err := guard.ValidateIP(ip); err != nil {
			return fmt.Errorf("DNS server %q rejected: %w", host, err)
		}
		return nil
	}
	if _, err := guard.ValidateHostOrIP(ctx, host); err != nil {
		return fmt.Errorf("DNS server %q rejected: %w", host, err)
	}
	return nil
}
