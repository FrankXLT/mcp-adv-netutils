package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	resp "github.com/FrankXLT/mcp-adv-netutils/internal/response"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/utils"
	"github.com/mark3labs/mcp-go/mcp"
)

const defaultTimeout = 5 * time.Second

// Config holds resolver configuration.
type Config struct {
	Timeout time.Duration
	Guard   *security.TargetGuard
}

// ResolverParams represents the parameters for hostname resolution.
type ResolverParams struct {
	Hostname  string `json:"hostname"`
	IPVersion string `json:"ip_version"`
}

// ResolverResponse represents the structured result of a hostname resolution.
type ResolverResponse struct {
	Hostname      string   `json:"hostname"`
	Timestamp     string   `json:"timestamp"`
	IPVersion     string   `json:"ip_version"`
	Failed        bool     `json:"failed"`
	Error         string   `json:"error,omitempty"`
	IPv4Addresses []string `json:"ipv4_addresses,omitempty"`
	IPv6Addresses []string `json:"ipv6_addresses,omitempty"`
}

type ipLookupFunc func(ctx context.Context, hostname, ipVersion string) ([]string, error)

// HandleHostnameResolution resolves a hostname to its IP addresses.
//
//nolint:gocritic // Exported handler mirrors mcp-go ToolHandlerFunc value parameter.
func HandleHostnameResolution(ctx context.Context, request mcp.CallToolRequest, config *Config) (*mcp.CallToolResult, error) {
	var params ResolverParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	result, err := Execute(ctx, params, config)
	if err != nil {
		return nil, err
	}

	// Use the response package to handle JSON encoding and MCP tool result creation
	toolRes, err := resp.JSON(result)
	if err != nil {
		return nil, fmt.Errorf("encode resolver response: %w", err)
	}
	return toolRes, nil
}

// Execute resolves a hostname according to params and cfg and returns a structured response.
func Execute(ctx context.Context, params ResolverParams, cfg *Config) (*ResolverResponse, error) {
	return executeWithLookup(ctx, params, cfg, lookupIPAddresses)
}

func executeWithLookup(ctx context.Context, params ResolverParams, cfg *Config, lookupFn ipLookupFunc) (*ResolverResponse, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}

	if params.Hostname == "" {
		return nil, errors.New("parameter \"hostname\" is required")
	}

	hostname, err := security.SanitizeTarget(params.Hostname)
	if err != nil {
		return nil, fmt.Errorf("invalid hostname: %w", err)
	}

	ipVersion, err := normalizeIPVersion(params.IPVersion)
	if err != nil {
		return nil, err
	}

	var guard *security.TargetGuard
	timeout := defaultTimeout
	if cfg != nil {
		guard = cfg.Guard
		if cfg.Timeout > 0 {
			timeout = cfg.Timeout
		}
	}

	if guard != nil {
		if addr, parseErr := netip.ParseAddr(hostname); parseErr == nil {
			ip := net.IP(addr.Unmap().AsSlice())
			if valErr := guard.ValidateIP(ip); valErr != nil {
				return nil, fmt.Errorf("target %q blocked: %w", hostname, valErr)
			}
		}
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	response := &ResolverResponse{
		Hostname:  hostname,
		Timestamp: time.Now().Format(time.RFC3339),
		IPVersion: ipVersion,
		Failed:    false,
	}

	switch ipVersion {
	case "ipv4", "ipv6":
		if err := resolveSingleVersion(ctxWithTimeout, hostname, ipVersion, guard, lookupFn, response); err != nil {
			return nil, err
		}
	case "both":
		if err := resolveBothVersions(ctxWithTimeout, hostname, guard, lookupFn, response); err != nil {
			return nil, err
		}
	}

	return response, nil
}

func normalizeIPVersion(raw string) (string, error) {
	if raw == "" {
		return "ipv4", nil
	}
	switch raw {
	case "ipv4", "ipv6", "both":
		return raw, nil
	default:
		return "", fmt.Errorf("invalid ip_version %q: must be \"ipv4\", \"ipv6\", or \"both\"", raw)
	}
}

func resolveSingleVersion(
	ctx context.Context,
	hostname, ipVersion string,
	guard *security.TargetGuard,
	lookupFn ipLookupFunc,
	response *ResolverResponse,
) error {
	addresses, err := lookupFn(ctx, hostname, ipVersion)
	if err != nil {
		if isHostNotFoundError(err) {
			response.Error = err.Error()
			response.Failed = true
			return nil
		}
		return fmt.Errorf("failed to resolve %s addresses: %w", ipVersion, err)
	}

	if err := validateResolvedAddresses(guard, hostname, addresses); err != nil {
		return err
	}

	if len(addresses) == 0 {
		response.Error = fmt.Sprintf("no %s addresses found for %s", ipVersion, hostname)
		response.Failed = true
		return nil
	}

	if ipVersion == "ipv6" {
		response.IPv6Addresses = addresses
	} else {
		response.IPv4Addresses = addresses
	}
	return nil
}

func resolveBothVersions(
	ctx context.Context,
	hostname string,
	guard *security.TargetGuard,
	lookupFn ipLookupFunc,
	response *ResolverResponse,
) error {
	ipv4Addresses, ipv4Err := lookupFn(ctx, hostname, "ipv4")
	if ipv4Err != nil && !isHostNotFoundError(ipv4Err) {
		return fmt.Errorf("failed to resolve ipv4 addresses: %w", ipv4Err)
	}
	if ipv4Err == nil {
		if err := validateResolvedAddresses(guard, hostname, ipv4Addresses); err != nil {
			return err
		}
		if len(ipv4Addresses) > 0 {
			response.IPv4Addresses = ipv4Addresses
		}
	}

	ipv6Addresses, ipv6Err := lookupFn(ctx, hostname, "ipv6")
	if ipv6Err != nil && !isHostNotFoundError(ipv6Err) {
		return fmt.Errorf("failed to resolve ipv6 addresses: %w", ipv6Err)
	}
	if ipv6Err == nil {
		if err := validateResolvedAddresses(guard, hostname, ipv6Addresses); err != nil {
			return err
		}
		if len(ipv6Addresses) > 0 {
			response.IPv6Addresses = ipv6Addresses
		}
	}

	if len(response.IPv4Addresses) == 0 && len(response.IPv6Addresses) == 0 {
		response.Failed = true
		response.Error = formatBothNotFoundError(hostname, ipv4Err, ipv6Err)
	}

	return nil
}

func validateResolvedAddresses(guard *security.TargetGuard, hostname string, addrs []string) error {
	if guard == nil {
		return nil
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return fmt.Errorf("invalid resolved IP %q for %q", addr, hostname)
		}
		if err := guard.ValidateIP(ip); err != nil {
			return fmt.Errorf("resolved IP %s for %q blocked: %w", addr, hostname, err)
		}
	}
	return nil
}

func formatBothNotFoundError(hostname string, ipv4Err, ipv6Err error) string {
	var parts []string
	if ipv4Err != nil {
		parts = append(parts, fmt.Sprintf("ipv4: %v", ipv4Err))
	}
	if ipv6Err != nil {
		parts = append(parts, fmt.Sprintf("ipv6: %v", ipv6Err))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("no IPv4 or IPv6 addresses found for %s", hostname)
	}
	return strings.Join(parts, "; ")
}

// isHostNotFoundError checks if the error is a DNS "host not found" type error.
func isHostNotFoundError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

// lookupIPAddresses handles the IP lookup for a specific IP version (IPv4 or IPv6).
func lookupIPAddresses(ctx context.Context, hostname, ipVersion string) ([]string, error) {
	networkType := "ip4"
	if ipVersion == "ipv6" {
		networkType = "ip6"
	}

	addrs, err := net.DefaultResolver.LookupIP(ctx, networkType, hostname)
	if err != nil {
		return nil, fmt.Errorf("lookup IP: %w", err)
	}

	result := make([]string, len(addrs))
	for i, addr := range addrs {
		result[i] = addr.String()
	}

	return result, nil
}
