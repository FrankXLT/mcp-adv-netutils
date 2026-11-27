package whois

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	resp "github.com/FrankXLT/mcp-adv-netutils/internal/response"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/utils"
	"github.com/likexian/whois"
	"github.com/mark3labs/mcp-go/mcp"
)

const defaultTimeout = 10 * time.Second

// Config holds WHOIS configuration.
type Config struct {
	CustomServer string
	Timeout      time.Duration
	Guard        *security.TargetGuard
}

// WhoisQueryParams represents the parameters for WHOIS queries.
type WhoisQueryParams struct {
	Domain string `json:"domain"`
}

// WhoisResponse represents the structured result of a WHOIS query.
type WhoisResponse struct {
	Domain string `json:"domain"`
	Result string `json:"result"`
}

type whoisLookupResult struct {
	data string
	err  error
}

// HandleWhoisQuery processes WHOIS queries.
//
//nolint:gocritic // Exported handler mirrors mcp-go ToolHandlerFunc value parameter.
func HandleWhoisQuery(ctx context.Context, request mcp.CallToolRequest, config *Config) (*mcp.CallToolResult, error) {
	var params WhoisQueryParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	result, err := Execute(ctx, params, config)
	if err != nil {
		return nil, err
	}

	toolResult, err := resp.JSON(result)
	if err != nil {
		return nil, fmt.Errorf("failed to encode WHOIS response: %w", err)
	}
	return toolResult, nil
}

// Execute runs a WHOIS lookup with target sanitization, optional TargetGuard checks,
// and context-aware timeout/cancellation handling.
func Execute(ctx context.Context, params WhoisQueryParams, cfg *Config) (*WhoisResponse, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}

	if params.Domain == "" {
		return nil, errors.New("parameter \"domain\" is required")
	}

	domain, err := security.SanitizeTarget(params.Domain)
	if err != nil {
		return nil, fmt.Errorf("invalid domain format: %w", err)
	}

	if strings.Contains(domain, "..") || strings.HasPrefix(domain, ".") {
		return nil, fmt.Errorf("invalid domain format: %q", domain)
	}

	timeout := defaultTimeout
	var customServer string
	var guard *security.TargetGuard
	if cfg != nil {
		if cfg.Timeout > 0 {
			timeout = cfg.Timeout
		}
		customServer = strings.TrimSpace(cfg.CustomServer)
		guard = cfg.Guard
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := ctxWithTimeout.Err(); err != nil {
		return nil, fmt.Errorf("WHOIS query cancelled: %w", err)
	}

	if guard != nil {
		if _, err := guard.ValidateHostOrIP(ctxWithTimeout, domain); err != nil {
			return nil, fmt.Errorf("domain %q blocked by target guard: %w", domain, err)
		}
	}

	client := whois.NewClient()
	client.SetTimeout(timeout)

	ch := make(chan whoisLookupResult, 1)
	go func() {
		var result string
		var lookupErr error
		if customServer != "" {
			result, lookupErr = client.Whois(domain, customServer)
		} else {
			result, lookupErr = client.Whois(domain)
		}
		ch <- whoisLookupResult{data: result, err: lookupErr}
	}()

	select {
	case <-ctxWithTimeout.Done():
		return nil, fmt.Errorf("WHOIS query cancelled or timed out: %w", ctxWithTimeout.Err())
	case res := <-ch:
		if res.err != nil {
			return nil, fmt.Errorf("WHOIS query failed: %w", res.err)
		}
		return &WhoisResponse{
			Domain: domain,
			Result: res.data,
		}, nil
	}
}
