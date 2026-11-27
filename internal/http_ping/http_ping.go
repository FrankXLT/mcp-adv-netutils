package http_ping

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	resp "github.com/FrankXLT/mcp-adv-netutils/internal/response"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/utils"
	"github.com/mark3labs/mcp-go/mcp"
)

// Config holds HTTP ping configuration.
type Config struct {
	Timeout   time.Duration
	Count     int
	Guard     *security.TargetGuard
	TLSConfig *tls.Config
}

// HTTPPingParams represents the parameters for HTTP ping operations.
type HTTPPingParams struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Count  *int   `json:"count"`
}

// HTTPPingResult represents the result of a single HTTP ping.
type HTTPPingResult struct {
	Sequence   int     `json:"sequence"`
	Method     string  `json:"method"`
	URL        string  `json:"url"`
	StatusCode int     `json:"status_code"`
	Status     string  `json:"status"`
	DNSTime    float64 `json:"dns_time_ms"`
	ConnTime   float64 `json:"connect_time_ms"`
	TLSTime    float64 `json:"tls_time_ms"`
	TTFBTime   float64 `json:"ttfb_time_ms"`
	TotalTime  float64 `json:"total_time_ms"`
	Success    bool    `json:"success"`
	Error      string  `json:"error,omitempty"`
	OneLiner   string  `json:"one_liner"`
}

// HTTPPingResponse represents the complete HTTP ping response.
type HTTPPingResponse struct {
	Target       string           `json:"target"`
	Method       string           `json:"method"`
	RequestsSent int              `json:"requests_sent"`
	SuccessCount int              `json:"success_count"`
	FailureCount int              `json:"failure_count"`
	Results      []HTTPPingResult `json:"results"`
	AvgDNSTime   float64          `json:"avg_dns_time_ms"`
	AvgConnTime  float64          `json:"avg_connect_time_ms"`
	AvgTLSTime   float64          `json:"avg_tls_time_ms"`
	AvgTTFBTime  float64          `json:"avg_ttfb_time_ms"`
	AvgTotalTime float64          `json:"avg_total_time_ms"`
	Timestamp    string           `json:"timestamp"`
}

// timingStats holds timing statistics for calculations.
type timingStats struct {
	totalDNS   float64
	totalConn  float64
	totalTLS   float64
	totalTTFB  float64
	totalTotal float64
	count      int
}

type traceTimings struct {
	mu        sync.Mutex
	dnsStart  time.Time
	dnsEnd    time.Time
	connStart time.Time
	connEnd   time.Time
	tlsStart  time.Time
	tlsEnd    time.Time
	reqStart  time.Time
	respStart time.Time
}

const (
	defaultTimeout    = 10 * time.Second
	defaultCount      = 1
	maxRedirects      = 10
	maxBodyDrainBytes = 1 << 20
	interRequestDelay = time.Second
	httpPingUserAgent = "mcp-netutils/http_ping"
)

// HandleHTTPPing performs HTTP ping operations to test connectivity to a HTTP endpoint.
//
//nolint:gocritic // Exported handler mirrors mcp-go ToolHandlerFunc value parameter.
func HandleHTTPPing(ctx context.Context, request mcp.CallToolRequest, config *Config) (*mcp.CallToolResult, error) {
	var params HTTPPingParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	httpResponse, err := Execute(ctx, params, config)
	if err != nil {
		return nil, fmt.Errorf("HTTP ping failed: %w", err)
	}

	// Use the response package to handle JSON encoding and MCP tool result creation
	toolResult, err := resp.JSON(httpResponse)
	if err != nil {
		return nil, fmt.Errorf("encode HTTP ping response: %w", err)
	}
	return toolResult, nil
}

// Execute validates parameters and performs the HTTP ping operation.
func Execute(ctx context.Context, params HTTPPingParams, cfg *Config) (*HTTPPingResponse, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}

	parsedURL, err := parseAndValidateURL(params.URL)
	if err != nil {
		return nil, err
	}

	method, err := normalizeAndValidateMethod(params.Method)
	if err != nil {
		return nil, err
	}

	timeout, count, guard, tlsConfig := resolveConfig(cfg, params.Count)
	if guard == nil {
		if guard, err = security.NewTargetGuard(nil, nil); err != nil {
			return nil, fmt.Errorf("failed to initialize target guard: %w", err)
		}
	}

	// Create context with timeout
	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if _, err := guard.ValidateHostOrIP(ctxWithTimeout, parsedURL.Hostname()); err != nil {
		return nil, fmt.Errorf("target blocked by security policy: %w", err)
	}

	return performHTTPPing(ctxWithTimeout, method, parsedURL, count, timeout, guard, tlsConfig), nil
}

func parseAndValidateURL(rawURL string) (*url.URL, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return nil, errors.New("parameter \"url\" is required")
	}

	parsedURL, err := url.Parse(trimmed)
	if (err != nil && !strings.Contains(trimmed, "://")) || (err == nil && parsedURL.Scheme == "") {
		parsedURL, err = url.Parse("https://" + trimmed)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme: %s", parsedURL.Scheme)
	}

	if parsedURL.Hostname() == "" {
		return nil, errors.New("invalid URL: missing host")
	}

	return parsedURL, nil
}

func normalizeAndValidateMethod(rawMethod string) (string, error) {
	method := strings.ToUpper(strings.TrimSpace(rawMethod))
	if method == "" {
		return http.MethodGet, nil
	}

	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete,
		http.MethodHead, http.MethodOptions, http.MethodPatch:
		return method, nil
	default:
		return "", fmt.Errorf("unsupported HTTP method: %s", method)
	}
}

func resolveConfig(cfg *Config, paramCount *int) (time.Duration, int, *security.TargetGuard, *tls.Config) {
	timeout, count := defaultTimeout, defaultCount
	var guard *security.TargetGuard
	var tlsConfig *tls.Config

	if cfg != nil {
		if cfg.Timeout > 0 {
			timeout = cfg.Timeout
		}
		if cfg.Count > 0 {
			count = cfg.Count
		}
		guard = cfg.Guard
		tlsConfig = cfg.TLSConfig
	}

	if paramCount != nil && *paramCount > 0 {
		count = *paramCount
	}

	return timeout, count, guard, tlsConfig
}

// performHTTPPing executes the actual HTTP ping operation.
func performHTTPPing(
	ctx context.Context,
	method string,
	parsedURL *url.URL,
	count int,
	timeout time.Duration,
	guard *security.TargetGuard,
	tlsConfig *tls.Config,
) *HTTPPingResponse {
	cleanTarget := cleanURLString(parsedURL)

	response := &HTTPPingResponse{
		Target:    cleanTarget,
		Method:    method,
		Results:   make([]HTTPPingResult, 0, count),
		Timestamp: time.Now().Format(time.RFC3339),
	}

	transport := &http.Transport{
		DisableKeepAlives: true, // Ensure fresh connections for accurate timing
		Proxy:             nil,
		DialContext:       guard.DialContext,
		TLSClientConfig:   tlsConfig,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			redirectHost := req.URL.Hostname()
			if redirectHost == "" {
				return errors.New("redirect URL missing host")
			}
			if _, err := guard.ValidateHostOrIP(req.Context(), redirectHost); err != nil {
				return fmt.Errorf("redirect target blocked by security policy: %w", err)
			}
			return nil
		},
	}

	var stats timingStats

pingLoop:
	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			break pingLoop
		default:
		}

		result := performSingleHTTPPing(ctx, client, method, parsedURL, cleanTarget, i+1)
		response.Results = append(response.Results, result)

		if result.Success {
			response.SuccessCount++
			updateTimingStats(&stats, &result)
		} else {
			response.FailureCount++
		}

		// Wait between requests (except for the last one)
		if i < count-1 {
			timer := time.NewTimer(interRequestDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				break pingLoop
			case <-timer.C:
			}
		}
	}

	response.RequestsSent = len(response.Results)
	calculateAverages(response, &stats)

	return response
}

func cleanURLString(parsedURL *url.URL) string {
	// Create clean URL without query parameters for display
	cleanURL := &url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
		Path:   parsedURL.Path,
	}
	return cleanURL.String()
}

// performSingleHTTPPing performs a single HTTP ping request.
func performSingleHTTPPing(
	ctx context.Context,
	client *http.Client,
	method string,
	parsedURL *url.URL,
	cleanTarget string,
	sequence int,
) HTTPPingResult {
	result := HTTPPingResult{
		Sequence: sequence,
		Method:   method,
		URL:      cleanTarget,
	}

	timings, trace := newTraceTimings()
	reqCtx := httptrace.WithClientTrace(ctx, trace)
	req, err := http.NewRequestWithContext(reqCtx, method, parsedURL.String(), http.NoBody)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		result.OneLiner = fmt.Sprintf("%s %s ERROR | %s", method, cleanTarget, result.Error)
		return result
	}

	req.Header.Set("User-Agent", httpPingUserAgent)

	startTime := time.Now()

	httpResp, err := client.Do(req)
	if err != nil {
		result.TotalTime = durationToMillis(time.Since(startTime))
		result.Error = fmt.Sprintf("request failed: %v", err)
		result.OneLiner = fmt.Sprintf("%s %s ERROR | total=%.2fms | %s", method, cleanTarget, result.TotalTime, result.Error)
		return result
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(httpResp.Body, maxBodyDrainBytes))
		_ = httpResp.Body.Close()
	}()

	endTime := time.Now()

	result.TotalTime = durationToMillis(endTime.Sub(startTime))
	result.StatusCode = httpResp.StatusCode
	result.Status = httpResp.Status
	result.Success = httpResp.StatusCode >= 200 && httpResp.StatusCode < 400
	timings.applyToResult(&result)

	var tlsInfo string
	if parsedURL.Scheme == "https" {
		tlsInfo = fmt.Sprintf("tls=%.2fms ", result.TLSTime)
	}

	result.OneLiner = fmt.Sprintf("%s %s %d %s | dns=%.2fms conn=%.2fms %sttfb=%.2fms total=%.2fms",
		method, cleanTarget, result.StatusCode, getStatusText(result.StatusCode),
		result.DNSTime, result.ConnTime, tlsInfo, result.TTFBTime, result.TotalTime)

	return result
}

func newTraceTimings() (*traceTimings, *httptrace.ClientTrace) {
	t := &traceTimings{}
	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			t.mu.Lock()
			t.dnsStart = time.Now()
			t.mu.Unlock()
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			t.mu.Lock()
			t.dnsEnd = time.Now()
			t.mu.Unlock()
		},
		ConnectStart: func(_, _ string) {
			t.mu.Lock()
			t.connStart = time.Now()
			t.mu.Unlock()
		},
		ConnectDone: func(_, _ string, _ error) {
			t.mu.Lock()
			t.connEnd = time.Now()
			t.mu.Unlock()
		},
		TLSHandshakeStart: func() {
			t.mu.Lock()
			t.tlsStart = time.Now()
			t.mu.Unlock()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			t.mu.Lock()
			t.tlsEnd = time.Now()
			t.mu.Unlock()
		},
		WroteRequest: func(_ httptrace.WroteRequestInfo) {
			t.mu.Lock()
			t.reqStart = time.Now()
			t.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			t.mu.Lock()
			t.respStart = time.Now()
			t.mu.Unlock()
		},
	}
	return t, trace
}

func (t *traceTimings) applyToResult(result *HTTPPingResult) {
	t.mu.Lock()
	dnsDur := subIfBothSet(t.dnsStart, t.dnsEnd)
	connDur := subIfBothSet(t.connStart, t.connEnd)
	tlsDur := subIfBothSet(t.tlsStart, t.tlsEnd)
	ttfbDur := subIfBothSet(t.reqStart, t.respStart)
	t.mu.Unlock()

	result.DNSTime = durationToMillis(dnsDur)
	result.ConnTime = durationToMillis(connDur)
	result.TLSTime = durationToMillis(tlsDur)
	result.TTFBTime = durationToMillis(ttfbDur)
}

func subIfBothSet(start, end time.Time) time.Duration {
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return 0
	}
	return end.Sub(start)
}

func durationToMillis(d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(d.Microseconds()) / 1000.0
}

// updateTimingStats updates the timing statistics with a successful result.
func updateTimingStats(stats *timingStats, result *HTTPPingResult) {
	stats.totalDNS += result.DNSTime
	stats.totalConn += result.ConnTime
	stats.totalTLS += result.TLSTime
	stats.totalTTFB += result.TTFBTime
	stats.totalTotal += result.TotalTime
	stats.count++
}

// calculateAverages calculates and sets the average timing statistics.
func calculateAverages(response *HTTPPingResponse, stats *timingStats) {
	if stats.count > 0 {
		n := float64(stats.count)
		response.AvgDNSTime = stats.totalDNS / n
		response.AvgConnTime = stats.totalConn / n
		response.AvgTLSTime = stats.totalTLS / n
		response.AvgTTFBTime = stats.totalTTFB / n
		response.AvgTotalTime = stats.totalTotal / n
	}
}

// getStatusText returns a human-readable status text for common HTTP status codes.
func getStatusText(statusCode int) string {
	switch statusCode {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Gateway Timeout"
	default:
		return http.StatusText(statusCode)
	}
}
