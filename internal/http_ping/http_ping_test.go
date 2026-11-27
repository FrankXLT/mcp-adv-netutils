package http_ping_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/http_ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecute_HTTPServerJSONMilliseconds(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pong"))
	}))
	defer srv.Close()

	count := 2
	cfg := &http_ping.Config{
		Timeout: 10 * time.Second,
		Count:   1,
	}

	res, err := http_ping.Execute(context.Background(), http_ping.HTTPPingParams{
		URL:    srv.URL + "/health?foo=bar",
		Method: "get",
		Count:  &count,
	}, cfg)
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.Equal(t, 2, res.RequestsSent)
	assert.Equal(t, 2, res.SuccessCount)
	assert.Equal(t, 0, res.FailureCount)
	assert.Equal(t, http.MethodGet, res.Method)
	assert.Equal(t, srv.URL+"/health", res.Target)
	require.Len(t, res.Results, 2)

	raw, err := json.Marshal(res)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))

	for _, avgKey := range []string{
		"avg_dns_time_ms",
		"avg_connect_time_ms",
		"avg_tls_time_ms",
		"avg_ttfb_time_ms",
		"avg_total_time_ms",
	} {
		val, ok := decoded[avgKey].(float64)
		require.True(t, ok, "expected float64 for %s", avgKey)
		assert.GreaterOrEqual(t, val, 0.0, avgKey)
		assert.Less(t, val, 5000.0, "%s should be in ms, not ns", avgKey)
	}
	assert.Greater(t, decoded["avg_total_time_ms"].(float64), 0.0)

	rawResults, ok := decoded["results"].([]any)
	require.True(t, ok)
	require.Len(t, rawResults, 2)

	for i, item := range rawResults {
		entry, ok := item.(map[string]any)
		require.True(t, ok)
		for _, key := range []string{
			"dns_time_ms",
			"connect_time_ms",
			"tls_time_ms",
			"ttfb_time_ms",
			"total_time_ms",
		} {
			val, ok := entry[key].(float64)
			require.True(t, ok, "result[%d] missing float64 %s", i, key)
			assert.GreaterOrEqual(t, val, 0.0)
			assert.Less(t, val, 5000.0, "result[%d].%s should be in ms, not ns", i, key)
		}
		assert.Greater(t, entry["total_time_ms"].(float64), 0.0)
	}
}

func TestExecute_TLSServerMilliseconds(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	certPool := x509.NewCertPool()
	certPool.AddCert(srv.Certificate())

	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)

	cfg := &http_ping.Config{
		Timeout: 10 * time.Second,
		Count:   1,
		Guard:   guard,
		TLSConfig: &tls.Config{
			RootCAs:    certPool,
			MinVersion: tls.VersionTLS12,
		},
	}

	res, err := http_ping.Execute(context.Background(), http_ping.HTTPPingParams{
		URL:    srv.URL,
		Method: http.MethodHead,
	}, cfg)
	require.NoError(t, err)
	require.Len(t, res.Results, 1)

	r := res.Results[0]
	assert.True(t, r.Success)
	assert.Equal(t, http.StatusNoContent, r.StatusCode)
	assert.Greater(t, r.TLSTime, 0.0)
	assert.Less(t, r.TLSTime, 5000.0)
	assert.Greater(t, r.TotalTime, 0.0)
	assert.Less(t, r.TotalTime, 5000.0)
	assert.Greater(t, res.AvgTLSTime, 0.0)
	assert.Less(t, res.AvgTLSTime, 5000.0)
	assert.Contains(t, r.OneLiner, "tls=")
}

func TestExecute_BlocksMetadataSSRF(t *testing.T) {
	t.Parallel()

	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)

	cfg := &http_ping.Config{
		Timeout: 5 * time.Second,
		Count:   1,
		Guard:   guard,
	}

	testCases := []struct {
		name string
		url  string
	}{
		{
			name: "http metadata IP",
			url:  "http://169.254.169.254/latest/meta-data/",
		},
		{
			name: "schemeless metadata IP",
			url:  "169.254.169.254",
		},
		{
			name: "metadata IPv6",
			url:  "http://[fd00:ec2::254]/latest/meta-data/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, execErr := http_ping.Execute(context.Background(), http_ping.HTTPPingParams{
				URL: tc.url,
			}, cfg)
			require.Error(t, execErr)
			assert.Nil(t, res)
			assert.True(t, errors.Is(execErr, security.ErrTargetDenied), "expected ErrTargetDenied, got: %v", execErr)
		})
	}
}

func TestExecute_BlocksRedirectSSRF(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)

	cfg := &http_ping.Config{
		Timeout: 5 * time.Second,
		Count:   1,
		Guard:   guard,
	}

	res, err := http_ping.Execute(context.Background(), http_ping.HTTPPingParams{
		URL: srv.URL,
	}, cfg)
	require.NoError(t, err)
	require.Len(t, res.Results, 1)
	assert.False(t, res.Results[0].Success)
	assert.Contains(t, res.Results[0].Error, "redirect target blocked by security policy")
}

func TestExecute_ContextCancellationStopsLoopPromptly(t *testing.T) {
	t.Parallel()

	firstHit := make(chan struct{})
	var once sync.Once

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		once.Do(func() {
			close(firstHit)
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-firstHit
		// Cancel shortly after the first request hits so the loop is in its inter-request wait.
		time.Sleep(25 * time.Millisecond)
		cancel()
	}()

	count := 5
	cfg := &http_ping.Config{
		Timeout: 30 * time.Second,
		Count:   1,
	}

	start := time.Now()
	res, err := http_ping.Execute(ctx, http_ping.HTTPPingParams{
		URL:   srv.URL,
		Count: &count,
	}, cfg)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Less(t, elapsed, 800*time.Millisecond, "loop should abort promptly instead of sleeping between requests")
	assert.Equal(t, 1, res.RequestsSent)
	assert.Len(t, res.Results, 1)
	assert.Equal(t, 1, res.SuccessCount)
	assert.Greater(t, res.AvgTotalTime, 0.0)
	assert.Less(t, res.AvgTotalTime, 5000.0)
}

func TestHandleHTTPPing_MCPWrapper(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	req := mcp.CallToolRequest{}
	req.Params.Name = "http_ping"
	req.Params.Arguments = map[string]any{
		"url":    srv.URL,
		"method": "GET",
		"count":  1,
	}

	toolRes, err := http_ping.HandleHTTPPing(context.Background(), req, nil)
	require.NoError(t, err)
	require.NotNil(t, toolRes)
	assert.False(t, toolRes.IsError)
}
