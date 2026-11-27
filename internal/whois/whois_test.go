package whois

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startMockWhoisServer(t *testing.T, handler func(net.Conn)) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = ln.Close()
	})

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go handler(conn)
		}
	}()

	return ln.Addr().String()
}

func TestHandleWhoisQuery_ParameterValidation(t *testing.T) {
	ctx := context.Background()
	cfg := &Config{Timeout: 2 * time.Second}

	t.Run("missing domain parameter", func(t *testing.T) {
		req := mcp.CallToolRequest{
			Params: mcp.CallToolParams{Arguments: map[string]interface{}{}},
		}
		res, err := HandleWhoisQuery(ctx, req, cfg)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), `parameter "domain" is required`)
	})

	t.Run("empty domain parameter", func(t *testing.T) {
		req := mcp.CallToolRequest{
			Params: mcp.CallToolParams{Arguments: map[string]interface{}{"domain": ""}},
		}
		res, err := HandleWhoisQuery(ctx, req, cfg)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), `parameter "domain" is required`)
	})

	t.Run("invalid json arguments", func(t *testing.T) {
		req := mcp.CallToolRequest{
			Params: mcp.CallToolParams{Arguments: map[string]interface{}{"domain": 12345}},
		}
		res, err := HandleWhoisQuery(ctx, req, cfg)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "failed to parse tool input")
	})
}

func TestExecute_DomainSanitizationAndGuard(t *testing.T) {
	ctx := context.Background()

	t.Run("nil context returns error", func(t *testing.T) {
		//nolint:staticcheck // intentionally passing nil context to verify guard check
		res, err := Execute(nil, WhoisQueryParams{Domain: "example.com"}, nil)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "context must not be nil")
	})

	t.Run("invalid domain syntax rejected", func(t *testing.T) {
		badDomains := []string{"   ", "-example.com", "example.com/path", "bad?query", "a..b.com", ".example.com"}
		for _, bad := range badDomains {
			res, err := Execute(ctx, WhoisQueryParams{Domain: bad}, nil)
			require.Error(t, err, "domain=%q should be rejected", bad)
			assert.Nil(t, res)
			assert.Contains(t, err.Error(), "invalid domain format")
		}
	})

	t.Run("target guard blocks denied and private targets", func(t *testing.T) {
		guard, err := security.NewTargetGuardWithOptions(nil, nil, true)
		require.NoError(t, err)
		cfg := &Config{Timeout: 2 * time.Second, Guard: guard}

		for _, blocked := range []string{"169.254.169.254", "127.0.0.1", "localhost"} {
			res, execErr := Execute(ctx, WhoisQueryParams{Domain: blocked}, cfg)
			require.Error(t, execErr, "target=%q should be blocked", blocked)
			assert.Nil(t, res)
			assert.Contains(t, execErr.Error(), "blocked by target guard")
		}
	})
}

func TestExecute_LoopbackMockServer(t *testing.T) {
	addr := startMockWhoisServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		reader := bufio.NewReader(conn)
		line, _ := reader.ReadString('\n')
		query := strings.TrimSpace(line)
		_, _ = conn.Write([]byte("Domain Name: " + strings.ToUpper(query) + "\r\nRegistrar: Mock WHOIS\r\n"))
	})

	t.Run("execute succeeds with trimmed domain and nil timeout default", func(t *testing.T) {
		cfg := &Config{CustomServer: addr}
		res, err := Execute(context.Background(), WhoisQueryParams{Domain: " example.com "}, cfg)
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.Equal(t, "example.com", res.Domain)
		assert.Contains(t, res.Result, "Domain Name: EXAMPLE.COM")
		assert.Contains(t, res.Result, "Registrar: Mock WHOIS")
	})

	t.Run("handle whois query returns expected JSON", func(t *testing.T) {
		req := mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Arguments: map[string]interface{}{"domain": "example.org"},
			},
		}
		res, err := HandleWhoisQuery(context.Background(), req, &Config{CustomServer: addr, Timeout: 2 * time.Second})
		require.NoError(t, err)
		require.Len(t, res.Content, 1)

		textContent, ok := mcp.AsTextContent(res.Content[0])
		require.True(t, ok)

		var payload WhoisResponse
		require.NoError(t, json.Unmarshal([]byte(textContent.Text), &payload))
		assert.Equal(t, "example.org", payload.Domain)
		assert.Contains(t, payload.Result, "Domain Name: EXAMPLE.ORG")
	})

	t.Run("guard allowlist permits loopback when explicitly allowed", func(t *testing.T) {
		guard, err := security.NewTargetGuard([]string{"127.0.0.0/8"}, nil)
		require.NoError(t, err)

		res, err := Execute(context.Background(), WhoisQueryParams{Domain: "127.0.0.1"}, &Config{
			CustomServer: addr,
			Timeout:      2 * time.Second,
			Guard:        guard,
		})
		require.NoError(t, err)
		assert.Equal(t, "127.0.0.1", res.Domain)
		assert.Contains(t, res.Result, "Domain Name: 127.0.0.1")
	})
}

func TestExecute_ContextCancellationAndTimeout(t *testing.T) {
	releaseServer := make(chan struct{})
	t.Cleanup(func() {
		close(releaseServer)
	})

	hangingAddr := startMockWhoisServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		<-releaseServer
	})

	t.Run("pre-cancelled context returns immediately", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		res, err := Execute(ctx, WhoisQueryParams{Domain: "example.com"}, &Config{
			CustomServer: hangingAddr,
			Timeout:      5 * time.Second,
		})
		require.Error(t, err)
		assert.Nil(t, res)
		assert.True(t, errors.Is(err, context.Canceled))
	})

	t.Run("in-flight context cancellation does not wait for client timeout", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(40 * time.Millisecond)
			cancel()
		}()

		start := time.Now()
		res, err := Execute(ctx, WhoisQueryParams{Domain: "example.com"}, &Config{
			CustomServer: hangingAddr,
			Timeout:      10 * time.Second,
		})
		elapsed := time.Since(start)

		require.Error(t, err)
		assert.Nil(t, res)
		assert.True(t, errors.Is(err, context.Canceled))
		assert.Less(t, elapsed, 2*time.Second)
	})

	t.Run("timeout expires against unresponsive server", func(t *testing.T) {
		res, err := Execute(context.Background(), WhoisQueryParams{Domain: "example.com"}, &Config{
			CustomServer: hangingAddr,
			Timeout:      50 * time.Millisecond,
		})
		require.Error(t, err)
		assert.Nil(t, res)
		assert.True(t, errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "WHOIS query failed"))
	})
}

func TestExecute_GuardDialer(t *testing.T) {
	t.Run("denies private CustomServer without dialing", func(t *testing.T) {
		var dialed atomic.Bool
		addr := startMockWhoisServer(t, func(conn net.Conn) {
			dialed.Store(true)
			_ = conn.Close()
		})

		guard, err := security.NewTargetGuardWithOptions(nil, nil, true)
		require.NoError(t, err)

		res, err := Execute(context.Background(), WhoisQueryParams{Domain: "8.8.8.8"}, &Config{
			CustomServer: addr,
			Timeout:      2 * time.Second,
			Guard:        guard,
		})
		require.Error(t, err)
		assert.Nil(t, res)
		assert.ErrorIs(t, err, security.ErrTargetDenied)
		assert.False(t, dialed.Load(), "denied CustomServer must not be dialed")
	})

	t.Run("denies metadata CustomServer without dialing", func(t *testing.T) {
		guard, err := security.NewTargetGuard(nil, nil)
		require.NoError(t, err)

		res, err := Execute(context.Background(), WhoisQueryParams{Domain: "8.8.8.8"}, &Config{
			CustomServer: "169.254.169.254:43",
			Timeout:      2 * time.Second,
			Guard:        guard,
		})
		require.Error(t, err)
		assert.Nil(t, res)
		assert.ErrorIs(t, err, security.ErrTargetDenied)
	})
}
