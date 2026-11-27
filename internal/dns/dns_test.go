package dns

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type shortTestRR struct {
	dns.RR
	hdr  dns.RR_Header
	text string
}

func (r *shortTestRR) Header() *dns.RR_Header { return &r.hdr }
func (r *shortTestRR) String() string         { return r.text }

func startTestDNSServer(t *testing.T, network string, handler dns.Handler) string {
	t.Helper()

	started := make(chan struct{})
	srv := &dns.Server{
		Handler:           handler,
		NotifyStartedFunc: func() { close(started) },
	}

	var addr string
	switch network {
	case "udp":
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		srv.PacketConn = pc
		addr = pc.LocalAddr().String()
	case "tcp":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		srv.Listener = ln
		addr = ln.Addr().String()
	default:
		t.Fatalf("unsupported test network %q", network)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ActivateAndServe()
	}()

	select {
	case <-started:
	case err := <-errCh:
		t.Fatalf("test DNS server failed to start: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for test DNS server to start")
	}

	t.Cleanup(func() {
		_ = srv.Shutdown()
	})

	return addr
}

func startMockDoHServer(t *testing.T, handler func(req *dns.Msg) *dns.Msg, delay time.Duration) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}

		var wireReq []byte
		var err error
		if r.Method == http.MethodGet {
			wireReq, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		} else {
			wireReq, err = io.ReadAll(r.Body)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		reqMsg := new(dns.Msg)
		if err := reqMsg.Unpack(wireReq); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		respMsg := handler(reqMsg)
		wireResp, err := respMsg.Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wireResp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func makeToolRequest(args map[string]any) mcp.CallToolRequest {
	return mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Arguments: args,
		},
	}
}

func TestFormatDNSServerAddrIPv6AndResolvConfLoopback(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "bare_ipv4", input: "8.8.8.8", want: "8.8.8.8:53"},
		{name: "ipv4_with_port", input: "127.0.0.1:5353", want: "127.0.0.1:5353"},
		{name: "bare_ipv6_loopback", input: "::1", want: "[::1]:53"},
		{name: "bare_ipv6_global", input: "2001:4860:4860::8888", want: "[2001:4860:4860::8888]:53"},
		{name: "bracketed_ipv6_no_port", input: "[::1]", want: "[::1]:53"},
		{name: "bracketed_ipv6_with_port", input: "[::1]:5353", want: "[::1]:5353"},
		{name: "hostname_no_port", input: "dns.example.com", want: "dns.example.com:53"},
		{name: "hostname_with_port", input: "dns.example.com:8053", want: "dns.example.com:8053"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, formatDNSServerAddr(tc.input))
		})
	}

	resolvPath := filepath.Join(t.TempDir(), "resolv.conf")
	content := "nameserver 127.0.0.1\nnameserver ::1\nnameserver 1.1.1.1\n"
	require.NoError(t, os.WriteFile(resolvPath, []byte(content), 0o600))

	servers, err := parseResolvConfServers(resolvPath)
	require.NoError(t, err)
	assert.Equal(t, []string{"127.0.0.1", "::1", "1.1.1.1"}, servers)
}

func TestExecuteLocalAndHandleLocalDNSQuery(t *testing.T) {
	t.Parallel()

	udpHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
				A:   net.ParseIP("93.184.216.34"),
			})
		}
		_ = w.WriteMsg(m)
	})

	udpAddr := startTestDNSServer(t, "udp", udpHandler)
	tcpAddr := startTestDNSServer(t, "tcp", udpHandler)
	require.NotEmpty(t, tcpAddr)

	cfg := &QueryConfig{
		Timeout:      2 * time.Second,
		LocalServers: []string{udpAddr},
	}

	res, err := ExecuteLocal(context.Background(), DNSQueryParams{
		Domain:     "example.com",
		RecordType: "A",
	}, cfg)
	require.NoError(t, err)
	require.Len(t, res.Answer, 1)
	assert.Equal(t, "93.184.216.34", res.Answer[0].Data)
	assert.Equal(t, "A", res.Answer[0].TypeName)

	mcpRes, err := HandleLocalDNSQuery(context.Background(), makeToolRequest(map[string]any{
		"domain":      "example.com",
		"record_type": "A",
	}), cfg)
	require.NoError(t, err)
	require.NotNil(t, mcpRes)
	require.Len(t, mcpRes.Content, 1)

	textContent, ok := mcp.AsTextContent(mcpRes.Content[0])
	require.True(t, ok)
	var decoded DNSResponse
	require.NoError(t, json.Unmarshal([]byte(textContent.Text), &decoded))
	require.Len(t, decoded.Answer, 1)
	assert.Equal(t, "93.184.216.34", decoded.Answer[0].Data)

	// Verify TCP test server also responds cleanly when queried directly.
	tcpClient := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	tcpResp, _, err := tcpClient.ExchangeContext(context.Background(), q, tcpAddr)
	require.NoError(t, err)
	require.Len(t, tcpResp.Answer, 1)
}

func TestExecuteLocalValidationGuardAndTimeout(t *testing.T) {
	t.Parallel()

	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)

	_, err = ExecuteLocal(context.Background(), DNSQueryParams{Domain: "-invalid.example", RecordType: "A"}, &QueryConfig{LocalServers: []string{"127.0.0.1:53"}})
	require.Error(t, err)

	_, err = ExecuteLocal(context.Background(), DNSQueryParams{Domain: "bad..example.com", RecordType: "A"}, &QueryConfig{LocalServers: []string{"127.0.0.1:53"}})
	require.Error(t, err)

	_, err = ExecuteLocal(context.Background(), DNSQueryParams{Domain: "example.com", RecordType: "A"}, &QueryConfig{
		Timeout:      time.Second,
		LocalServers: []string{"169.254.169.254"},
		Guard:        guard,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrTargetDenied)

	slowAddr := startTestDNSServer(t, "udp", dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(200 * time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	}))

	_, err = ExecuteLocal(context.Background(), DNSQueryParams{
		Domain:     "slow.example.com",
		RecordType: "A",
	}, &QueryConfig{
		Timeout:      35 * time.Millisecond,
		LocalServers: []string{slowAddr},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded)

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = ExecuteLocal(canceledCtx, DNSQueryParams{
		Domain:     "canceled.example.com",
		RecordType: "A",
	}, &QueryConfig{
		Timeout:      2 * time.Second,
		LocalServers: []string{slowAddr},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestExecuteRemoteDoHFallbackFreshTimeoutAndGuard(t *testing.T) {
	t.Parallel()

	makeReply := func(ip string) func(*dns.Msg) *dns.Msg {
		return func(r *dns.Msg) *dns.Msg {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(ip),
			})
			return m
		}
	}

	okServer := startMockDoHServer(t, makeReply("198.51.100.10"), 0)
	res, err := ExecuteRemote(context.Background(), DNSQueryParams{
		Domain:     "example.org",
		RecordType: "A",
	}, &QueryConfig{
		Timeout:             2 * time.Second,
		RemoteServerAddress: okServer.URL,
	})
	require.NoError(t, err)
	require.Len(t, res.Answer, 1)
	assert.Equal(t, "198.51.100.10", res.Answer[0].Data)

	// Primary DoH server times out (>40ms), fallback receives a fresh timeout and succeeds.
	slowPrimary := startMockDoHServer(t, makeReply("198.51.100.1"), 200*time.Millisecond)
	fastFallback := startMockDoHServer(t, makeReply("198.51.100.2"), 0)

	fallbackRes, err := executeRemoteWithServers(context.Background(), DNSQueryParams{
		Domain:     "fallback.example.org",
		RecordType: "A",
	}, &QueryConfig{
		Timeout: 45 * time.Millisecond,
	}, slowPrimary.URL, fastFallback.URL)
	require.NoError(t, err)
	require.Len(t, fallbackRes.Answer, 1)
	assert.Equal(t, "198.51.100.2", fallbackRes.Answer[0].Data)

	// Explicit parent context cancellation must surface timeout/cancel without fallback masking.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = ExecuteRemote(ctx, DNSQueryParams{
		Domain:     "timeout.example.org",
		RecordType: "A",
	}, &QueryConfig{
		Timeout:             2 * time.Second,
		RemoteServerAddress: slowPrimary.URL,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)
	_, err = ExecuteRemote(context.Background(), DNSQueryParams{
		Domain:     "example.org",
		RecordType: "A",
	}, &QueryConfig{
		Timeout:             time.Second,
		RemoteServerAddress: "http://169.254.169.254/dns-query",
		Guard:               guard,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrTargetDenied)
}

func TestCreateDNSResponseShortRRBoundsSafety(t *testing.T) {
	t.Parallel()

	msg := new(dns.Msg)
	msg.SetQuestion("short.example.", dns.TypeTXT)
	msg.Answer = []dns.RR{
		&shortTestRR{
			hdr:  dns.RR_Header{Name: "short.example.", Rrtype: dns.TypeNULL, Class: dns.ClassINET, Ttl: 60},
			text: "",
		},
		&shortTestRR{
			hdr:  dns.RR_Header{Name: "short.example.", Rrtype: dns.TypeNULL, Class: dns.ClassINET, Ttl: 60},
			text: "only three fields",
		},
		&shortTestRR{
			hdr:  dns.RR_Header{Name: "short.example.", Rrtype: dns.TypeNULL, Class: dns.ClassINET, Ttl: 60},
			text: "short.example. 60 IN NULL payload_part1 payload_part2",
		},
	}

	require.NotPanics(t, func() {
		resp := createDNSResponse(msg)
		require.Len(t, resp.Answer, 3)
		assert.Equal(t, "", resp.Answer[0].Data)
		assert.Equal(t, "only three fields", resp.Answer[1].Data)
		assert.Equal(t, "payload_part1 payload_part2", resp.Answer[2].Data)
	})
}

func TestExecuteReverseBatchCapValidationGuardAndLookup(t *testing.T) {
	t.Parallel()

	// Exceeding MaxReverseBatchIPs (256) returns a clear error.
	tooMany := make([]string, MaxReverseBatchIPs+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("192.0.2.%d", i%250+1)
	}
	_, err := ExecuteReverseBatch(context.Background(), ReverseDNSBatchParams{
		IPs: strings.Join(tooMany, ","),
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "256")

	// Invalid IP handling returns a clear error.
	_, err = ExecuteReverseBatch(context.Background(), ReverseDNSBatchParams{
		IPs: "127.0.0.1,not-a-valid-ip",
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IP address")

	// TimeoutMS bounds validation (50..10000).
	badLow := 49
	_, err = ExecuteReverseBatch(context.Background(), ReverseDNSBatchParams{
		IPs:       "127.0.0.1",
		TimeoutMS: &badLow,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "50")

	badHigh := 10001
	_, err = ExecuteReverseBatch(context.Background(), ReverseDNSBatchParams{
		IPs:       "127.0.0.1",
		TimeoutMS: &badHigh,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "10000")

	// Guard blocks metadata IP 169.254.169.254 cleanly without crashing.
	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)
	_, err = ExecuteReverseBatch(context.Background(), ReverseDNSBatchParams{
		IPs: "169.254.169.254",
	}, &QueryConfig{Guard: guard})
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrTargetDenied)

	// Offline PTR lookup against in-process miekg/dns server.
	ptrAddr := startTestDNSServer(t, "udp", dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypePTR {
			m.Answer = append(m.Answer, &dns.PTR{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
				Ptr: "host.internal.example.",
			})
		}
		_ = w.WriteMsg(m)
	}))

	validTimeout := 500
	batchRes, err := ExecuteReverseBatch(context.Background(), ReverseDNSBatchParams{
		IPs:       "198.51.100.42",
		TimeoutMS: &validTimeout,
	}, &QueryConfig{LocalServers: []string{ptrAddr}})
	require.NoError(t, err)
	assert.Equal(t, 1, batchRes.Count)
	require.NotNil(t, batchRes.Results["198.51.100.42"])
	assert.Equal(t, "host.internal.example", *batchRes.Results["198.51.100.42"])
}
