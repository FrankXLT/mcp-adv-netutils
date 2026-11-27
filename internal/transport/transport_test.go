package transport_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPathSecret = "0123456789abcdef0123456789abcdef0123456789abcdef"

func newTestMCPServer() *server.MCPServer {
	s := server.NewMCPServer("test-netutils", "2.0.0")
	s.AddTool(mcp.NewTool("test_ping", mcp.WithDescription("test tool")),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("pong"), nil
		},
	)
	return s
}

func mcpInitBody() []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0"}}}`)
}

func newTestReq(t *testing.T, method, target, remoteAddr string, headers ...[2]string) *http.Request {
	t.Helper()
	var body io.Reader = http.NoBody
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		body = strings.NewReader("{}")
	}
	req := httptest.NewRequestWithContext(t.Context(), method, target, body)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	for _, kv := range headers {
		req.Header.Add(kv[0], kv[1])
	}
	return req
}

func TestVerifyPathToken(t *testing.T) {
	t.Parallel()

	assert.True(t, transport.VerifyPathToken("secret-token-value", "secret-token-value"))
	assert.False(t, transport.VerifyPathToken("secret-token-valuX", "secret-token-value"))
	assert.False(t, transport.VerifyPathToken("short", "secret-token-value"))
	assert.False(t, transport.VerifyPathToken("", "secret-token-value"))
	assert.False(t, transport.VerifyPathToken("secret-token-value", ""))
	assert.False(t, transport.VerifyPathToken("", ""))
}

func TestValidateLANDoorwayRequest(t *testing.T) {
	t.Parallel()

	proxyHeaders := []string{
		"X-Forwarded-For", "X-Real-IP", "Forwarded", "CF-Connecting-IP",
		"X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port",
		"X-Forwarded-Server", "X-Forwarded-Ssl", "X-Forwarded-Prefix",
		"X-Forwarded-Scheme", "X-Forwarded", "Forwarded-For",
		"True-Client-IP", "CF-Ray", "Via",
		"X-Client-IP", "X-Cluster-Client-IP", "X-Original-Forwarded-For",
	}
	for _, hdr := range proxyHeaders {
		t.Run("rejects_proxy_"+hdr, func(t *testing.T) {
			t.Parallel()
			req := newTestReq(t, http.MethodPost, "http://192.168.3.167:8000/sse", "172.18.0.10:1234", [2]string{hdr, "1.2.3.4"})
			err := transport.ValidateLANDoorwayRequest(req)
			require.ErrorIs(t, err, transport.ErrForbidden)
		})
	}

	tests := []struct {
		name      string
		req       func(t *testing.T) *http.Request
		wantAllow bool
	}{
		{"ipv4_loopback", func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://127.0.0.1:8000/sse", "127.0.0.1:54321")
		}, true},
		{"ipv6_loopback", func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://[::1]:8000/sse", "[::1]:54321")
		}, true},
		{"mapped_ipv6_and_rfc1918", func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://192.168.3.167:8000/sse", "[::ffff:192.168.3.42]:44110")
		}, true},
		{"ula_and_docker_hostname", func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://mcp-netutils:8000/sse", "[fd00::12]:4000")
		}, true},
		{"lan_suffixes_and_origin", func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://netutils.home.arpa:8000/sse", "10.0.0.25:4444", [2]string{"Origin", "http://inspector.lan:6274"})
		}, true},
		{"duplicate_host", func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://127.0.0.1:8000/sse", "127.0.0.1:1234", [2]string{"Host", "127.0.0.1:8000"}, [2]string{"Host", "evil.com"})
		}, false},
		{"duplicate_origin", func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://127.0.0.1:8000/sse", "127.0.0.1:1234", [2]string{"Origin", "http://127.0.0.1:8000"}, [2]string{"Origin", "http://localhost:8000"})
		}, false},
		{"public_remoteaddr", func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://192.168.3.167:8000/sse", "198.51.100.10:443")
		}, false},
		{"link_local_remoteaddr", func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://127.0.0.1:8000/sse", "169.254.169.254:80")
		}, false},
		{"untrusted_trailing_dot_host", func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://com.:8000/sse", "127.0.0.1:1234")
		}, false},
		{"userinfo_host", func(t *testing.T) *http.Request {
			r := newTestReq(t, http.MethodPost, "http://localhost:8000/sse", "127.0.0.1:1234")
			r.Host = "evil.com@localhost:8000"
			return r
		}, false},
		{"null_origin", func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://127.0.0.1:8000/sse", "127.0.0.1:1234", [2]string{"Origin", "null"})
		}, false},
		{"evil_origin", func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://192.168.3.167:8000/sse", "192.168.3.50:1234", [2]string{"Origin", "https://evil.com"})
		}, false},
		{"hex_ip_host_rejected", func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://0xdeadbeef:8000/sse", "127.0.0.1:1234")
		}, false},
		{"hex_ip_origin_rejected", func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://127.0.0.1:8000/sse", "127.0.0.1:1234", [2]string{"Origin", "http://0x7f000001:8000"})
		}, false},
		{"ipv6_zone_host_rejected", func(t *testing.T) *http.Request {
			r := newTestReq(t, http.MethodPost, "http://localhost:8000/sse", "127.0.0.1:1234")
			r.Host = "[::1%eth0]:8000"
			return r
		}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := transport.ValidateLANDoorwayRequest(tc.req(t))
			if tc.wantAllow {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, transport.ErrForbidden)
		})
	}
}

func TestValidateWebRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		allowedHosts []string
		req          func(t *testing.T) *http.Request
		wantAllow    bool
	}{
		{"same_origin_post_lan", nil, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://192.168.3.167:8000/web/api/run", "", [2]string{"Origin", "http://192.168.3.167:8000"}, [2]string{"Sec-Fetch-Site", "same-origin"})
		}, true},
		{"tls_reverse_proxy_allowed_host", []string{"netutils.example.com"}, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://mcp-netutils:8000/web/api/unlock", "", [2]string{"X-Forwarded-Proto", "https"}, [2]string{"X-Forwarded-Host", "netutils.example.com"}, [2]string{"Origin", "https://netutils.example.com"}, [2]string{"Sec-Fetch-Site", "same-origin"})
		}, true},
		{"cross_origin_post_rejected", nil, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://192.168.3.167:8000/web/api/run", "", [2]string{"Origin", "https://evil.example"}, [2]string{"Sec-Fetch-Site", "cross-site"})
		}, false},
		{"cross_port_localhost_rejected", nil, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://localhost:8000/web/api/run", "", [2]string{"Origin", "http://localhost:3000"})
		}, false},
		{"origin_null_rejected", nil, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://localhost:8000/web/api/run", "", [2]string{"Origin", "null"})
		}, false},
		{"dns_rebinding_get_rejected", nil, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodGet, "http://rebind.evil.com:8000/web/api/jobs", "")
		}, false},
		{"sec_fetch_same_site_delete_rejected", nil, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodDelete, "http://localhost:8000/web/api/job", "", [2]string{"Sec-Fetch-Site", "same-site"})
		}, false},
		{"cross_allowed_host_origin_xfp_https_rejected", []string{"netutils.example.com", "other.example.com"}, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://netutils.example.com/web/api/run", "", [2]string{"X-Forwarded-Proto", "https"}, [2]string{"Origin", "https://other.example.com"})
		}, false},
		{"cross_allowed_host_with_xfh_origin_rejected", []string{"netutils.example.com", "other.example.com"}, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://mcp-netutils:8000/web/api/run", "", [2]string{"X-Forwarded-Proto", "https"}, [2]string{"X-Forwarded-Host", "netutils.example.com"}, [2]string{"Origin", "https://other.example.com"})
		}, false},
		{"lan_host_xfh_spoofing_rejected", nil, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://192.168.3.167:8000/web/api/run", "192.168.3.10:1234", [2]string{"X-Forwarded-Host", "evil.lan:8000"}, [2]string{"Origin", "http://evil.lan:8000"})
		}, false},
		{"lan_host_xfh_spoofing_with_allowed_hosts_rejected", []string{"netutils.example.com"}, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://192.168.3.167:8000/web/api/run", "172.18.0.10:1234", [2]string{"X-Forwarded-Host", "evil.lan:8000"}, [2]string{"Origin", "http://evil.lan:8000"})
		}, false},
		{"untrusted_remote_xfp_https_without_xfh_rejected", nil, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://localhost/web/api/run", "", [2]string{"X-Forwarded-Proto", "https"}, [2]string{"Origin", "https://localhost"})
		}, false},
		{"private_peer_xfp_https_without_xfh_allowed", nil, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://localhost/web/api/run", "172.18.0.5:1234", [2]string{"X-Forwarded-Proto", "https"}, [2]string{"Origin", "https://localhost"})
		}, true},
		{"scheme_mismatch_https_origin_on_http_rejected", nil, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://localhost:8000/web/api/run", "127.0.0.1:1234", [2]string{"Origin", "https://localhost:8000"})
		}, false},
		{"internal_host_origin_spoof_with_xfh_rejected", []string{"netutils.example.com"}, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://mcp-netutils:8000/web/api/run", "172.18.0.5:1234", [2]string{"X-Forwarded-Proto", "https"}, [2]string{"X-Forwarded-Host", "netutils.example.com"}, [2]string{"Origin", "https://mcp-netutils:8000"})
		}, false},
		{"duplicate_xfp_rejected", []string{"netutils.example.com"}, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodPost, "http://netutils.example.com/web/api/run", "172.18.0.5:1234", [2]string{"X-Forwarded-Proto", "https"}, [2]string{"X-Forwarded-Proto", "http"}, [2]string{"Origin", "https://netutils.example.com"})
		}, false},
		{"wildcard_malformed_host_rejected", []string{"*.example.com"}, func(t *testing.T) *http.Request {
			return newTestReq(t, http.MethodGet, "http://bad..example.com/web/api/jobs", "")
		}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := transport.ValidateWebRequest(tc.req(t), tc.allowedHosts)
			if tc.wantAllow {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, transport.ErrForbidden)
		})
	}
}

func TestHTTPHandler_RemoteDoorway(t *testing.T) {
	t.Parallel()

	h, err := transport.NewHTTPHandler(transport.HTTPConfig{
		Version:    "2.0.0",
		MCPServer:  newTestMCPServer(),
		PathSecret: testPathSecret,
	})
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://remote.example.com/"+testPathSecret+"/mcp", bytes.NewReader(mcpInitBody()))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.77:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("Mcp-Session-Id"))
	assert.Contains(t, rec.Body.String(), `"serverInfo"`)

	optReq := newTestReq(t, http.MethodOptions, "https://remote.example.com/"+testPathSecret+"/mcp", "", [2]string{"Origin", "https://claude.ai"})
	optRec := httptest.NewRecorder()
	h.ServeHTTP(optRec, optReq)
	assert.Equal(t, http.StatusNoContent, optRec.Code)
	assert.Equal(t, "*", optRec.Header().Get("Access-Control-Allow-Origin"))

	badReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://remote.example.com/wrong-secret-0123456789abcdef012345/mcp", bytes.NewReader(mcpInitBody()))
	badReq.Header.Set("Content-Type", "application/json")
	badRec := httptest.NewRecorder()
	h.ServeHTTP(badRec, badReq)
	assert.Equal(t, http.StatusNotFound, badRec.Code)

	shortH, err := transport.NewHTTPHandler(transport.HTTPConfig{
		MCPServer:  newTestMCPServer(),
		PathSecret: "too-short",
	})
	require.NoError(t, err)
	shortReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/too-short/mcp", bytes.NewReader(mcpInitBody()))
	shortReq.Header.Set("Content-Type", "application/json")
	shortRec := httptest.NewRecorder()
	shortH.ServeHTTP(shortRec, shortReq)
	assert.Equal(t, http.StatusNotFound, shortRec.Code)
}

func TestHTTPHandler_LANDoorwayAndSSECompat(t *testing.T) {
	t.Parallel()

	derivedToken := transport.DeriveLANToken(testPathSecret)
	require.Len(t, derivedToken, 64)
	assert.Equal(t, derivedToken, transport.DeriveLANToken(testPathSecret))

	h, err := transport.NewHTTPHandler(transport.HTTPConfig{
		Version:         "2.0.0",
		MCPServer:       newTestMCPServer(),
		PathSecret:      testPathSecret,
		EnableSSECompat: true,
	})
	require.NoError(t, err)

	for _, targetPath := range []string{"/lan/" + derivedToken + "/mcp", "/sse"} {
		t.Run("guard_and_allow_"+targetPath, func(t *testing.T) {
			t.Parallel()

			cases := []struct {
				name       string
				remoteAddr string
				headers    [][2]string
				wantCode   int
			}{
				{"reject_xff", "192.168.3.10:12345", [][2]string{{"X-Forwarded-For", "1.2.3.4"}}, http.StatusForbidden},
				{"reject_forwarded", "192.168.3.10:12345", [][2]string{{"Forwarded", "for=198.51.100.2"}}, http.StatusForbidden},
				{"reject_proxy_net_xfh", "172.18.0.10:54321", [][2]string{{"X-Forwarded-Host", "netutils.example.com"}}, http.StatusForbidden},
				{"reject_proxy_net_xfp", "172.18.0.10:54321", [][2]string{{"X-Forwarded-Proto", "https"}}, http.StatusForbidden},
				{"reject_proxy_net_xf_server", "172.18.0.10:54321", [][2]string{{"X-Forwarded-Server", "reverse-proxy"}}, http.StatusForbidden},
				{"reject_proxy_net_via", "172.18.0.10:54321", [][2]string{{"Via", "1.1 caddy"}}, http.StatusForbidden},
				{"reject_proxy_net_x_real_ip", "172.18.0.10:54321", [][2]string{{"X-Real-IP", "203.0.113.5"}}, http.StatusForbidden},
				{"reject_public_ip", "203.0.113.20:12345", nil, http.StatusForbidden},
				{"reject_evil_origin", "192.168.3.10:12345", [][2]string{{"Origin", "https://evil.com"}}, http.StatusForbidden},
				{"reject_cross_origin_lan_host", "192.168.3.10:12345", [][2]string{{"Origin", "http://otherhost.lan:3000"}}, http.StatusForbidden},
				{"reject_scheme_spoof_origin", "192.168.3.10:12345", [][2]string{{"Origin", "https://192.168.3.167:8000"}}, http.StatusForbidden},
				{"reject_cross_port_lan_origin", "192.168.3.10:12345", [][2]string{{"Origin", "http://192.168.3.167:8001"}}, http.StatusForbidden},
				{"reject_hex_ip_lan_origin", "192.168.3.10:12345", [][2]string{{"Origin", "http://0xdeadbeef:8000"}}, http.StatusForbidden},
				{"allow_same_origin_no_cors", "192.168.3.10:12345", [][2]string{{"Origin", "http://192.168.3.167:8000"}}, http.StatusOK},
				{"allow_rfc1918", "192.168.3.10:12345", nil, http.StatusOK},
			}
			for _, tc := range cases {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://192.168.3.167:8000"+targetPath, bytes.NewReader(mcpInitBody()))
				req.RemoteAddr = tc.remoteAddr
				req.Header.Set("Content-Type", "application/json")
				for _, kv := range tc.headers {
					req.Header.Set(kv[0], kv[1])
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				assert.Equal(t, tc.wantCode, rec.Code, tc.name)
				assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"), tc.name)
				if tc.wantCode == http.StatusOK {
					assert.Contains(t, rec.Body.String(), `"serverInfo"`)
				}
			}
		})
	}

	wrongTokenReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://192.168.3.167:8000/lan/wrong-token/mcp", bytes.NewReader(mcpInitBody()))
	wrongTokenReq.RemoteAddr = "192.168.3.10:12345"
	wrongTokenReq.Header.Set("Content-Type", "application/json")
	wrongTokenRec := httptest.NewRecorder()
	h.ServeHTTP(wrongTokenRec, wrongTokenReq)
	assert.Equal(t, http.StatusNotFound, wrongTokenRec.Code)

	publicWrongReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://192.168.3.167:8000/lan/wrong-token/mcp", bytes.NewReader(mcpInitBody()))
	publicWrongReq.RemoteAddr = "198.51.100.44:12345"
	publicWrongRec := httptest.NewRecorder()
	h.ServeHTTP(publicWrongRec, publicWrongReq)
	assert.Equal(t, http.StatusForbidden, publicWrongRec.Code)

	noSSEH, err := transport.NewHTTPHandler(transport.HTTPConfig{MCPServer: newTestMCPServer()})
	require.NoError(t, err)
	sseDisabledRec := httptest.NewRecorder()
	noSSEH.ServeHTTP(sseDisabledRec, newTestReq(t, http.MethodPost, "http://127.0.0.1:8000/sse", "127.0.0.1:1234"))
	assert.Equal(t, http.StatusNotFound, sseDisabledRec.Code)
}

func TestHTTPHandler_WebAndHealthz(t *testing.T) {
	t.Parallel()

	db := security.NewDeadbolt(security.DeadboltConfig{
		PassHash: security.NormalizePhrase("correct horse battery"),
	})

	var gotWebPath string
	h, err := transport.NewHTTPHandler(transport.HTTPConfig{
		Version:   "1.2.3",
		MCPServer: newTestMCPServer(),
		Deadbolt:  db,
		WebHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotWebPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}),
		HealthProvider: func(_ context.Context) map[string]any {
			return map[string]any{"jobs_total": 42}
		},
	})
	require.NoError(t, err)

	hzRec := httptest.NewRecorder()
	h.ServeHTTP(hzRec, newTestReq(t, http.MethodGet, "/healthz", ""))
	require.Equal(t, http.StatusOK, hzRec.Code)
	assert.Equal(t, "no-store", hzRec.Header().Get("Cache-Control"))
	var hzPayload map[string]any
	require.NoError(t, json.Unmarshal(hzRec.Body.Bytes(), &hzPayload))
	assert.Equal(t, "ok", hzPayload["status"])
	assert.Equal(t, "1.2.3", hzPayload["version"])
	assert.InDelta(t, 42, hzPayload["jobs_total"], 0)

	redirRec := httptest.NewRecorder()
	h.ServeHTTP(redirRec, newTestReq(t, http.MethodGet, "http://192.168.3.167:8000/web?demo=1", ""))
	assert.Equal(t, http.StatusMovedPermanently, redirRec.Code)
	assert.Equal(t, "/web/?demo=1", redirRec.Header().Get("Location"))

	evilRec := httptest.NewRecorder()
	h.ServeHTTP(evilRec, newTestReq(t, http.MethodPost, "http://192.168.3.167:8000/web/api/run", "", [2]string{"Origin", "https://evil.example"}))
	assert.Equal(t, http.StatusForbidden, evilRec.Code)
	assert.Equal(t, "nosniff", evilRec.Header().Get("X-Content-Type-Options"))

	nullRec := httptest.NewRecorder()
	h.ServeHTTP(nullRec, newTestReq(t, http.MethodPost, "http://192.168.3.167:8000/web/api/run", "", [2]string{"Origin", "null"}))
	assert.Equal(t, http.StatusForbidden, nullRec.Code)

	okRec := httptest.NewRecorder()
	h.ServeHTTP(okRec, newTestReq(t, http.MethodPost, "http://192.168.3.167:8000/web/api/run", "", [2]string{"Origin", "http://192.168.3.167:8000"}, [2]string{"Sec-Fetch-Site", "same-origin"}))
	assert.Equal(t, http.StatusOK, okRec.Code)
	assert.Equal(t, "/api/run", gotWebPath)
	assert.Equal(t, "nosniff", okRec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "same-origin", okRec.Header().Get("Referrer-Policy"))
	assert.Equal(t, "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;", okRec.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "no-store", okRec.Header().Get("Cache-Control"))
}

func TestHTTPHandler_WebPathNormalization(t *testing.T) {
	t.Parallel()

	called := false
	h, err := transport.NewHTTPHandler(transport.HTTPConfig{
		Version:   "2.0.0",
		MCPServer: newTestMCPServer(),
		WebHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}),
	})
	require.NoError(t, err)

	cases := []struct {
		name     string
		target   string
		headers  [][2]string
		wantCode int
		wantCall bool
		noStore  bool
	}{
		{"double_slash_disallowed_host", "http://rebind.evil.com:8000/web//api/status", nil, http.StatusNotFound, false, false},
		{"dot_segment_disallowed_host", "http://rebind.evil.com:8000/web/./api/status", nil, http.StatusNotFound, false, false},
		{"double_slash_cross_origin", "http://192.168.3.167:8000/web//api/status", [][2]string{{"Origin", "https://evil.example"}, {"Sec-Fetch-Site", "cross-site"}}, http.StatusNotFound, false, false},
		{"dot_segment_cross_origin", "http://192.168.3.167:8000/web/./api/status", [][2]string{{"Origin", "https://evil.example"}, {"Sec-Fetch-Site", "cross-site"}}, http.StatusNotFound, false, false},
		{"canonical_api_disallowed_host", "http://rebind.evil.com:8000/web/api/status", nil, http.StatusForbidden, false, true},
		{"canonical_api_root_allowed", "http://192.168.3.167:8000/web/api", nil, http.StatusOK, true, true},
	}

	for _, tc := range cases {
		called = false
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newTestReq(t, http.MethodGet, tc.target, "", tc.headers...))
		assert.Equal(t, tc.wantCode, rec.Code, tc.name)
		assert.Equal(t, tc.wantCall, called, tc.name)
		if tc.noStore {
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"), tc.name)
		}
	}
}

func TestStartHTTPServer_GracefulShutdown(t *testing.T) {
	t.Parallel()

	h, err := transport.NewHTTPHandler(transport.HTTPConfig{
		Version:   "test",
		MCPServer: newTestMCPServer(),
	})
	require.NoError(t, err)

	ts := httptest.NewServer(h)
	defer ts.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/healthz", http.NoBody)
	require.NoError(t, err)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), `"status":"ok"`)

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() {
		errCh <- transport.StartHTTPServer(ctx, "127.0.0.1:0", h)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case srvErr := <-errCh:
		require.NoError(t, srvErr)
	case <-time.After(3 * time.Second):
		t.Fatal("StartHTTPServer did not shut down cleanly within deadline")
	}
}
