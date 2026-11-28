package dispatch

import (
	"bufio"
	"cmp"
	"context"
	cryptotls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/ascii"
	"github.com/FrankXLT/mcp-adv-netutils/internal/dns"
	"github.com/FrankXLT/mcp-adv-netutils/internal/http_ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/port_scan"
	"github.com/FrankXLT/mcp-adv-netutils/internal/probe"
	"github.com/FrankXLT/mcp-adv-netutils/internal/recipes"
	"github.com/FrankXLT/mcp-adv-netutils/internal/resolver"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
	"github.com/FrankXLT/mcp-adv-netutils/internal/tls"
	"github.com/FrankXLT/mcp-adv-netutils/internal/traceroute"
	"github.com/FrankXLT/mcp-adv-netutils/internal/whois"
	"github.com/FrankXLT/mcp-adv-netutils/internal/wol"
	"github.com/gosnmp/gosnmp"
	miekgdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockEnv struct {
	disp        *Dispatcher
	tlsOK       *httptest.Server
	tls503      *httptest.Server
	openTCPPort string
	snmpPort    uint16
}

func newMockEnv(t *testing.T) *mockEnv {
	t.Helper()
	ctx, st := context.Background(), openTestStore(t)
	guard, err := security.NewTargetGuard(nil, []string{"203.0.113.0/24"})
	require.NoError(t, err)

	dnsAddr, dohSrv, whoisAddr := startMockDNSUDPServer(t), startMockDoHServer(t), startMockWhoisServer(t)
	snmpPort, tlsOK, tls503 := startMockSNMPServer(t, ctx, "test-ro"), startTLSStatusServer(t, http.StatusOK), startTLSStatusServer(t, http.StatusServiceUnavailable)
	pool := x509.NewCertPool()
	pool.AddCert(tlsOK.Certificate())
	pool.AddCert(tls503.Certificate())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	d, err := New(Config{
		Version: "test", Guard: guard, Store: st,
		DNS:      &dns.QueryConfig{Timeout: 2 * time.Second, LocalServers: []string{dnsAddr}, RemoteServerAddress: dohSrv.URL + "/dns-query"},
		Whois:    &whois.Config{Timeout: 2 * time.Second, CustomServer: whoisAddr},
		Resolver: &resolver.Config{Timeout: 2 * time.Second},
		Ping:     &ping.Config{Timeout: 400 * time.Millisecond, Count: 1},
		HTTP:     &http_ping.Config{Timeout: 2 * time.Second, Count: 1, TLSConfig: &cryptotls.Config{RootCAs: pool}},
		TLS:      &tls.Config{Timeout: 2 * time.Second, RootCAs: pool},
	})
	require.NoError(t, err)
	return &mockEnv{disp: d, tlsOK: tlsOK, tls503: tls503, openTCPPort: portStr, snmpPort: snmpPort}
}

func startTLSStatusServer(t *testing.T, code int) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
	t.Cleanup(srv.Close)
	return srv
}

func mockDNSReply(r *miekgdns.Msg) *miekgdns.Msg {
	m := new(miekgdns.Msg)
	m.SetReply(r)
	if len(r.Question) == 0 {
		return m
	}
	q := r.Question[0]
	addA := func(ip string) {
		m.Answer = append(m.Answer, &miekgdns.A{Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)})
	}
	switch q.Name {
	case "nx.example.com.", "2.0.0.127.in-addr.arpa.":
		m.Rcode = miekgdns.RcodeNameError
	case "fail.example.com.":
		m.Rcode = miekgdns.RcodeServerFailure
	case "ok.example.com.", "match.example.com.", "localhost.":
		if q.Qtype == miekgdns.TypeA {
			addA("127.0.0.1")
		}
	case "split.example.com.":
		switch q.Qtype {
		case miekgdns.TypeA:
			addA("10.0.0.10")
		case miekgdns.TypeTXT:
			m.Answer = append(m.Answer, &miekgdns.TXT{Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeTXT, Class: miekgdns.ClassINET, Ttl: 60}, Txt: []string{"internal"}})
		case miekgdns.TypeMX:
			m.Answer = append(m.Answer, &miekgdns.MX{Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeMX, Class: miekgdns.ClassINET, Ttl: 60}, Preference: 10, Mx: "mail.example.com."})
		}
	case "1.0.0.127.in-addr.arpa.":
		if q.Qtype == miekgdns.TypePTR {
			m.Answer = append(m.Answer, &miekgdns.PTR{Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypePTR, Class: miekgdns.ClassINET, Ttl: 60}, Ptr: "localhost."})
		}
	}
	return m
}

func startMockDNSUDPServer(t *testing.T) string {
	t.Helper()
	started := make(chan struct{})
	srv := &miekgdns.Server{
		NotifyStartedFunc: func() { close(started) },
		Handler:           miekgdns.HandlerFunc(func(w miekgdns.ResponseWriter, r *miekgdns.Msg) { _ = w.WriteMsg(mockDNSReply(r)) }),
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	srv.PacketConn = pc
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func startMockDoHServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var wire []byte
		var err error
		if r.Method == http.MethodGet {
			wire, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		} else {
			wire, err = io.ReadAll(r.Body)
		}
		req := new(miekgdns.Msg)
		if err != nil || req.Unpack(wire) != nil {
			http.Error(w, "bad dns request", http.StatusBadRequest)
			return
		}
		reply := mockDNSReply(req)
		if len(req.Question) > 0 && req.Question[0].Name == "split.example.com." && req.Question[0].Qtype == miekgdns.TypeA {
			reply.Answer = []miekgdns.RR{&miekgdns.A{Hdr: miekgdns.RR_Header{Name: req.Question[0].Name, Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.10")}}
		}
		out, err := reply.Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func startMockWhoisServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				line, _ := bufio.NewReader(c).ReadString('\n')
				_, _ = c.Write([]byte("Domain Name: " + strings.TrimSpace(line) + "\r\nRegistrar: Mock\r\nCreation Date: 2020-01-01\r\nRegistry Expiry Date: 2030-01-01\r\nName Server: ns1.local\r\nDomain Status: ok\r\n"))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func startMockSNMPServer(t *testing.T, ctx context.Context, community string) uint16 {
	t.Helper()
	entries := []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: []byte("TestSwitch OS")},
		{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(9006100)},
		{Name: ".1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: []byte("sw-lab-01")},
		{Name: ".1.3.6.1.2.1.2.2.1.2.1", Type: gosnmp.OctetString, Value: []byte("eth0")},
		{Name: ".1.3.6.1.2.1.2.2.1.2.2", Type: gosnmp.OctetString, Value: []byte("eth1")},
		{Name: ".1.3.6.1.2.1.2.2.1.8.1", Type: gosnmp.Integer, Value: 1},
		{Name: ".1.3.6.1.2.1.2.2.1.8.2", Type: gosnmp.Integer, Value: 2},
		{Name: ".1.3.6.1.2.1.31.1.1.1.15.1", Type: gosnmp.Gauge32, Value: uint32(1000)},
	}
	sort.Slice(entries, func(i, j int) bool { return compareTestOIDs(entries[i].Name, entries[j].Name) < 0 })
	byOID := make(map[string]gosnmp.SnmpPDU, len(entries))
	for _, e := range entries {
		byOID[e.Name] = e
	}
	conn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	codec := &gosnmp.GoSNMP{Version: gosnmp.Version2c}
	go func() {
		buf := make([]byte, 8192)
		for {
			n, raddr, rErr := conn.ReadFrom(buf)
			if rErr != nil {
				return
			}
			req, dErr := codec.SnmpDecodePacket(buf[:n])
			if dErr != nil || req.Community != community {
				continue
			}
			var respVars []gosnmp.SnmpPDU
			if req.PDUType == gosnmp.GetRequest {
				for _, v := range req.Variables {
					if pdu, ok := byOID[v.Name]; ok {
						respVars = append(respVars, pdu)
					} else {
						respVars = append(respVars, gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.NoSuchObject})
					}
				}
			} else if len(req.Variables) > 0 {
				startOID, maxReps := req.Variables[0].Name, max(int(req.MaxRepetitions), 1)
				if req.PDUType == gosnmp.GetNextRequest {
					maxReps = 1
				}
				for _, pdu := range entries {
					if compareTestOIDs(pdu.Name, startOID) > 0 && len(respVars) < maxReps {
						respVars = append(respVars, pdu)
					}
				}
				if len(respVars) == 0 {
					respVars = append(respVars, gosnmp.SnmpPDU{Name: startOID, Type: gosnmp.EndOfMibView})
				}
			}
			pkt := &gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: req.Community, PDUType: gosnmp.GetResponse, RequestID: req.RequestID, Variables: respVars}
			if wire, eErr := pkt.MarshalMsg(); eErr == nil {
				_, _ = conn.WriteTo(wire, raddr)
			}
		}
	}()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

func compareTestOIDs(a, b string) int {
	pa, pb := strings.Split(strings.TrimPrefix(a, "."), "."), strings.Split(strings.TrimPrefix(b, "."), ".")
	for i := range min(len(pa), len(pb)) {
		va, _ := strconv.Atoi(pa[i])
		vb, _ := strconv.Atoi(pb[i])
		if c := cmp.Compare(va, vb); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(pa), len(pb))
}

func listenTestUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func mustHostPortNum(t *testing.T, rawURL string) int {
	t.Helper()
	_, pStr, err := net.SplitHostPort(strings.TrimPrefix(rawURL, "https://"))
	require.NoError(t, err)
	p, err := strconv.Atoi(pStr)
	require.NoError(t, err)
	return p
}

func TestDispatchCoreTools(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	env := newMockEnv(t)
	tlsPort, udpPort := mustHostPortNum(t, env.tlsOK.URL), listenTestUDPPort(t)

	for _, tc := range []struct {
		tool, wantStatus string
		args             map[string]any
	}{
		{"local_dns_query", "OK", map[string]any{"domain": "ok.example.com", "record_type": "A"}},
		{"local_dns_query", "WARN", map[string]any{"domain": "nx.example.com", "record_type": "A"}},
		{"local_dns_query", "FAIL", map[string]any{"domain": "fail.example.com", "record_type": "A"}},
		{"remote_dns_query", "OK", map[string]any{"target": "ok.example.com", "record_type": "A"}},
		{"whois_query", "OK", map[string]any{"target": "127.0.0.1"}},
		{"resolve_hostname", "OK", map[string]any{"hostname": "localhost", "ip_version": "both"}},
		{"ping", "", map[string]any{"target": "127.0.0.1", "count": 1}},
		{"traceroute", "", map[string]any{"target": "127.0.0.1", "max_hops": 2, "timeout_seconds": 1}},
		{"dns_reverse_batch", "OK", map[string]any{"ips": "127.0.0.1, 127.0.0.2", "timeout_ms": 500}},
		{"dns_reverse_batch", "WARN", map[string]any{"ips": "127.0.0.2"}},
		{"wol_wake", "OK", map[string]any{"mac": "aa:bb:cc:dd:ee:ff", "broadcast_ip": "127.0.0.1", "port": udpPort}},
	} {
		out, err := env.disp.Dispatch(ctx, Request{Tool: tc.tool, Args: tc.args})
		if tc.tool == "traceroute" && errors.Is(err, exec.ErrNotFound) {
			continue
		}
		require.NoError(t, err, tc.tool)
		if tc.wantStatus != "" {
			assert.Equal(t, tc.wantStatus, out.Status, tc.tool)
		}
		assertASCIIWidths(t, out)
	}

	for _, tc := range []struct {
		sni       string
		wantValid bool
	}{{"", true}, {"mismatch.invalid", false}} {
		out, err := env.disp.Dispatch(ctx, Request{Tool: "tls_certificate_check", Args: map[string]any{"domain": "127.0.0.1", "port": tlsPort, "server_name": tc.sni, "include_chain": true, "check_expiry": true}})
		require.NoError(t, err)
		assert.Equal(t, tc.wantValid, out.Data.(*tls.CheckResult).ChainValid)
		require.NotNil(t, out.TLSHealth)
		assert.Equal(t, tc.wantValid, out.TLSHealth.Valid)
		assert.Equal(t, tc.wantValid, out.TLSHealth.HostnameMatch)
		assert.NotEmpty(t, out.TLSHealth.Protocol)
		assertASCIIWidths(t, out)
		rep, err := env.disp.GetJobReport(ctx, out.JobID, ascii.StyleDefault)
		require.NoError(t, err)
		require.NotNil(t, rep.TLSHealth)
		assert.Equal(t, out.TLSHealth.Valid, rep.TLSHealth.Valid)
	}

	for _, errReq := range []Request{
		{Tool: "local_dns_query", Args: map[string]any{"domain": ""}}, {Tool: "remote_dns_query", Args: map[string]any{"domain": "-bad"}},
		{Tool: "whois_query", Args: map[string]any{"domain": "169.254.169.254"}}, {Tool: "resolve_hostname", Args: map[string]any{"hostname": "localhost", "ip_version": "v9"}},
		{Tool: "tls_certificate_check", Args: map[string]any{"domain": "127.0.0.1", "port": "bad"}}, {Tool: "http_ping", Args: map[string]any{"url": env.tlsOK.URL, "count": "bad"}},
		{Tool: "tcp_port_scan", Args: map[string]any{"target": "127.0.0.1", "timeout_ms": "bad"}}, {Tool: "ping", Args: map[string]any{"target": "169.254.169.254"}},
		{Tool: "traceroute", Args: map[string]any{"target": "-bad"}}, {Tool: "traceroute", Args: map[string]any{"target": "127.0.0.1", "max_hops": "bad"}},
		{Tool: "dns_reverse_batch", Args: map[string]any{"ips": "not-an-ip"}}, {Tool: "dns_reverse_batch", Args: map[string]any{"ips": "127.0.0.1", "timeout_ms": "bad"}},
		{Tool: "wol_wake", Args: map[string]any{"mac": "invalid"}}, {Tool: "wol_wake", Args: map[string]any{"mac": "aa:bb:cc:dd:ee:ff", "port": "bad"}},
	} {
		_, err := env.disp.Dispatch(ctx, errReq)
		require.Error(t, err, errReq.Tool)
	}
}

func TestDispatchProbeAndRecipeTools(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	env := newMockEnv(t)
	udpPort := listenTestUDPPort(t)

	if discOut, discErr := env.disp.Dispatch(ctx, Request{Tool: "mdns_ssdp_discover", Args: map[string]any{"protocol": "ssdp", "timeout_ms": 500, "max_results": 5}}); discErr == nil {
		assertASCIIWidths(t, discOut)
	}
	for _, req := range []Request{
		{Tool: "arp_neighbor_sweep", Args: map[string]any{"active_probe": false, "resolve_ptr": false}},
		{Tool: "mtu_path_probe", Args: map[string]any{"target": "127.0.0.1", "min_mtu": 1280, "max_mtu": 1500, "protocol": "udp"}},
		{Tool: "mtr_path_quality", Args: map[string]any{"target": "127.0.0.1", "max_hops": 2, "cycles": 1, "timeout_ms": 200}},
		{Tool: "split_dns_audit", Args: map[string]any{"domain": "split.example.com", "record_types": []any{"A", "TXT", "MX"}}},
		{Tool: "snmp_switch_port", Args: map[string]any{"target": "127.0.0.1", "port": int(env.snmpPort), "version": "2c", "community": "test-ro", "mode": "all", "max_entries": 10}},
		{Tool: "recipe_diff_ping", Args: map[string]any{"target": "127.0.0.1", "gateway": "127.0.0.1", "canary": "127.0.0.1", "count": 1}},
		{Tool: "recipe_diff_dns", Args: map[string]any{"domain": "localhost", "record_types": "A"}},
		{Tool: "recipe_diff_http", Args: map[string]any{"url": env.tlsOK.URL, "compare_urls": []string{env.tls503.URL}, "count": 1}},
		{Tool: "recipe_diff_snapshot", Args: map[string]any{"baseline": "snap-1", "save_as": "snap-1"}},
		{Tool: "recipe_diff_snapshot", Args: map[string]any{"baseline": "snap-1", "save_as": "snap-1"}},
		{Tool: "recipe_host_card", Args: map[string]any{"target": "127.0.0.1", "port_preset": env.openTCPPort, "check_snmp": true, "snmp_params": map[string]any{"target": "127.0.0.1", "port": int(env.snmpPort), "version": "2c", "community": "test-ro"}}},
		{Tool: "recipe_lan_radar", Args: map[string]any{"discover_services": false}},
		{Tool: "recipe_path_autopsy", Args: map[string]any{"target": "127.0.0.1", "max_hops": 1, "cycles": 1}},
		{Tool: "recipe_wake_verify", Args: map[string]any{"mac": "aa:bb:cc:dd:ee:ff", "target": "127.0.0.1", "broadcast_ip": "127.0.0.1", "port": udpPort, "wait_seconds": 2, "ports": env.openTCPPort}},
	} {
		out, err := env.disp.Dispatch(ctx, req)
		require.NoError(t, err, req.Tool)
		assertASCIIWidths(t, out)
		if req.Tool == "split_dns_audit" || req.Tool == "recipe_diff_dns" {
			assert.NotEmpty(t, out.DNSComparisons, req.Tool)
		}
		if req.Tool == "recipe_diff_http" {
			require.NotNil(t, out.TLSHealth)
			assert.True(t, out.TLSHealth.Valid)
		}
	}
	for _, errReq := range []Request{
		{Tool: "arp_neighbor_sweep", Args: map[string]any{"active_probe": "bad"}}, {Tool: "mtu_path_probe", Args: map[string]any{"target": "127.0.0.1", "min_mtu": "bad"}},
		{Tool: "mtr_path_quality", Args: map[string]any{"target": "127.0.0.1", "cycles": "bad"}}, {Tool: "mdns_ssdp_discover", Args: map[string]any{"protocol": "ssdp", "timeout_ms": "bad"}},
		{Tool: "split_dns_audit", Args: map[string]any{"domain": "localhost", "record_types": []any{123}}}, {Tool: "snmp_switch_port", Args: map[string]any{"target": "127.0.0.1", "port": 70000}},
		{Tool: "snmp_switch_port", Args: map[string]any{"target": "127.0.0.1", "port": "bad"}}, {Tool: "recipe_host_card", Args: map[string]any{"target": "127.0.0.1", "snmp_params": "bad"}},
		{Tool: "recipe_host_card", Args: map[string]any{"target": "127.0.0.1", "snmp_params": map[string]any{"port": 70000}}},
	} {
		_, err := env.disp.Dispatch(ctx, errReq)
		require.Error(t, err, errReq.Tool)
	}
}

func TestSyntheticExtractorsBuildersAndArgReader(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()

	dp := buildRecipeExec("recipe_diff_ping", &recipes.RecipeResult{Status: "WARN", Card: &ascii.ReportCard{Title: "DP", Target: "10.0.0.1"}, Data: recipes.DiffPingData{Hops: []recipes.DiffPingHop{{Stage: "GW", Address: "192.168.1.1", AvgRTTMs: 1.5}, {Stage: "T", Address: "10.0.0.1", AvgRTTMs: 5, LossPct: 25}}}}, "10.0.0.1", 12, now)
	require.Len(t, dp.Whiskers, 2)
	assert.Nil(t, dp.Waterfall)
	assert.Equal(t, []string{"GW", "192.168.1.1"}, []string{dp.Whiskers[0].Segment, dp.Whiskers[0].Hostname})
	validTrue, expDays := true, 45
	dh := buildRecipeExec("recipe_diff_http", &recipes.RecipeResult{Data: recipes.DiffHTTPData{Endpoints: []recipes.DiffHTTPEndpoint{{URL: "https://a.example:8443/p", DNSMs: 1, TCPMs: 2, TLSMs: 3, TTFBMs: 4, TotalMs: 10, ChainValid: &validTrue, ExpiresDays: &expDays, Issuer: "CN=R11,O=Let's Encrypt,C=US", TLSVersion: "TLSv1.3", CipherSuite: "TLS_AES_256_GCM_SHA384", NotAfter: "2027-02-08T00:00:00Z"}}}}, "https://a", 10, now)
	require.Len(t, dh.Waterfall, 5)
	assert.Equal(t, []string{"DNS Lookup", "TCP Connect", "TLS Handshake", "First Byte", "Total"}, []string{dh.Waterfall[0].Label, dh.Waterfall[1].Label, dh.Waterfall[2].Label, dh.Waterfall[3].Label, dh.Waterfall[4].Label})
	require.NotNil(t, dh.TLSHealth)
	assert.Equal(t, "a.example", dh.TLSHealth.Subject)
	assert.Equal(t, "Let's Encrypt (R11)", dh.TLSHealth.Issuer)
	assert.Equal(t, "TLSv1.3", dh.TLSHealth.Protocol)
	assert.Equal(t, "TLS_AES_256_GCM_SHA384", dh.TLSHealth.Cipher)
	assert.Equal(t, "2027-02-08T00:00:00Z", dh.TLSHealth.NotAfter)
	assert.Equal(t, 45, dh.TLSHealth.DaysRemaining)
	dd := buildRecipeExec("recipe_diff_dns", &recipes.RecipeResult{Data: recipes.DiffDNSData{Comparisons: []probe.SplitDNSComparison{{RecordType: "A", Status: "MATCH", LocalAnswers: []string{"1.1.1.1"}, RemoteAnswers: []string{"1.1.1.1"}}}}}, "example.com", 5, now)
	require.Len(t, dd.DNSComparisons, 2)
	assert.True(t, dd.DNSComparisons[0].Match && dd.DNSComparisons[1].Match)
	ds := buildRecipeExec("recipe_diff_snapshot", &recipes.RecipeResult{Data: recipes.DiffSnapshotData{Baseline: "b1", Diffs: []recipes.DiffSnapshotEntry{{DiffType: "[+] ADDED", IP: "10.0.0.2"}, {DiffType: "[-] REMOVED", IP: "10.0.0.3"}, {DiffType: "[~] CHANGED", IP: "10.0.0.4"}}}}, "b1", 5, now)
	assert.Equal(t, []int{1, 1, 1}, []int{len(ds.SnapshotDiff.Added), len(ds.SnapshotDiff.Removed), len(ds.SnapshotDiff.Changed)})
	hc := buildRecipeExec("recipe_host_card", &recipes.RecipeResult{Data: recipes.HostCardData{Target: "nas", DNS: &resolver.ResolverResponse{IPv4Addresses: []string{"10.0.0.5"}}, Ping: &ping.PingResponse{MinRTT: 1, AvgRTT: 2, MaxRTT: 3}, TLS: &tls.CheckResult{ChainValid: true, TLSVersion: "TLSv1.3", PeerCertificates: []tls.CertificateInfo{{Subject: "nas", Issuer: "CN=R11,O=Let's Encrypt,C=US", ExpiresInDays: 60}}}, HTTP: &http_ping.HTTPPingResponse{AvgDNSTime: 1, AvgConnTime: 2, AvgTLSTime: 3, AvgTTFBTime: 4, AvgTotalTime: 10}}}, "nas", 5, now)
	assert.Len(t, hc.Whiskers, 1)
	assert.Len(t, hc.Waterfall, 5)
	require.NotNil(t, hc.TLSHealth)
	assert.Equal(t, "TLSv1.3", hc.TLSHealth.Protocol)
	assert.Equal(t, "Let's Encrypt (R11)", hc.TLSHealth.Issuer)
	require.Len(t, hc.DNSComparisons, 1)
	assert.Equal(t, []string{"10.0.0.5"}, hc.DNSComparisons[0].Answers)
	lr := buildRecipeExec("recipe_lan_radar", &recipes.RecipeResult{Data: recipes.LANRadarData{PhysicalUAA: []probe.ARPNeighbor{{IP: "192.168.1.2", MAC: "9C:8E:CD:0A:91:0C"}}, VirtualLAA: []probe.ARPNeighbor{{IP: "172.17.0.2", MAC: "02:42:ac:11:00:02", IsLAA: true}}}}, "lan", 5, now)
	assert.Equal(t, []int{1, 1}, []int{len(lr.LANInventory.Physical), len(lr.LANInventory.Virtual)})
	assert.Equal(t, "Virtual MAC (Docker / VM)", lr.LANInventory.Virtual[0].Runtime)
	assert.Equal(t, "Let's Encrypt (R11)", formatCertIssuer("CN=R11,O=Let's Encrypt,C=US"))
	assert.Equal(t, "Example, Inc. (Root CA)", formatCertIssuer(`O=Example\, Inc.,CN=Root CA`))
	assert.Equal(t, "Google Trust Services", formatCertIssuer("O=Google Trust Services,C=US"))
	assert.Equal(t, "GlobalSign Root CA", formatCertIssuer("CN=GlobalSign Root CA,C=BE"))
	assert.Equal(t, "ACME Corp", formatCertIssuer("O=ACME Corp,CN=acme corp"))
	assert.Equal(t, "C=US", formatCertIssuer(" C=US "))
	assert.Equal(t, "", formatCertIssuer("   "))
	paMTR := buildRecipeExec("recipe_path_autopsy", &recipes.RecipeResult{Data: recipes.PathAutopsyData{
		MTR:        &probe.MTRResult{Reached: true, Hops: []probe.MTRHop{{Hop: 1, IP: "*", Segment: "Transit", Silent: true}, {Hop: 2, IP: "10.0.0.1", Hostname: "edge.lan", Segment: "Destination", BestMs: 1, AvgMs: 2, WorstMs: 3}}},
		Traceroute: &traceroute.TracerouteResponse{ReachedDestination: true, Hops: []traceroute.HopResult{{Hop: 1, IP: "10.0.0.9"}}},
	}}, "10.0.0.1", 5, now)
	require.Len(t, paMTR.Whiskers, 2)
	assert.True(t, paMTR.Whiskers[0].Silent)
	assert.Equal(t, []string{"Destination", "edge.lan"}, []string{paMTR.Whiskers[1].Segment, paMTR.Whiskers[1].Hostname})
	paTR := extractPathAutopsyWhiskers(&recipes.PathAutopsyData{
		MTR:        &probe.MTRResult{Reached: false},
		Traceroute: &traceroute.TracerouteResponse{ReachedDestination: true, DestLossPct: 25, Hops: []traceroute.HopResult{{Hop: 1, IP: "*", Segment: "Transit", Silent: true, TimedOut: true}, {Hop: 2, IP: "1.1.1.1", Hostname: "one.one", Segment: "Destination", RTTMs: []float64{2, 8, 4}, AvgRTTMs: 4.6}}},
	})
	require.Len(t, paTR, 2)
	assert.True(t, paTR[0].Silent)
	assert.Equal(t, "Transit", paTR[0].Segment)
	assert.Equal(t, []float64{100, 25, 2, 8}, []float64{paTR[0].LossPct, paTR[1].LossPct, paTR[1].MinMs, paTR[1].MaxMs})
	assert.Equal(t, []string{"Destination", "one.one"}, []string{paTR[1].Segment, paTR[1].Hostname})
	paKeepMTR := extractPathAutopsyWhiskers(&recipes.PathAutopsyData{
		MTR:        &probe.MTRResult{Reached: false, Hops: []probe.MTRHop{{Hop: 1, IP: "10.0.0.1", LossPct: 100}}},
		Traceroute: &traceroute.TracerouteResponse{ReachedDestination: false, Hops: []traceroute.HopResult{{Hop: 1, IP: "*", TimedOut: true}, {Hop: 2, IP: "*", TimedOut: true}}},
	})
	require.Len(t, paKeepMTR, 1)
	assert.Equal(t, "Hop 1 (10.0.0.1)", paKeepMTR[0].Label)
	assert.Nil(t, extractPathAutopsyWhiskers(&recipes.PathAutopsyData{}))
	lo, hi := minMaxFloat(nil, 3.5)
	assert.Equal(t, []float64{3.5, 3.5}, []float64{lo, hi})
	require.Len(t, buildRecipeExec("recipe_wake_verify", &recipes.RecipeResult{Data: recipes.WakeVerifyData{WakeToReadyM: 420}}, "nas", 5, now).Waterfall, 1)

	mtrCoPP := buildMTRExec(&probe.MTRResult{Target: "1.1.1.1", ProbeMode: "tcp_443", Reached: true, SilentTransitHops: 1, DestLossPct: 0, Hops: []probe.MTRHop{{Hop: 1, IP: "*", Segment: "Transit", Silent: true, LossPct: 100}, {Hop: 2, IP: "1.1.1.1", Hostname: "one.one", Segment: "Destination", BestMs: 2, AvgMs: 3, WorstMs: 4}}}, 1)
	assert.Equal(t, statusOK, mtrCoPP.Status)
	assert.Equal(t, statusINFO, mtrCoPP.Card.Rows[0].Status)
	assert.True(t, mtrCoPP.Whiskers[0].Silent)
	trCoPP := buildTracerouteExec(&traceroute.TracerouteResponse{Target: "1.1.1.1", ProbeMode: "tcp_443", ReachedDestination: true, SilentTransitHops: 1, DestLossPct: 25, Hops: []traceroute.HopResult{{Hop: 1, IP: "*", Segment: "Transit", Silent: true, TimedOut: true}, {Hop: 2, IP: "1.1.1.1", Hostname: "one.one", Segment: "Destination", RTTMs: []float64{3, 5}, AvgRTTMs: 4}}}, 1)
	assert.Equal(t, statusWARN, trCoPP.Status)
	assert.Equal(t, statusINFO, trCoPP.Card.Rows[0].Status)
	assert.Equal(t, statusWARN, trCoPP.Card.Rows[1].Status)
	assert.Equal(t, float64(25), trCoPP.Whiskers[1].LossPct)
	assert.True(t, trCoPP.Whiskers[0].Silent)
	assert.Equal(t, []string{"Destination", "one.one"}, []string{trCoPP.Whiskers[1].Segment, trCoPP.Whiskers[1].Hostname})

	for _, tc := range []struct {
		want string
		exec *toolExec
	}{
		{statusFAIL, buildPingExec(&ping.PingResponse{Target: "t", PacketsSent: 1, Results: []ping.PingResult{{Sequence: 1}}}, 1)},
		{statusWARN, buildPingExec(&ping.PingResponse{Target: "t", PacketsSent: 2, PacketsReceived: 1, PacketLoss: 50, Results: []ping.PingResult{{Sequence: 1, Success: true}, {Sequence: 2}}}, 1)},
		{statusFAIL, buildTracerouteExec(&traceroute.TracerouteResponse{Target: "t"}, 1)},
		{statusFAIL, buildTracerouteExec(&traceroute.TracerouteResponse{Target: "t", Hops: []traceroute.HopResult{{Hop: 1, IP: "*", TimedOut: true}}}, 1)},
		{statusFAIL, buildResolverExec(&resolver.ResolverResponse{Hostname: "bad", Failed: true, Error: "nx"}, 1)},
		{statusOK, buildTLSExec(&tls.CheckResult{Domain: "a", ChainValid: true, PeerCertificates: []tls.CertificateInfo{{Subject: "a", ExpiresInDays: 90}}}, 1)},
		{statusFAIL, buildTLSExec(&tls.CheckResult{Domain: "a", PeerCertificates: []tls.CertificateInfo{{Subject: "a", IsExpired: true}}}, 1)},
		{statusWARN, buildTLSExec(&tls.CheckResult{Domain: "a", ChainValid: true, PeerCertificates: []tls.CertificateInfo{{Subject: "a", ExpiresInDays: 5}}}, 1)},
		{statusWARN, buildPortScanExec(&port_scan.PortScanResponse{Target: "a", Ports: []port_scan.PortResult{{Port: 80, State: "filtered"}}}, 1)},
		{statusFAIL, buildWOLExec(&wol.WOLResponse{Normalized: "AA:BB:CC:DD:EE:FF", Message: "err"}, 1)},
		{statusWARN, buildWhoisExec(&whois.WhoisResponse{Domain: "a"}, 1)},
		{statusOK, buildWhoisExec(&whois.WhoisResponse{Domain: "a", Result: strings.Repeat("Registrar: X\n", 10)}, 1)},
		{statusOK, buildARPSweepExec(&probe.ARPSweepResult{PhysicalCount: 1, VirtualCount: 1, Neighbors: []probe.ARPNeighbor{{IP: "192.168.1.2", MAC: "9C:8E:CD:0A:91:0C"}, {IP: "172.17.0.2", MAC: "02:42:ac:11:00:02", IsLAA: true}}}, 1)},
		{statusFAIL, buildMTUProbeExec(&probe.MTUProbeResult{Target: "a", BlackholeDetected: true, Steps: []probe.MTUStep{{WireMTU: 1500}}}, 1)},
		{statusFAIL, buildMTRExec(&probe.MTRResult{Target: "a"}, 1)},
		{statusFAIL, buildMTRExec(&probe.MTRResult{Target: "a", Reached: true, DestLossPct: 60, Hops: []probe.MTRHop{{Hop: 1, IP: "1.1.1.1", LossPct: 60}, {Hop: 2, IP: "1.1.1.2", StDevMs: 25}}}, 1)},
		{statusWARN, buildMTRExec(&probe.MTRResult{Target: "a", Reached: true, DestLossPct: 25, Hops: []probe.MTRHop{{Hop: 1, IP: "1.1.1.1", LossPct: 25}}}, 1)},
		{statusWARN, buildDiscoverExec(&probe.DiscoverResult{Protocol: "both", Warnings: []string{"w"}}, 1)},
		{statusOK, buildDiscoverExec(&probe.DiscoverResult{Protocol: "ssdp", Count: 1, Services: []probe.DiscoveredService{{Protocol: "ssdp", IP: "127.0.0.1", Port: 8080, Name: "d"}}}, 1)},
		{statusFAIL, buildSplitDNSExec(&probe.SplitDNSResult{Domain: "a", OverallStatus: "ERROR", Comparisons: []probe.SplitDNSComparison{{RecordType: "A", Status: "ERROR", LocalErr: "x", RemoteErr: "y"}}}, 1)},
		{statusWARN, buildSplitDNSExec(&probe.SplitDNSResult{Domain: "a", SplitDetected: true, Comparisons: []probe.SplitDNSComparison{{RecordType: "A", Status: "SPLIT-LOCAL"}}}, 1)},
	} {
		assert.Equal(t, tc.want, tc.exec.Status)
	}

	r := &argReader{m: map[string]any{"i64": int64(3), "f": float64(4), "f_bad": 1.5, "jn": json.Number("7"), "jn_bad": json.Number("x"), "s0": " ", "s1": "9", "s_bad": "z", "b": true, "bs": "true", "b_bad": "maybe", "sl": []string{"a", " "}, "sl_bad": []any{1}, "bad_t": 9}}
	assert.Equal(t, []int{3, 4, 7, 9}, []int{r.i("i64"), r.i("f"), r.i("jn"), r.i("s0", "s1")})
	assert.True(t, r.b("b") && r.b("s0", "bs"))
	assert.Equal(t, []string{"a"}, r.strs("sl"))
	for _, fn := range []func(){func() { _ = r.i("f_bad") }, func() { _ = r.i("jn_bad") }, func() { _ = r.i("s_bad") }, func() { _ = r.i("b") }, func() { _ = r.b("b_bad") }, func() { _ = r.b("bad_t") }, func() { _ = r.strs("sl_bad") }, func() { _ = r.strs("bad_t") }} {
		r.err = nil
		fn()
		require.Error(t, r.err)
	}

	out, err := finalizeOutcome("ping", ascii.StyleDefault, &toolExec{Target: "t", Status: "OK", Summary: "s", Data: map[string]any{"k": 1}, TLSHealth: &TLSHealthView{Valid: true, Subject: "t"}, DNSComparisons: []DNSComparisonRow{{Resolver: "Local", Status: "MATCH", Match: true}}}, now, 0, 0, "j1", now.Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, "j1", out.JobID)
	envJSON, err := encodePayloadEnvelope(out)
	require.NoError(t, err)
	hydrated, err := outcomeFromJobRecord(&store.JobRecord{JobID: "j1", ToolName: "ping", Target: "t", Status: "OK", PayloadJSON: envJSON}, ascii.StyleDefault)
	require.NoError(t, err)
	require.NotNil(t, hydrated.TLSHealth)
	assert.Equal(t, "t", hydrated.TLSHealth.Subject)
	require.Len(t, hydrated.DNSComparisons, 1)
	dNoStore, err := New(Config{})
	require.NoError(t, err)
	canceledCtx, cancelFn := context.WithCancel(context.Background())
	cancelFn()
	//nolint:staticcheck // intentionally testing nil context defense
	_, err = dNoStore.Dispatch(nil, Request{Tool: "ping"})
	require.Error(t, err)
	_, err = dNoStore.Dispatch(canceledCtx, Request{Tool: "ping"})
	require.Error(t, err)
	//nolint:staticcheck // intentionally testing nil context defense
	_, err = dNoStore.GetJobReport(nil, "j1", "default")
	require.Error(t, err)
	_, err = dNoStore.GetJobReport(context.Background(), "j1", "default")
	require.Error(t, err)
	_, err = newMockEnv(t).disp.GetJobReport(context.Background(), "nonexistent", "default")
	require.Error(t, err)
	recOut, err := outcomeFromJobRecord(&store.JobRecord{JobID: "j2", ToolName: "ping", Target: "1.1.1.1", Status: "OK", PayloadJSON: `{"legacy":true}`}, ascii.StyleDefault)
	require.NoError(t, err)
	assert.Equal(t, "j2", recOut.JobID)
}
