package recipes

import (
	"context"
	cryptotls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/ascii"
	"github.com/FrankXLT/mcp-adv-netutils/internal/dns"
	"github.com/FrankXLT/mcp-adv-netutils/internal/http_ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/probe"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/store"
	"github.com/FrankXLT/mcp-adv-netutils/internal/tls"
	miekgdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecuteDiffPingAndTCPRSTDiagnosis(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	openPort := ln.Addr().(*net.TCPAddr).Port

	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	require.NoError(t, closedLn.Close())

	checks := probeTCPReachability(ctx, net.ParseIP("127.0.0.1"), []int{openPort, closedPort})
	require.Len(t, checks, 2)
	assert.Equal(t, "SYN-ACK", checks[0].State)
	assert.Equal(t, "RST", checks[1].State)

	diag, st := diagnoseDiffPing([]DiffPingHop{
		{Stage: "[1] NIC/Loopback", Status: StatusOK},
		{Stage: "[5] Target", Status: StatusFAIL},
	}, checks)
	assert.Equal(t, StatusWARN, st)
	assert.Contains(t, diag, "TCP RST/SYN-ACK proves bidirectional L3 routing")

	okDiag, okSt := diagnoseDiffPing([]DiffPingHop{
		{Stage: "[1] NIC/Loopback", Status: StatusOK},
		{Stage: "[5] Target", Status: StatusOK},
	}, checks)
	assert.Equal(t, StatusOK, okSt)
	assert.Contains(t, okDiag, "healthy")

	res, err := ExecuteDiffPing(ctx, Dependencies{}, DiffPingParams{
		Target: "127.0.0.1", Gateway: "127.0.0.1", Canary: "127.0.0.1", Count: 1,
	})
	require.NoError(t, err)
	assert.Contains(t, []string{StatusOK, StatusWARN}, res.Status)
	if res.Status == StatusWARN {
		assert.Contains(t, res.Summary, "TCP RST/SYN-ACK proves bidirectional L3 routing")
	}
	require.NotNil(t, res.Card)
	assert.NotEmpty(t, res.Card.Rows)
	assert.NotEmpty(t, res.Card.SparkValues)
}

func TestExecuteDiffDNS(t *testing.T) {
	t.Parallel()
	localAddr := startTestUDPServer(t, miekgdns.HandlerFunc(func(w miekgdns.ResponseWriter, r *miekgdns.Msg) {
		m := new(miekgdns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			q := r.Question[0]
			switch q.Name {
			case "match.example.com.":
				if q.Qtype == miekgdns.TypeA {
					m.Answer = append(m.Answer, &miekgdns.A{Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 60}, A: net.ParseIP("93.184.216.34")})
				}
			case "split.example.com.":
				if q.Qtype == miekgdns.TypeA {
					m.Answer = append(m.Answer, &miekgdns.A{Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 60}, A: net.ParseIP("10.0.0.10")})
				} else if q.Qtype == miekgdns.TypeTXT {
					m.Answer = append(m.Answer, &miekgdns.TXT{Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeTXT, Class: miekgdns.ClassINET, Ttl: 60}, Txt: []string{"internal"}})
				}
			}
		}
		_ = w.WriteMsg(m)
	}))

	dohSrv := startTestDoHServer(t, func(r *miekgdns.Msg) *miekgdns.Msg {
		m := new(miekgdns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			q := r.Question[0]
			switch q.Name {
			case "match.example.com.":
				if q.Qtype == miekgdns.TypeA {
					m.Answer = append(m.Answer, &miekgdns.A{Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 60}, A: net.ParseIP("93.184.216.34")})
				}
			case "split.example.com.":
				if q.Qtype == miekgdns.TypeA {
					m.Answer = append(m.Answer, &miekgdns.A{Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.10")})
				} else if q.Qtype == miekgdns.TypeMX {
					m.Answer = append(m.Answer, &miekgdns.MX{Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeMX, Class: miekgdns.ClassINET, Ttl: 60}, Preference: 10, Mx: "mail.example.com."})
				}
			}
		}
		return m
	})

	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)
	deps := Dependencies{
		Guard: guard,
		DNS:   &dns.QueryConfig{Timeout: 2 * time.Second, LocalServers: []string{localAddr}, RemoteServerAddress: dohSrv.URL + "/dns-query", Guard: guard},
	}

	ctx := context.Background()
	matchRes, err := ExecuteDiffDNS(ctx, deps, DiffDNSParams{Domain: "match.example.com", RecordTypes: []string{"A"}})
	require.NoError(t, err)
	assert.Equal(t, StatusOK, matchRes.Status)

	splitRes, err := ExecuteDiffDNS(ctx, deps, DiffDNSParams{Domain: "split.example.com", RecordTypes: []string{"A", "TXT", "MX"}})
	require.NoError(t, err)
	assert.Equal(t, StatusWARN, splitRes.Status)
	data, ok := splitRes.Data.(DiffDNSData)
	require.True(t, ok)
	assert.True(t, data.SplitDetected)
	require.Len(t, data.Comparisons, 3)
	assert.Equal(t, "SPLIT-LOCAL", data.Comparisons[0].Status)
	assert.Equal(t, "LOCAL-ONLY", data.Comparisons[1].Status)
	assert.Equal(t, "PUBLIC-ONLY", data.Comparisons[2].Status)
}

func TestExecuteDiffHTTP(t *testing.T) {
	t.Parallel()
	srvOK := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srvOK.Close()

	srvFail := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srvFail.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srvOK.Certificate())
	pool.AddCert(srvFail.Certificate())

	deps := Dependencies{
		HTTP: &http_ping.Config{Timeout: 3 * time.Second, TLSConfig: &cryptotls.Config{RootCAs: pool}},
		TLS:  &tls.Config{Timeout: 3 * time.Second, RootCAs: pool},
	}
	res, err := ExecuteDiffHTTP(context.Background(), deps, DiffHTTPParams{URL: srvOK.URL, CompareURLs: []string{srvFail.URL}, Count: 1})
	require.NoError(t, err)
	assert.Equal(t, StatusFAIL, res.Status)
	data, ok := res.Data.(DiffHTTPData)
	require.True(t, ok)
	require.Len(t, data.Endpoints, 2)
	assert.Equal(t, http.StatusOK, data.Endpoints[0].StatusCode)
	assert.Equal(t, StatusOK, data.Endpoints[0].Status)
	require.NotNil(t, data.Endpoints[0].ChainValid)
	assert.True(t, *data.Endpoints[0].ChainValid)
	assert.Equal(t, http.StatusServiceUnavailable, data.Endpoints[1].StatusCode)
	assert.Equal(t, StatusFAIL, data.Endpoints[1].Status)
	assert.Len(t, res.Card.Rows, 2)
	assert.Len(t, res.SparkValues, 2)
}

func TestExecuteDiffSnapshot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "snap.db"), 10)
	require.NoError(t, err)
	defer func() { _ = st.Close() }()

	deps := Dependencies{Store: st}
	firstRes, err := ExecuteDiffSnapshot(ctx, deps, DiffSnapshotParams{Baseline: "base1"})
	require.NoError(t, err)
	assert.Equal(t, StatusOK, firstRes.Status)
	firstData, ok := firstRes.Data.(DiffSnapshotData)
	require.True(t, ok)
	assert.True(t, firstData.IsFirstRun)

	// Verify synthetic diff tags and that Card.Rows shows ONLY diff rows.
	diffs, added, removed, changed := computeARPSnapshotDiff(
		[]probe.ARPNeighbor{
			{IP: "192.168.1.1", MAC: "AA:BB:CC:00:00:01", Vendor: "V1", Interface: "eth0"},
			{IP: "192.168.1.2", MAC: "AA:BB:CC:00:00:02", Vendor: "V2", Interface: "eth0"},
		},
		[]probe.ARPNeighbor{
			{IP: "192.168.1.1", MAC: "AA:BB:CC:00:00:99", Vendor: "V1", Interface: "eth0"},
			{IP: "192.168.1.3", MAC: "AA:BB:CC:00:00:03", Vendor: "V3", Interface: "eth0"},
		},
	)
	assert.Equal(t, 1, added)
	assert.Equal(t, 1, removed)
	assert.Equal(t, 1, changed)
	require.Len(t, diffs, 3)

	// Seed baseline with a ghost IP so ExecuteDiffSnapshot produces only diff rows in Card.
	snap, err := st.GetSnapshot(ctx, "base1")
	require.NoError(t, err)
	var baseSweep probe.ARPSweepResult
	require.NoError(t, json.Unmarshal([]byte(snap.PayloadJSON), &baseSweep))
	if len(baseSweep.Neighbors) > 0 {
		baseSweep.Neighbors[0].MAC = "00:11:22:33:44:55"
	}
	baseSweep.Neighbors = append(baseSweep.Neighbors, probe.ARPNeighbor{IP: "192.0.2.250", MAC: "DE:AD:BE:EF:00:01"})
	raw, err := json.Marshal(baseSweep)
	require.NoError(t, err)
	require.NoError(t, st.SaveSnapshot(ctx, &store.SnapshotRecord{Name: "base1", PayloadJSON: string(raw)}))

	diffRes, err := ExecuteDiffSnapshot(ctx, deps, DiffSnapshotParams{Baseline: "base1"})
	require.NoError(t, err)
	assert.Equal(t, StatusWARN, diffRes.Status)
	diffData := diffRes.Data.(DiffSnapshotData)
	assert.Len(t, diffRes.Card.Rows, len(diffData.Diffs))
	assert.NotEmpty(t, diffRes.Card.Rows)
}

func TestExecuteHostCard(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	require.NoError(t, err)

	res, err := ExecuteHostCard(context.Background(), Dependencies{}, HostCardParams{Target: "127.0.0.1", PortPreset: portStr})
	require.NoError(t, err)
	assert.Contains(t, []string{StatusOK, StatusWARN}, res.Status)
	data, ok := res.Data.(HostCardData)
	require.True(t, ok)
	assert.Equal(t, "127.0.0.1", data.ResolvedIP)
	require.NotNil(t, data.Ports)
	assert.Equal(t, 1, data.Ports.OpenCount)
	require.GreaterOrEqual(t, len(res.Card.Rows), 3)
}

func TestExecuteLANRadarAndGrouping(t *testing.T) {
	t.Parallel()
	synth := &probe.ARPSweepResult{
		Neighbors: []probe.ARPNeighbor{
			{IP: "192.168.1.10", MAC: "B8:27:EB:12:34:56", Vendor: "Raspberry Pi", IsLAA: false},
			{IP: "172.17.0.2", MAC: "02:42:AC:11:00:02", Vendor: "Docker LAA", IsLAA: true},
		},
	}
	phys, virt, rows, _ := buildLANRadarRows(synth, nil)
	require.Len(t, phys, 1)
	require.Len(t, virt, 1)
	require.Len(t, rows, 2)
	assert.Equal(t, groupLabelPhysicalUAA, rows[0].Cells[0])
	assert.Equal(t, groupLabelVirtualLAA, rows[1].Cells[0])

	rendered, err := ascii.Render(&ascii.ReportCard{Title: "LAN RADAR", Headers: []string{"Group", "IP", "MAC", "Vendor"}, Rows: rows}, ascii.StyleDefault)
	require.NoError(t, err)
	assert.Less(t, strings.Index(rendered, groupLabelPhysicalUAA), strings.Index(rendered, groupLabelVirtualLAA))

	res, err := ExecuteLANRadar(context.Background(), Dependencies{}, LANRadarParams{DiscoverServices: false})
	require.NoError(t, err)
	assert.Equal(t, StatusOK, res.Status)
	require.NotNil(t, res.Card)
}

func TestExecutePathAutopsy(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := ExecutePathAutopsy(ctx, Dependencies{}, PathAutopsyParams{Target: "127.0.0.1", MaxHops: 2, Cycles: 2})
	require.NoError(t, err)
	data, ok := res.Data.(PathAutopsyData)
	require.True(t, ok)
	assert.Equal(t, "127.0.0.1", data.ResolvedIP)
	assert.NotNil(t, data.MTR)
	assert.NotNil(t, data.MTU)
	require.NotNil(t, res.Card)
}

func TestExecuteWakeVerify(t *testing.T) {
	t.Parallel()
	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = udpConn.Close() }()
	udpPort := udpConn.LocalAddr().(*net.UDPAddr).Port

	pktCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 256)
		_ = udpConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, readErr := udpConn.ReadFrom(buf)
		if readErr == nil {
			pktCh <- buf[:n]
		}
	}()

	tcpLn, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = tcpLn.Close() }()
	tcpPort := tcpLn.Addr().(*net.TCPAddr).Port

	res, err := ExecuteWakeVerify(context.Background(), Dependencies{}, WakeVerifyParams{
		MAC: "aa:bb:cc:dd:ee:ff", Target: "127.0.0.1", BroadcastIP: "127.0.0.1",
		Port: udpPort, WaitSeconds: 5, Ports: strconv.Itoa(tcpPort),
	})
	require.NoError(t, err)
	assert.Equal(t, StatusOK, res.Status)
	data, ok := res.Data.(WakeVerifyData)
	require.True(t, ok)
	assert.True(t, data.Ready)
	assert.Equal(t, "tcp_port_scan", data.ReadyVia)

	select {
	case pkt := <-pktCh:
		assert.Len(t, pkt, 102)
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive WoL magic packet")
	}
}

func TestExecuteRenderRunDigest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "digest.db"), 10)
	require.NoError(t, err)
	defer func() { _ = st.Close() }()

	now := time.Now().UTC().Unix()
	records := []*store.JobRecord{
		{JobID: "job_ok", ToolName: "ping", Target: "1.1.1.1", Source: "manual", Status: "OK", Summary: "ok", DurationMS: 12, CreatedAt: now},
		{JobID: "job_warn", ToolName: "diff_dns", Target: "example.com", Source: "cron", Status: "WARN", Summary: "split", DurationMS: 45, CreatedAt: now + 1},
		{JobID: "job_fail", ToolName: "diff_ping", Target: "10.0.0.99", Source: "cron", Status: "FAIL", Summary: "down", DurationMS: 90, CreatedAt: now + 2, IsIncident: true},
	}
	for _, r := range records {
		require.NoError(t, st.SaveJob(ctx, r))
	}

	res, err := ExecuteRenderRunDigest(ctx, Dependencies{Store: st}, RenderDigestParams{Limit: 10})
	require.NoError(t, err)
	assert.Equal(t, StatusFAIL, res.Status)
	data, ok := res.Data.(DigestData)
	require.True(t, ok)
	assert.Equal(t, 3, data.TotalJobs)
	assert.Equal(t, 1, data.OKCount)
	assert.Equal(t, 1, data.WarnCount)
	assert.Equal(t, 1, data.FailCount)
	assert.Equal(t, 1, data.IncidentCount)
	require.Len(t, res.Card.Rows, 3)
	assert.Equal(t, StatusFAIL, res.Card.Rows[0].Status)
	assert.Equal(t, StatusWARN, res.Card.Rows[1].Status)
	assert.Equal(t, StatusOK, res.Card.Rows[2].Status)
	rendered, err := ascii.Render(res.Card, ascii.StyleRich)
	require.NoError(t, err)
	assert.Contains(t, rendered, "DIAGNOSTIC RUN DIGEST")
}

func startTestUDPServer(t *testing.T, handler miekgdns.Handler) string {
	t.Helper()
	started := make(chan struct{})
	srv := &miekgdns.Server{Handler: handler, NotifyStartedFunc: func() { close(started) }}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	srv.PacketConn = pc
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func startTestDoHServer(t *testing.T, handler func(req *miekgdns.Msg) *miekgdns.Msg) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		reqMsg := new(miekgdns.Msg)
		if err := reqMsg.Unpack(wireReq); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		wireResp, err := handler(reqMsg).Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wireResp)
	}))
	t.Cleanup(srv.Close)
	return srv
}
