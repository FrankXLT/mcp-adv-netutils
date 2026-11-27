package probe

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/dns"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	miekgdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProcNetARPAndClassification(t *testing.T) {
	t.Parallel()

	sample := strings.Join([]string{
		"IP address       HW type     Flags       HW address            Mask     Device",
		"192.168.1.1      0x1         0x2         b8:27:eb:12:34:56     *        eth0",
		"172.17.0.2       0x1         0x2         02:42:ac:11:00:02     *        docker0",
		"169.254.169.254  0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0",
		"169.254.10.20    0x1         0x2         00:11:22:33:44:55     *        eth0",
		"192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0",
		"192.168.1.50     0x1         0x6         00:0c:29:aa:bb:cc     *        eth0",
	}, "\n")

	entries, err := parseProcNetARP(strings.NewReader(sample))
	require.NoError(t, err)
	require.Len(t, entries, 5)

	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)

	neighbors, physCount, virtCount := buildARPNeighbors(entries, nil, "", guard)
	require.Len(t, neighbors, 3)
	assert.Equal(t, 2, physCount)
	assert.Equal(t, 1, virtCount)

	byIP := make(map[string]ARPNeighbor, len(neighbors))
	for i := range neighbors {
		byIP[neighbors[i].IP] = neighbors[i]
	}

	assert.NotContains(t, byIP, "169.254.169.254")
	assert.NotContains(t, byIP, "169.254.10.20")
	assert.NotContains(t, byIP, "192.168.1.99")

	docker := byIP["172.17.0.2"]
	assert.True(t, docker.IsLAA)
	assert.Equal(t, arpGroupVirtualLAA, docker.Group)
	assert.Equal(t, "locally_administered_laa", docker.AddressType)
	assert.Equal(t, "02:42:AC:11:00:02", docker.MAC)
	assert.Equal(t, "docker0", docker.Interface)
	assert.Equal(t, "complete", docker.State)

	pi := byIP["192.168.1.1"]
	assert.False(t, pi.IsLAA)
	assert.Equal(t, arpGroupPhysicalUAA, pi.Group)
	assert.Equal(t, "unicast_uaa", pi.AddressType)
	assert.Equal(t, "B8:27:EB:12:34:56", pi.MAC)
	assert.NotEmpty(t, pi.Vendor)
	assert.NotEqual(t, "Unknown Vendor", pi.Vendor)

	vmw := byIP["192.168.1.50"]
	assert.False(t, vmw.IsLAA)
	assert.Equal(t, arpGroupPhysicalUAA, vmw.Group)
	assert.Equal(t, "complete,permanent", vmw.State)

	// Interface and CIDR filtering should further narrow results.
	_, ethNet, err := net.ParseCIDR("192.168.1.0/24")
	require.NoError(t, err)
	filtered, fPhys, fVirt := buildARPNeighbors(entries, ethNet, "eth0", guard)
	require.Len(t, filtered, 2)
	assert.Equal(t, 2, fPhys)
	assert.Equal(t, 0, fVirt)
}

func TestARPSweepCIDRValidation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	guard, err := security.NewTargetGuard(nil, []string{"172.31.0.0/24"})
	require.NoError(t, err)

	// /8 and /21 must be rejected by the >= /22 cap.
	_, err = ExecuteARPSweep(ctx, ARPSweepParams{CIDR: "10.0.0.0/8"}, guard, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errARPCIDRTooBroad)

	_, err = ExecuteARPSweep(ctx, ARPSweepParams{CIDR: "192.168.0.0/21"}, guard, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errARPCIDRTooBroad)

	// 169.254.0.0/16 and overlapping /24 must be rejected by TargetGuard.
	_, err = ExecuteARPSweep(ctx, ARPSweepParams{CIDR: "169.254.0.0/16"}, guard, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrTargetDenied)

	_, err = ExecuteARPSweep(ctx, ARPSweepParams{CIDR: "169.254.10.0/24"}, guard, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrTargetDenied)

	// Explicit deny CIDR must be rejected.
	_, err = ExecuteARPSweep(ctx, ARPSweepParams{CIDR: "172.31.0.0/24"}, guard, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrTargetDenied)

	// IPv6 CIDR must be rejected.
	_, err = ExecuteARPSweep(ctx, ARPSweepParams{CIDR: "fd00:1234::/64"}, guard, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errARPIPv4Required)

	// /22 and /24 pass CIDR validation cleanly.
	ipNet22, norm22, err := validateARPSweepCIDR("192.168.0.0/22", guard)
	require.NoError(t, err)
	require.NotNil(t, ipNet22)
	assert.Equal(t, "192.168.0.0/22", norm22)

	// Empty CIDR executes cleanly against OS ARP table (with metadata filtering).
	res, err := ExecuteARPSweep(ctx, ARPSweepParams{TimeoutMS: 250}, guard, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.NotEmpty(t, res.ProbeMode)
	assert.NotEmpty(t, res.Timestamp)
	for i := range res.Neighbors {
		assert.False(t, strings.HasPrefix(res.Neighbors[i].IP, "169.254."))
	}

	// ActiveProbe on /24 without CAP_NET_RAW or matching interface falls back gracefully.
	activeRes, err := ExecuteARPSweep(ctx, ARPSweepParams{
		CIDR:        "192.0.2.0/24",
		ActiveProbe: true,
		TimeoutMS:   200,
	}, guard, nil)
	require.NoError(t, err)
	require.NotNil(t, activeRes)
	assert.Equal(t, "192.0.2.0/24", activeRes.CIDR)
	assert.NotEmpty(t, activeRes.ProbeMode)
}

func TestARPNeighborPTRBatchEnrichment(t *testing.T) {
	t.Parallel()

	localAddr := startProbeTestDNSServer(t, miekgdns.HandlerFunc(func(w miekgdns.ResponseWriter, r *miekgdns.Msg) {
		m := new(miekgdns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == miekgdns.TypePTR {
			qname := r.Question[0].Name
			switch qname {
			case "10.1.0.10.in-addr.arpa.":
				m.Answer = append(m.Answer, &miekgdns.PTR{
					Hdr: miekgdns.RR_Header{Name: qname, Rrtype: miekgdns.TypePTR, Class: miekgdns.ClassINET, Ttl: 60},
					Ptr: "gateway.corp.local.",
				})
			case "20.1.0.10.in-addr.arpa.":
				m.Answer = append(m.Answer, &miekgdns.PTR{
					Hdr: miekgdns.RR_Header{Name: qname, Rrtype: miekgdns.TypePTR, Class: miekgdns.ClassINET, Ttl: 60},
					Ptr: "docker-host.corp.local.",
				})
			default:
				m.Rcode = miekgdns.RcodeNameError
			}
		}
		_ = w.WriteMsg(m)
	}))

	neighbors := []ARPNeighbor{
		{IP: "10.0.1.10", MAC: "00:11:22:33:44:55"},
		{IP: "10.0.1.20", MAC: "02:42:AC:11:00:02"},
		{IP: "10.0.1.30", MAC: "00:11:22:33:44:66"},
	}

	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)

	dnsCfg := &dns.QueryConfig{
		Timeout:      2 * time.Second,
		LocalServers: []string{localAddr},
		Guard:        guard,
	}

	err = enrichARPNeighborsPTR(context.Background(), neighbors, dnsCfg, time.Second)
	require.NoError(t, err)
	assert.Equal(t, "gateway.corp.local", neighbors[0].Hostname)
	assert.Equal(t, "docker-host.corp.local", neighbors[1].Hostname)
	assert.Empty(t, neighbors[2].Hostname)
}

func TestExecuteSplitDNSAuditClassification(t *testing.T) {
	t.Parallel()

	localAddr := startProbeTestDNSServer(t, miekgdns.HandlerFunc(func(w miekgdns.ResponseWriter, r *miekgdns.Msg) {
		m := new(miekgdns.Msg)
		m.SetReply(r)
		if len(r.Question) == 0 {
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		switch q.Name {
		case "match.example.com.":
			if q.Qtype == miekgdns.TypeA {
				m.Answer = append(m.Answer, &miekgdns.A{
					Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 300},
					A:   net.ParseIP("93.184.216.34"),
				})
			}
		case "app.corp.example.com.":
			switch q.Qtype {
			case miekgdns.TypeA:
				// Split-horizon: local returns RFC1918 IP, public returns WAN IP.
				m.Answer = append(m.Answer, &miekgdns.A{
					Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 60},
					A:   net.ParseIP("10.0.1.50"),
				})
			case miekgdns.TypeTXT:
				// Matching TXT across local & public.
				m.Answer = append(m.Answer, &miekgdns.TXT{
					Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeTXT, Class: miekgdns.ClassINET, Ttl: 120},
					Txt: []string{"v=spf1 -all"},
				})
			case miekgdns.TypeMX:
				// Local-only MX record.
				m.Answer = append(m.Answer, &miekgdns.MX{
					Hdr:        miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeMX, Class: miekgdns.ClassINET, Ttl: 60},
					Preference: 10,
					Mx:         "mail.internal.corp.",
				})
			}
		case "nas.home.arpa.":
			if q.Qtype == miekgdns.TypeA {
				m.Answer = append(m.Answer, &miekgdns.A{
					Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 30},
					A:   net.ParseIP("192.168.1.10"),
				})
			}
		case "missing.example.invalid.":
			m.Rcode = miekgdns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	}))

	dohSrv := startProbeTestDoHServer(t, func(req *miekgdns.Msg) *miekgdns.Msg {
		m := new(miekgdns.Msg)
		m.SetReply(req)
		if len(req.Question) == 0 {
			return m
		}
		q := req.Question[0]
		switch q.Name {
		case "match.example.com.":
			if q.Qtype == miekgdns.TypeA {
				m.Answer = append(m.Answer, &miekgdns.A{
					Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 600},
					A:   net.ParseIP("93.184.216.34"),
				})
			}
		case "app.corp.example.com.":
			switch q.Qtype {
			case miekgdns.TypeA:
				m.Answer = append(m.Answer, &miekgdns.A{
					Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 300},
					A:   net.ParseIP("203.0.113.50"),
				})
			case miekgdns.TypeTXT:
				m.Answer = append(m.Answer, &miekgdns.TXT{
					Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeTXT, Class: miekgdns.ClassINET, Ttl: 120},
					Txt: []string{"v=spf1 -all"},
				})
			case miekgdns.TypeMX:
				m.Rcode = miekgdns.RcodeNameError
			}
		case "nas.home.arpa.":
			m.Rcode = miekgdns.RcodeNameError
		case "missing.example.invalid.":
			m.Rcode = miekgdns.RcodeNameError
		}
		return m
	})

	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)

	dnsCfg := &dns.QueryConfig{
		Timeout:             2 * time.Second,
		LocalServers:        []string{localAddr},
		RemoteServerAddress: dohSrv.URL + "/dns-query",
		Guard:               guard,
	}

	ctx := context.Background()

	// 1. MATCH scenario using default record types.
	matchRes, err := ExecuteSplitDNSAudit(ctx, SplitDNSParams{
		Domain: "match.example.com",
	}, dnsCfg)
	require.NoError(t, err)
	assert.False(t, matchRes.SplitDetected)
	assert.Equal(t, splitStatusMatch, matchRes.OverallStatus)
	require.Len(t, matchRes.Comparisons, 5)
	assert.Equal(t, "A", matchRes.Comparisons[0].RecordType)
	assert.Equal(t, splitStatusMatch, matchRes.Comparisons[0].Status)
	assert.Equal(t, []string{"93.184.216.34"}, matchRes.Comparisons[0].LocalAnswers)
	assert.Equal(t, []string{"93.184.216.34"}, matchRes.Comparisons[0].RemoteAnswers)
	assert.Equal(t, uint32(300), matchRes.Comparisons[0].LocalTTL)
	assert.Equal(t, uint32(600), matchRes.Comparisons[0].RemoteTTL)

	// 2. SPLIT-LOCAL + MATCH + LOCAL-ONLY mixed scenario.
	splitRes, err := ExecuteSplitDNSAudit(ctx, SplitDNSParams{
		Domain:      "app.corp.example.com",
		RecordTypes: []string{"A", "TXT", "MX"},
	}, dnsCfg)
	require.NoError(t, err)
	assert.True(t, splitRes.SplitDetected)
	assert.Equal(t, "SPLIT-DETECTED", splitRes.OverallStatus)
	require.Len(t, splitRes.Comparisons, 3)

	assert.Equal(t, splitStatusSplitLocal, splitRes.Comparisons[0].Status)
	assert.Equal(t, []string{"10.0.1.50"}, splitRes.Comparisons[0].LocalAnswers)
	assert.Equal(t, []string{"203.0.113.50"}, splitRes.Comparisons[0].RemoteAnswers)

	assert.Equal(t, splitStatusMatch, splitRes.Comparisons[1].Status)
	assert.Equal(t, []string{"v=spf1 -all"}, splitRes.Comparisons[1].LocalAnswers)

	assert.Equal(t, splitStatusLocalOnly, splitRes.Comparisons[2].Status)
	assert.Equal(t, []string{"10 mail.internal.corp"}, splitRes.Comparisons[2].LocalAnswers)
	assert.Empty(t, splitRes.Comparisons[2].RemoteAnswers)

	// 3. Pure LOCAL-ONLY scenario.
	localOnlyRes, err := ExecuteSplitDNSAudit(ctx, SplitDNSParams{
		Domain:      "nas.home.arpa",
		RecordTypes: []string{"A"},
	}, dnsCfg)
	require.NoError(t, err)
	assert.True(t, localOnlyRes.SplitDetected)
	assert.Equal(t, "SPLIT-DETECTED", localOnlyRes.OverallStatus)
	require.Len(t, localOnlyRes.Comparisons, 1)
	assert.Equal(t, splitStatusLocalOnly, localOnlyRes.Comparisons[0].Status)

	// 4. BOTH-NXDOMAIN scenario.
	nxRes, err := ExecuteSplitDNSAudit(ctx, SplitDNSParams{
		Domain:      "missing.example.invalid",
		RecordTypes: []string{"A", "AAAA"},
	}, dnsCfg)
	require.NoError(t, err)
	assert.False(t, nxRes.SplitDetected)
	assert.Equal(t, splitStatusBothNXDomain, nxRes.OverallStatus)
	require.Len(t, nxRes.Comparisons, 2)
	assert.Equal(t, splitStatusBothNXDomain, nxRes.Comparisons[0].Status)
	assert.Equal(t, splitStatusBothNXDomain, nxRes.Comparisons[1].Status)
}

func TestSplitDNSValidationLimits(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	_, err := ExecuteSplitDNSAudit(ctx, SplitDNSParams{Domain: ""}, nil)
	require.Error(t, err)

	_, err = ExecuteSplitDNSAudit(ctx, SplitDNSParams{
		Domain:      "example.com",
		RecordTypes: []string{"A", "AAAA", "CNAME", "TXT", "MX", "NS", "PTR", "SOA", "SRV", "CAA", "DNSKEY"},
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")

	_, err = ExecuteSplitDNSAudit(ctx, SplitDNSParams{
		Domain:      "example.com",
		RecordTypes: []string{"INVALIDTYPE"},
	}, nil)
	require.Error(t, err)
}

func startProbeTestDNSServer(t *testing.T, handler miekgdns.Handler) string {
	t.Helper()

	started := make(chan struct{})
	srv := &miekgdns.Server{
		Handler:           handler,
		NotifyStartedFunc: func() { close(started) },
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	srv.PacketConn = pc
	addr := pc.LocalAddr().String()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ActivateAndServe()
	}()

	select {
	case <-started:
	case startErr := <-errCh:
		t.Fatalf("test DNS server failed to start: %v", startErr)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for test DNS server to start")
	}

	t.Cleanup(func() {
		_ = srv.Shutdown()
	})

	return addr
}

func startProbeTestDoHServer(t *testing.T, handler func(req *miekgdns.Msg) *miekgdns.Msg) *httptest.Server {
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
			http.Error(w, fmt.Sprintf("read error: %v", err), http.StatusBadRequest)
			return
		}

		reqMsg := new(miekgdns.Msg)
		if err := reqMsg.Unpack(wireReq); err != nil {
			http.Error(w, fmt.Sprintf("unpack error: %v", err), http.StatusBadRequest)
			return
		}

		respMsg := handler(reqMsg)
		wireResp, err := respMsg.Pack()
		if err != nil {
			http.Error(w, fmt.Sprintf("pack error: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wireResp)
	}))
	t.Cleanup(srv.Close)
	return srv
}
