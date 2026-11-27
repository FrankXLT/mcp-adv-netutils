package dispatch

import (
	"testing"

	"github.com/FrankXLT/mcp-adv-netutils/internal/dns"
	"github.com/FrankXLT/mcp-adv-netutils/internal/http_ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/mac_lookup"
	"github.com/FrankXLT/mcp-adv-netutils/internal/ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/port_scan"
	"github.com/FrankXLT/mcp-adv-netutils/internal/probe"
	"github.com/FrankXLT/mcp-adv-netutils/internal/resolver"
	"github.com/FrankXLT/mcp-adv-netutils/internal/tls"
	"github.com/FrankXLT/mcp-adv-netutils/internal/traceroute"
	"github.com/FrankXLT/mcp-adv-netutils/internal/whois"
	"github.com/FrankXLT/mcp-adv-netutils/internal/wol"
	"github.com/stretchr/testify/assert"
)

func TestPlainSentenceSummaries(t *testing.T) {
	t.Parallel()

	pingDown := buildPingExec(&ping.PingResponse{Target: "127.0.0.1", ResolvedIP: "127.0.0.1", PacketsSent: 4, PacketsReceived: 0, PacketLoss: 100, AvgRTT: 0}, 5)
	assert.Equal(t, "Unreachable — 0 of 4 packets returned (100% packet loss)", pingDown.Summary)
	assert.NotContains(t, pingDown.Summary, "0.00")

	pingUp := buildPingExec(&ping.PingResponse{Target: "1.1.1.1", ResolvedIP: "1.1.1.1", PacketsSent: 4, PacketsReceived: 4, PacketLoss: 0, MinRTT: 1.1, AvgRTT: 1.5, MaxRTT: 2.0}, 5)
	assert.Equal(t, "Reachable — 4 of 4 packets returned in 1.50 ms average (min 1.10 ms, max 2.00 ms)", pingUp.Summary)

	pingPartial := buildPingExec(&ping.PingResponse{Target: "1.1.1.1", PacketsSent: 4, PacketsReceived: 2, PacketLoss: 50, AvgRTT: 8.25}, 5)
	assert.Contains(t, pingPartial.Summary, "Partial loss — 2 of 4 packets returned (50% packet loss, 8.25 ms average)")

	httpDown := buildHTTPPingExec(&http_ping.HTTPPingResponse{Target: "https://a.example", Method: "GET", RequestsSent: 3, SuccessCount: 0, FailureCount: 3}, 10)
	assert.Equal(t, "Website unreachable — 0 of 3 GET requests succeeded", httpDown.Summary)
	assert.NotContains(t, httpDown.Summary, "0.0")

	httpOK := buildHTTPPingExec(&http_ping.HTTPPingResponse{
		Target: "https://a.example", Method: "GET", RequestsSent: 2, SuccessCount: 2, AvgTotalTime: 18.4,
		Results: []http_ping.HTTPPingResult{{Sequence: 1, Success: true, StatusCode: 200}},
	}, 10)
	assert.Equal(t, "HTTP 200 responded in 18.4 ms average (2 of 2 requests succeeded)", httpOK.Summary)

	trOK := buildTracerouteExec(&traceroute.TracerouteResponse{
		Target: "1.1.1.1", ReachedDestination: true, Hops: []traceroute.HopResult{{Hop: 1, IP: "1.1.1.1", AvgRTTMs: 4.5}},
	}, 10)
	assert.Equal(t, "Reached 1.1.1.1 in 1 hop (4.5 ms final hop)", trOK.Summary)

	tlsOK := buildTLSExec(&tls.CheckResult{Domain: "api.example.com", Port: 443, TLSVersion: "TLSv1.3", ChainValid: true, PeerCertificates: []tls.CertificateInfo{{ExpiresInDays: 74}}}, 8)
	assert.Equal(t, "Valid TLSv1.3 certificate for api.example.com — expires in 74 days", tlsOK.Summary)

	dnsOK := buildDNSExec("local_dns_query", "api.example.com", "A", &dns.DNSResponse{Status: 0, Answer: []dns.DNSAnswer{{Data: "203.0.113.44"}}}, 4)
	assert.Equal(t, "Returned 1 A record for api.example.com (203.0.113.44)", dnsOK.Summary)

	dnsNX := buildDNSExec("remote_dns_query", "missing.example.com", "A", &dns.DNSResponse{Status: 3}, 4)
	assert.Equal(t, "No A records found for missing.example.com (domain does not exist)", dnsNX.Summary)

	resOK := buildResolverExec(&resolver.ResolverResponse{Hostname: "api.example.com", IPv4Addresses: []string{"203.0.113.44"}, IPv6Addresses: []string{"2001:db8::44"}}, 3)
	assert.Equal(t, "Resolved api.example.com to 1 IPv4 and 1 IPv6 addresses", resOK.Summary)

	portsOK := buildPortScanExec(&port_scan.PortScanResponse{Target: "192.0.2.10", OpenCount: 2, Ports: []port_scan.PortResult{{Port: 22, State: "open"}, {Port: 443, State: "open"}}}, 10)
	assert.Equal(t, "Found 2 open TCP ports on 192.0.2.10 (22, 443)", portsOK.Summary)

	mtuOK := buildMTUProbeExec(&probe.MTUProbeResult{Target: "canary.example.net", DiscoveredMTU: 1420, WireGuardSafeMTU: 1340}, 10)
	assert.Equal(t, "Maximum path packet size is 1420 bytes to canary.example.net (WireGuard safe: 1340 bytes)", mtuOK.Summary)

	wolOK := buildWOLExec(&wol.WOLResponse{Normalized: "00:00:5E:00:53:42", BroadcastIP: "255.255.255.255", Port: 9, Success: true}, 2)
	assert.Equal(t, "Wake packet sent to 00:00:5E:00:53:42 via 255.255.255.255:9", wolOK.Summary)

	whoisOK := buildWhoisExec(&whois.WhoisResponse{Domain: "example.net", Result: "Registrar: Example\n"}, 10)
	assert.Equal(t, "Retrieved domain registration details for example.net (1 field)", whoisOK.Summary)

	macOK := buildMACLookupExec(&mac_lookup.MACLookupResult{NormalizedMAC: "00:00:5E:00:53:10", Vendor: "IANA", IsLocallyAdministered: false}, 1)
	assert.Equal(t, "00:00:5E:00:53:10 belongs to IANA (Physical Hardware)", macOK.Summary)

	arpOK := buildARPSweepExec(&probe.ARPSweepResult{PhysicalCount: 5, VirtualCount: 3}, 10)
	assert.Equal(t, "Found 8 active local devices (5 physical hardware, 3 containers or VMs)", arpOK.Summary)

	discOK := buildDiscoverExec(&probe.DiscoverResult{Protocol: "both", Count: 2}, 10)
	assert.Equal(t, "Discovered 2 advertised local services", discOK.Summary)

	splitOK := buildSplitDNSExec(&probe.SplitDNSResult{Domain: "api.example.com", Comparisons: []probe.SplitDNSComparison{{RecordType: "A"}}}, 10)
	assert.Equal(t, "Local and public DNS answers match for api.example.com (1 record type checked)", splitOK.Summary)

	snmpOK := buildSNMPExec(&probe.SNMPResult{Target: "192.0.2.14", SysName: "switch-core", Interfaces: []probe.SNMPInterface{{Index: 1}}, FDB: []probe.SNMPFDBEntry{{MAC: "aa:bb:cc:dd:ee:ff"}}}, 10)
	assert.Equal(t, "Read 1 switch port and 1 learned MAC entry on switch-core", snmpOK.Summary)
}
