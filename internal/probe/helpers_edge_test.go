package probe

import (
	"context"
	"errors"
	"math"
	"net"
	"os"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/gosnmp/gosnmp"
	"github.com/hashicorp/mdns"
	miekgdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

type fakeNetTimeoutErr struct{ timeout bool }

func (e fakeNetTimeoutErr) Error() string   { return "net timeout" }
func (e fakeNetTimeoutErr) Timeout() bool   { return e.timeout }
func (e fakeNetTimeoutErr) Temporary() bool { return false }

func TestProbeMTULinuxAndTimeoutHelpers(t *testing.T) {
	t.Parallel()

	echoV4 := &icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: 42, Seq: 7}}
	assert.True(t, isEchoReplyMatch(echoV4, true, 42, 7))
	assert.False(t, isEchoReplyMatch(echoV4, true, 42, 8))
	assert.False(t, isEchoReplyMatch(echoV4, false, 42, 7))

	echoV6 := &icmp.Message{Type: ipv6.ICMPTypeEchoReply, Body: &icmp.Echo{ID: 9, Seq: 1}}
	assert.True(t, isEchoReplyMatch(echoV6, false, 9, 1))
	assert.False(t, isEchoReplyMatch(&icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.RawBody{}}, true, 9, 1))

	assert.True(t, isPacketTooBigMsg(&icmp.Message{Type: ipv4.ICMPTypeDestinationUnreachable, Code: 4}, true))
	assert.False(t, isPacketTooBigMsg(&icmp.Message{Type: ipv4.ICMPTypeDestinationUnreachable, Code: 3}, true))
	assert.True(t, isPacketTooBigMsg(&icmp.Message{Type: ipv6.ICMPTypePacketTooBig}, false))

	assert.True(t, classifySocketDialErr(os.ErrPermission).permDenied)
	assert.True(t, classifySocketDialErr(unix.EMSGSIZE).emsgsize)
	assert.True(t, classifySocketDialErr(context.DeadlineExceeded).timedOut)

	assert.True(t, classifyWriteErr(unix.EMSGSIZE, 5*time.Millisecond).emsgsize)
	assert.True(t, classifyWriteErr(unix.EACCES, 5*time.Millisecond).permDenied)
	assert.True(t, classifyWriteErr(fakeNetTimeoutErr{timeout: true}, 5*time.Millisecond).timedOut)

	assert.False(t, isTimeoutErr(nil))
	assert.False(t, isTimeoutErr(errors.New("other")))
	assert.True(t, isConnRefusedErr(errors.New("connect: connection refused")))
	assert.False(t, isConnRefusedErr(nil))
	assert.GreaterOrEqual(t, safeICMPProbeID(), 0)
}

func TestProbeARPSweepPureHelpers(t *testing.T) {
	t.Parallel()

	clean, err := sanitizeInterfaceName("  ")
	require.NoError(t, err)
	assert.Empty(t, clean)

	clean, err = sanitizeInterfaceName(" eth0 ")
	require.NoError(t, err)
	assert.Equal(t, "eth0", clean)

	_, err = sanitizeInterfaceName("eth0;rm -rf")
	require.Error(t, err)

	assert.Equal(t, defaultARPTimeout, normalizeARPTimeout(0))
	assert.Equal(t, time.Duration(minARPTimeoutMS)*time.Millisecond, normalizeARPTimeout(1))
	assert.Equal(t, time.Duration(maxARPTimeoutMS)*time.Millisecond, normalizeARPTimeout(999999))
	assert.Equal(t, 500*time.Millisecond, normalizeARPTimeout(500))

	assert.Equal(t, "complete", parseLinuxARPFlags("0x2"))
	assert.Equal(t, "permanent", parseLinuxARPFlags(" 0X4 "))
	assert.Equal(t, "complete,permanent", parseLinuxARPFlags("0x6"))
	assert.Equal(t, "incomplete", parseLinuxARPFlags("0x0"))
	assert.Equal(t, "0x8", parseLinuxARPFlags(" 0x8 "))

	assert.True(t, isIncompleteMAC(""))
	assert.True(t, isIncompleteMAC("00-00-00-00-00-00"))
	assert.True(t, isIncompleteMAC("(INCOMPLETE)"))
	assert.False(t, isIncompleteMAC("00:50:56:11:22:33"))

	guard, err := security.NewTargetGuard([]string{"192.168.1.0/24"}, []string{"192.168.1.2/32"})
	require.NoError(t, err)
	_, ipNet, err := net.ParseCIDR("192.168.1.0/29")
	require.NoError(t, err)
	hosts := enumerateIPv4SweepHosts(ipNet, guard)
	// /29 has 8 addresses: .0 network and .7 broadcast skipped; .2 denied -> 5 hosts.
	assert.Len(t, hosts, 5)
	assert.Nil(t, enumerateIPv4SweepHosts(nil, guard))
}

func TestProbeSplitDNSAndSNMPAndMDNSHelpers(t *testing.T) {
	t.Parallel()

	assert.Empty(t, normalizeDNSAnswerValue("A", "   "))
	assert.Equal(t, "1.2.3.4", normalizeDNSAnswerValue("A", "::ffff:1.2.3.4"))
	assert.Equal(t, "not-ip", normalizeDNSAnswerValue("A", "NOT-IP"))
	assert.Equal(t, "host.example.com", normalizeDNSAnswerValue("CNAME", "HOST.EXAMPLE.COM."))
	assert.Equal(t, "10 mail.example.com", normalizeDNSAnswerValue("MX", "10 MAIL.EXAMPLE.COM."))
	assert.Equal(t, "0 5 443 svc.example.com", normalizeDNSAnswerValue("SRV", "0 5 443 SVC.EXAMPLE.COM."))
	assert.Equal(t, "v=spf1 -all", normalizeDNSAnswerValue("TXT", "v=spf1 -all"))

	assert.Equal(t, splitStatusError, classifySplitDNSComparison(dnsSideOutcome{errMsg: "e"}, dnsSideOutcome{errMsg: "e"}))
	assert.Equal(t, splitStatusPublicOnly, classifySplitDNSComparison(dnsSideOutcome{errMsg: "e"}, dnsSideOutcome{answers: []string{"1.1.1.1"}}))
	assert.Equal(t, splitStatusError, classifySplitDNSComparison(dnsSideOutcome{errMsg: "e"}, dnsSideOutcome{}))
	assert.Equal(t, splitStatusLocalOnly, classifySplitDNSComparison(dnsSideOutcome{answers: []string{"10.0.0.1"}}, dnsSideOutcome{errMsg: "e"}))
	assert.Equal(t, splitStatusError, classifySplitDNSComparison(dnsSideOutcome{}, dnsSideOutcome{errMsg: "e"}))
	assert.Equal(t, splitStatusMatch, classifySplitDNSComparison(dnsSideOutcome{answers: []string{"1.1.1.1"}}, dnsSideOutcome{answers: []string{"1.1.1.1"}}))
	assert.Equal(t, splitStatusSplitLocal, classifySplitDNSComparison(dnsSideOutcome{answers: []string{"10.0.0.1"}}, dnsSideOutcome{answers: []string{"1.1.1.1"}}))
	assert.Equal(t, splitStatusLocalOnly, classifySplitDNSComparison(dnsSideOutcome{answers: []string{"10.0.0.1"}}, dnsSideOutcome{}))
	assert.Equal(t, splitStatusPublicOnly, classifySplitDNSComparison(dnsSideOutcome{}, dnsSideOutcome{answers: []string{"1.1.1.1"}}))
	assert.Equal(t, splitStatusBothNXDomain, classifySplitDNSComparison(dnsSideOutcome{rcode: miekgdns.RcodeNameError}, dnsSideOutcome{rcode: miekgdns.RcodeNameError}))
	assert.Equal(t, splitStatusSplitLocal, classifySplitDNSComparison(dnsSideOutcome{rcode: miekgdns.RcodeNameError}, dnsSideOutcome{rcode: miekgdns.RcodeSuccess}))
	assert.Equal(t, splitStatusMatch, classifySplitDNSComparison(dnsSideOutcome{}, dnsSideOutcome{}))

	names := map[int]string{1: "up"}
	assert.Equal(t, "up", mapIntLookup(gosnmp.SnmpPDU{Value: 1}, names))
	assert.Equal(t, "9", mapIntLookup(gosnmp.SnmpPDU{Value: 9}, names))
	assert.Equal(t, "", mapIntLookup(gosnmp.SnmpPDU{Value: int64(math.MaxInt32) + 1}, names))
	assert.Equal(t, "eth", formatSNMPValueString(gosnmp.SnmpPDU{Value: []byte("eth\x00 ")}))
	assert.Equal(t, "desc", formatSNMPValueString(gosnmp.SnmpPDU{Value: " desc "}))
	assert.Equal(t, "", formatSNMPValueString(gosnmp.SnmpPDU{Value: nil}))
	assert.Equal(t, "42", formatSNMPValueString(gosnmp.SnmpPDU{Value: 42}))
	assert.Equal(t, "00:11:22:33:44:55", formatLLDPID(gosnmp.SnmpPDU{Value: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}}))
	assert.Equal(t, "sw1", formatLLDPID(gosnmp.SnmpPDU{Value: []byte(" sw1 ")}))

	assert.Equal(t, net.ParseIP("10.0.0.1").To4(), pickMDNSIP(&mdns.ServiceEntry{AddrV4: net.ParseIP("10.0.0.1")}))
	assert.Equal(t, net.ParseIP("fe80::1"), pickMDNSIP(&mdns.ServiceEntry{AddrV6IPAddr: &net.IPAddr{IP: net.ParseIP("fe80::1")}}))
	assert.Equal(t, net.ParseIP("fe80::2"), pickMDNSIP(&mdns.ServiceEntry{AddrV6: net.ParseIP("fe80::2")}))
	assert.Equal(t, net.ParseIP("192.168.1.5"), pickMDNSIP(&mdns.ServiceEntry{Addr: net.ParseIP("192.168.1.5")}))

	deduped, truncated := dedupeAndCapServices([]DiscoveredService{
		{Protocol: "ssdp", IP: "10.0.0.2", Port: 1900, ServiceType: "s2", Name: "b"},
		{Protocol: "mdns", IP: "10.0.0.1", Port: 5353, ServiceType: "s1", Name: "a"},
		{Protocol: "mdns", IP: "10.0.0.1", Port: 5353, ServiceType: "s1", Name: "a"},
		{Protocol: "mdns", IP: "10.0.0.1", Port: 5354, ServiceType: "s1", Name: "c"},
	}, 2)
	assert.True(t, truncated)
	require.Len(t, deduped, 2)
	assert.Equal(t, 5353, deduped[0].Port)
}
