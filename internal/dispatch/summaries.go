package dispatch

import (
	"fmt"
	"strconv"
	"strings"

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
)

func pluralWord(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

func formatPingSummary(res *ping.PingResponse) string {
	unit := pluralWord(res.PacketsSent, "packet", "packets")
	if res.PacketsReceived == 0 {
		return fmt.Sprintf("Unreachable — 0 of %d %s returned (100%% packet loss)", res.PacketsSent, unit)
	}
	if res.PacketLoss > 0 {
		return fmt.Sprintf("Partial loss — %d of %d %s returned (%.0f%% packet loss, %.2f ms average)",
			res.PacketsReceived, res.PacketsSent, unit, res.PacketLoss, res.AvgRTT)
	}
	return fmt.Sprintf("Reachable — %d of %d %s returned in %.2f ms average (min %.2f ms, max %.2f ms)",
		res.PacketsReceived, res.PacketsSent, unit, res.AvgRTT, res.MinRTT, res.MaxRTT)
}

func formatHTTPPingSummary(res *http_ping.HTTPPingResponse) string {
	reqWord := pluralWord(res.RequestsSent, "request", "requests")
	if res.SuccessCount == 0 {
		return fmt.Sprintf("Website unreachable — 0 of %d %s %s succeeded", res.RequestsSent, res.Method, reqWord)
	}
	if res.FailureCount > 0 {
		return fmt.Sprintf("Intermittent response — %d of %d %s %s succeeded in %.1f ms average",
			res.SuccessCount, res.RequestsSent, res.Method, reqWord, res.AvgTotalTime)
	}
	lastCode := 0
	for i := range res.Results {
		if res.Results[i].Success && res.Results[i].StatusCode > 0 {
			lastCode = res.Results[i].StatusCode
		}
	}
	if lastCode > 0 {
		return fmt.Sprintf("HTTP %d responded in %.1f ms average (%d of %d %s succeeded)",
			lastCode, res.AvgTotalTime, res.SuccessCount, res.RequestsSent, reqWord)
	}
	return fmt.Sprintf("Responded in %.1f ms average (%d of %d %s succeeded)",
		res.AvgTotalTime, res.SuccessCount, res.RequestsSent, reqWord)
}

func formatTracerouteSummary(res *traceroute.TracerouteResponse) string {
	n := len(res.Hops)
	if n == 0 {
		return fmt.Sprintf("Route trace to %s returned no responding hops", res.Target)
	}
	hopWord := pluralWord(n, "hop", "hops")
	if res.ReachedDestination {
		last := res.Hops[n-1]
		if !last.TimedOut && last.AvgRTTMs > 0 {
			return fmt.Sprintf("Reached %s in %d %s (%.1f ms final hop)", res.Target, n, hopWord, last.AvgRTTMs)
		}
		return fmt.Sprintf("Reached %s in %d %s", res.Target, n, hopWord)
	}
	return fmt.Sprintf("Traced %d %s toward %s without reaching destination", n, hopWord, res.Target)
}

func formatTLSSummary(res *tls.CheckResult) string {
	if len(res.PeerCertificates) == 0 {
		return fmt.Sprintf("No TLS certificate presented by %s:%d", res.Domain, res.Port)
	}
	leaf := res.PeerCertificates[0]
	ver := firstNonEmpty(res.TLSVersion, "TLS")
	if leaf.IsExpired {
		return fmt.Sprintf("Certificate expired for %s (%s)", res.Domain, ver)
	}
	dayWord := pluralWord(leaf.ExpiresInDays, "day", "days")
	if !res.ChainValid {
		return fmt.Sprintf("Certificate trust issue on %s (%s, %d %s remaining)", res.Domain, ver, leaf.ExpiresInDays, dayWord)
	}
	if leaf.ExpiresInDays <= 30 {
		return fmt.Sprintf("Certificate expiring soon on %s — valid for %d more %s (%s)", res.Domain, leaf.ExpiresInDays, dayWord, ver)
	}
	return fmt.Sprintf("Valid %s certificate for %s — expires in %d %s", ver, res.Domain, leaf.ExpiresInDays, dayWord)
}

func formatDNSSummary(domain, rt string, res *dns.DNSResponse) string {
	if res.Status == 3 {
		return fmt.Sprintf("No %s records found for %s (domain does not exist)", rt, domain)
	}
	if res.Status != 0 {
		return fmt.Sprintf("%s lookup failed for %s (%s)", rt, domain, firstNonEmpty(res.StatusMessage, "resolver error"))
	}
	if len(res.Answer) == 0 {
		return fmt.Sprintf("No %s records returned for %s", rt, domain)
	}
	preview := make([]string, 0, 2)
	for i := 0; i < len(res.Answer) && i < 2; i++ {
		if d := strings.TrimSpace(res.Answer[i].Data); d != "" {
			preview = append(preview, d)
		}
	}
	recWord := pluralWord(len(res.Answer), "record", "records")
	if len(res.Answer) > 2 {
		return fmt.Sprintf("Returned %d %s %s for %s (%s, ...)", len(res.Answer), rt, recWord, domain, strings.Join(preview, ", "))
	}
	return fmt.Sprintf("Returned %d %s %s for %s (%s)", len(res.Answer), rt, recWord, domain, strings.Join(preview, ", "))
}

func formatResolverSummary(res *resolver.ResolverResponse) string {
	if res.Failed {
		return fmt.Sprintf("Could not resolve %s (%s)", res.Hostname, firstNonEmpty(res.Error, "lookup failed"))
	}
	v4, v6 := len(res.IPv4Addresses), len(res.IPv6Addresses)
	switch {
	case v4 > 0 && v6 > 0:
		return fmt.Sprintf("Resolved %s to %d IPv4 and %d IPv6 addresses", res.Hostname, v4, v6)
	case v4 > 0:
		return fmt.Sprintf("Resolved %s to %d IPv4 %s", res.Hostname, v4, pluralWord(v4, "address", "addresses"))
	case v6 > 0:
		return fmt.Sprintf("Resolved %s to %d IPv6 %s", res.Hostname, v6, pluralWord(v6, "address", "addresses"))
	default:
		return fmt.Sprintf("No IP addresses resolved for %s", res.Hostname)
	}
}

func formatReverseBatchSummary(resolved, total int) string {
	return fmt.Sprintf("Resolved reverse names for %d of %d IP %s",
		resolved, total, pluralWord(total, "address", "addresses"))
}

func formatSplitDNSSummary(res *probe.SplitDNSResult) string {
	typeWord := pluralWord(len(res.Comparisons), "type", "types")
	if res.OverallStatus == "ERROR" {
		return fmt.Sprintf("DNS comparison failed for %s across %d record %s", res.Domain, len(res.Comparisons), typeWord)
	}
	if res.SplitDetected {
		return fmt.Sprintf("Local and public DNS answers differ for %s across %d record %s", res.Domain, len(res.Comparisons), typeWord)
	}
	return fmt.Sprintf("Local and public DNS answers match for %s (%d record %s checked)", res.Domain, len(res.Comparisons), typeWord)
}

func formatPortScanSummary(res *port_scan.PortScanResponse, filtered int) string {
	scanned := len(res.Ports)
	if res.OpenCount == 0 && filtered == scanned && scanned > 0 {
		return fmt.Sprintf("All %d scanned ports on %s appear filtered (no response)", scanned, res.Target)
	}
	if res.OpenCount == 0 {
		return fmt.Sprintf("No open TCP ports found across %d scanned %s on %s",
			scanned, pluralWord(scanned, "port", "ports"), res.Target)
	}
	openPorts := make([]string, 0, min(res.OpenCount, 4))
	for i := range res.Ports {
		if res.Ports[i].State == "open" {
			openPorts = append(openPorts, strconv.Itoa(res.Ports[i].Port))
			if len(openPorts) == 4 {
				break
			}
		}
	}
	suffix := ""
	if res.OpenCount > 4 {
		suffix = ", ..."
	}
	return fmt.Sprintf("Found %d open TCP %s on %s (%s%s)",
		res.OpenCount, pluralWord(res.OpenCount, "port", "ports"), res.Target, strings.Join(openPorts, ", "), suffix)
}

func formatMTUSummary(res *probe.MTUProbeResult) string {
	if res.BlackholeDetected || res.DiscoveredMTU == 0 {
		return fmt.Sprintf("Path packet size probe detected fragmentation blocking toward %s", res.Target)
	}
	return fmt.Sprintf("Maximum path packet size is %d bytes to %s (WireGuard safe: %d bytes)",
		res.DiscoveredMTU, res.Target, res.WireGuardSafeMTU)
}

func formatMTRSummary(res *probe.MTRResult, hasIssue bool) string {
	n := len(res.Hops)
	if !res.Reached && n == 0 {
		return fmt.Sprintf("Path quality trace to %s returned no responding hops", res.Target)
	}
	hopWord := pluralWord(n, "hop", "hops")
	if hasIssue {
		return fmt.Sprintf("Traced %d %s to %s — packet loss or high jitter detected", n, hopWord, res.Target)
	}
	if !res.Reached {
		return fmt.Sprintf("Traced %d %s toward %s without reaching destination", n, hopWord, res.Target)
	}
	return fmt.Sprintf("Measured %d %s to %s with no packet loss", n, hopWord, res.Target)
}

func formatWOLSummary(res *wol.WOLResponse) string {
	if !res.Success {
		return fmt.Sprintf("Failed to send wake packet to %s (%s)", res.Normalized, firstNonEmpty(res.Message, "send error"))
	}
	return fmt.Sprintf("Wake packet sent to %s via %s:%d", res.Normalized, res.BroadcastIP, res.Port)
}

func formatWhoisSummary(res *whois.WhoisResponse, fieldCount int) string {
	if strings.TrimSpace(res.Result) == "" {
		return fmt.Sprintf("No domain registration record returned for %s", res.Domain)
	}
	return fmt.Sprintf("Retrieved domain registration details for %s (%d %s)",
		res.Domain, fieldCount, pluralWord(fieldCount, "field", "fields"))
}

func formatMACLookupSummary(res *mac_lookup.MACLookupResult) string {
	kind := "Physical Hardware"
	if res.IsLocallyAdministered {
		kind = "Container / Virtual Adapter"
	}
	return fmt.Sprintf("%s belongs to %s (%s)", res.NormalizedMAC, res.Vendor, kind)
}

func formatARPSweepSummary(res *probe.ARPSweepResult) string {
	total := res.PhysicalCount + res.VirtualCount
	return fmt.Sprintf("Found %d active local %s (%d physical hardware, %d containers or VMs)",
		total, pluralWord(total, "device", "devices"), res.PhysicalCount, res.VirtualCount)
}

func formatDiscoverSummary(res *probe.DiscoverResult) string {
	return fmt.Sprintf("Discovered %d advertised local %s", res.Count, pluralWord(res.Count, "service", "services"))
}

func formatSNMPSummary(res *probe.SNMPResult) string {
	return fmt.Sprintf("Read %d switch %s and %d learned MAC %s on %s",
		len(res.Interfaces), pluralWord(len(res.Interfaces), "port", "ports"),
		len(res.FDB), pluralWord(len(res.FDB), "entry", "entries"),
		firstNonEmpty(res.SysName, res.Target, res.ResolvedIP))
}
