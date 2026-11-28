package dispatch

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/ascii"
	"github.com/FrankXLT/mcp-adv-netutils/internal/http_ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/ping"
	"github.com/FrankXLT/mcp-adv-netutils/internal/probe"
	"github.com/FrankXLT/mcp-adv-netutils/internal/recipes"
	"github.com/FrankXLT/mcp-adv-netutils/internal/resolver"
	"github.com/FrankXLT/mcp-adv-netutils/internal/tls"
	"github.com/FrankXLT/mcp-adv-netutils/internal/traceroute"
)

func buildPingExec(res *ping.PingResponse, durMS int64) *toolExec {
	status := statusOK
	if res.PacketsReceived == 0 {
		status = statusFAIL
	} else if res.PacketLoss > 0 {
		status = statusWARN
	}
	rows, spark, health := make([]ascii.TableRow, 0, len(res.Results)), make([]float64, 0, len(res.Results)), make([]string, 0, len(res.Results))
	for i := range res.Results {
		r := &res.Results[i]
		rst, detail := statusOK, fmt.Sprintf("%.2fms", r.ResponseTime)
		if !r.Success {
			rst, detail = statusFAIL, firstNonEmpty(r.Error, "timeout")
		}
		rows = append(rows, ascii.TableRow{Status: rst, Cells: []string{strconv.Itoa(r.Sequence), res.ProbeMode, fmt.Sprintf("%.2f", r.ResponseTime), strconv.Itoa(r.TTL), detail}})
		spark, health = append(spark, r.ResponseTime), append(health, rst)
	}
	return makeExecCard(&cardSpec{
		tool: "ping", title: "PING", subtitle: res.ProbeMode, target: res.Target, status: status, durMS: durMS, raw: res,
		summary: formatPingSummary(res),
		metrics: []ascii.MetricKV{{Label: "IP", Value: res.ResolvedIP}, {Label: "Loss", Value: fmt.Sprintf("%.0f%%", res.PacketLoss)}, {Label: "Avg RTT", Value: fmt.Sprintf("%.2fms", res.AvgRTT)}},
		headers: []string{"Seq", "Mode", "RTTms", "TTL", "Detail"}, rows: rows, spark: spark, health: health,
		whiskers: []WhiskerPoint{{Label: res.Target, MinMs: res.MinRTT, AvgMs: res.AvgRTT, MaxMs: res.MaxRTT, LossPct: res.PacketLoss}},
	})
}

func buildHTTPPingExec(res *http_ping.HTTPPingResponse, durMS int64) *toolExec {
	status := statusOK
	if res.SuccessCount == 0 {
		status = statusFAIL
	} else if res.FailureCount > 0 {
		status = statusWARN
	}
	rows, spark, health := make([]ascii.TableRow, 0, len(res.Results)), make([]float64, 0, len(res.Results)), make([]string, 0, len(res.Results))
	for i := range res.Results {
		r, rst := &res.Results[i], statusOK
		if !r.Success {
			rst = statusFAIL
		}
		rows = append(rows, ascii.TableRow{Status: rst, Cells: []string{strconv.Itoa(r.Sequence), strconv.Itoa(r.StatusCode), fmt.Sprintf("%.1f", r.TotalTime), fmt.Sprintf("%.1f", r.TTFBTime), firstNonEmpty(r.Error, r.Status)}})
		spark, health = append(spark, r.TotalTime), append(health, rst)
	}
	return makeExecCard(&cardSpec{
		tool: "http_ping", title: "HTTP PING", subtitle: res.Method, target: res.Target, status: status, durMS: durMS, raw: res,
		summary: formatHTTPPingSummary(res),
		metrics: []ascii.MetricKV{{Label: "Success", Value: fmt.Sprintf("%d/%d", res.SuccessCount, res.RequestsSent)}, {Label: "Avg Total", Value: fmt.Sprintf("%.1fms", res.AvgTotalTime)}, {Label: "TTFB", Value: fmt.Sprintf("%.1fms", res.AvgTTFBTime)}},
		headers: []string{"Seq", "Code", "Total", "TTFB", "Detail"}, rows: rows, spark: spark, health: health,
		waterfall: buildHTTPWaterfall(res.AvgDNSTime, res.AvgConnTime, res.AvgTLSTime, res.AvgTTFBTime, res.AvgTotalTime),
	})
}

func buildTracerouteExec(res *traceroute.TracerouteResponse, durMS int64) *toolExec {
	status := statusOK
	switch {
	case len(res.Hops) == 0 || !res.ReachedDestination || res.DestLossPct >= 50:
		status = statusFAIL
	case res.DestLossPct >= 20:
		status = statusWARN
	}
	rows, spark, health := make([]ascii.TableRow, 0, len(res.Hops)), make([]float64, 0, len(res.Hops)), make([]string, 0, len(res.Hops))
	whiskers := make([]WhiskerPoint, 0, len(res.Hops))
	for i := range res.Hops {
		h := &res.Hops[i]
		isDest := h.Segment == "Destination" || (res.ResolvedIP != "" && h.IP == res.ResolvedIP) || (res.ReachedDestination && i == len(res.Hops)-1)
		wp, hst := tracerouteHopWhisker(h, isDest, res.DestLossPct)
		rows = append(rows, ascii.TableRow{Status: hst, Cells: []string{strconv.Itoa(h.Hop), h.IP, firstNonEmpty(h.Hostname, "-"), fmt.Sprintf("%.2fms", h.AvgRTTMs)}})
		spark, health, whiskers = append(spark, h.AvgRTTMs), append(health, hst), append(whiskers, wp)
	}
	return makeExecCard(&cardSpec{
		tool: "traceroute", title: "TRACEROUTE", subtitle: res.ProbeMode, target: res.Target, status: status, durMS: durMS, raw: res,
		summary: formatTracerouteVerdict(res),
		metrics: []ascii.MetricKV{{Label: "Resolved IP", Value: res.ResolvedIP}, {Label: "Hops", Value: strconv.Itoa(len(res.Hops))}, {Label: "Reached", Value: strconv.FormatBool(res.ReachedDestination)}},
		headers: []string{"Hop", "IP", "Host", "Avg"}, rows: rows, spark: spark, health: health, whiskers: whiskers,
	})
}

func formatTracerouteVerdict(res *traceroute.TracerouteResponse) string {
	n := len(res.Hops)
	if n == 0 {
		return fmt.Sprintf("Route trace to %s returned no responding hops", res.Target)
	}
	hopWord, mode := pluralWord(n, "hop", "hops"), firstNonEmpty(res.ProbeMode, "icmp")
	if !res.ReachedDestination {
		return fmt.Sprintf("Traced %d %s toward %s via %s without reaching destination", n, hopWord, res.Target, mode)
	}
	msg := fmt.Sprintf("Reached %s in %d %s via %s", res.Target, n, hopWord, mode)
	if last := res.Hops[n-1]; !last.TimedOut && last.AvgRTTMs > 0 {
		msg += fmt.Sprintf(" (%.1f ms final hop)", last.AvgRTTMs)
	}
	if res.SilentTransitHops > 0 {
		msg += fmt.Sprintf("; %d silent transit %s flowing", res.SilentTransitHops, pluralWord(res.SilentTransitHops, "router", "routers"))
	}
	return msg
}

func buildHTTPWaterfall(dnsMs, connMs, tlsMs, ttfbMs, totalMs float64) []WaterfallPhase {
	phases := make([]WaterfallPhase, 0, 5)
	cursor := 0.0
	for _, p := range []struct {
		label string
		dur   float64
	}{{"DNS Lookup", dnsMs}, {"TCP Connect", connMs}, {"TLS Handshake", tlsMs}, {"First Byte", ttfbMs}} {
		if p.dur > 0 {
			phases = append(phases, WaterfallPhase{Label: p.label, StartMs: cursor, DurationMs: p.dur})
			cursor += p.dur
		}
	}
	if totalMs > 0 {
		phases = append(phases, WaterfallPhase{Label: "Total", StartMs: 0, DurationMs: totalMs, IsTotal: true})
	}
	return phases
}

func buildRecipeExec(_ string, res *recipes.RecipeResult, target string, durMS int64, now time.Time) *toolExec {
	exec := &toolExec{Target: target, Status: firstNonEmpty(res.Status, statusOK), Summary: res.Summary, Data: res.Data, Card: res.Card}
	if exec.Card != nil {
		exec.Target = firstNonEmpty(exec.Card.Target, target)
	}
	switch v := res.Data.(type) {
	case recipes.DiffPingData:
		exec.Whiskers, exec.Waterfall = extractDiffPingCharts(&v)
	case recipes.DiffDNSData:
		exec.DNSComparisons = extractSplitDNSComparisons(v.Comparisons)
		if v.SystemResolver != nil {
			exec.DNSComparisons = append(exec.DNSComparisons, resolverDNSRow(v.SystemResolver))
		}
	case recipes.DiffHTTPData:
		if len(v.Endpoints) > 0 {
			ep := &v.Endpoints[0]
			exec.Waterfall = buildHTTPWaterfall(ep.DNSMs, ep.TCPMs, ep.TLSMs, ep.TTFBMs, ep.TotalMs)
			exec.TLSHealth = extractDiffHTTPTLSHealth(v.Endpoints)
		}
	case recipes.DiffSnapshotData:
		exec.SnapshotDiff = extractSnapshotDiff(&v, now)
	case recipes.HostCardData:
		if v.DNS != nil {
			exec.DNSComparisons = []DNSComparisonRow{resolverDNSRow(v.DNS)}
		}
		if v.Ping != nil {
			exec.Whiskers = []WhiskerPoint{{Label: v.Target, MinMs: v.Ping.MinRTT, AvgMs: v.Ping.AvgRTT, MaxMs: v.Ping.MaxRTT, LossPct: v.Ping.PacketLoss}}
		}
		if v.TLS != nil {
			exec.TLSHealth = extractTLSHealth(v.TLS)
		}
		if v.HTTP != nil {
			exec.Waterfall = buildHTTPWaterfall(v.HTTP.AvgDNSTime, v.HTTP.AvgConnTime, v.HTTP.AvgTLSTime, v.HTTP.AvgTTFBTime, v.HTTP.AvgTotalTime)
		}
	case recipes.LANRadarData:
		exec.LANInventory = extractLANInventory(&v, now)
	case recipes.PathAutopsyData:
		exec.Whiskers = extractPathAutopsyWhiskers(&v)
	case recipes.WakeVerifyData:
		exec.Waterfall = []WaterfallPhase{{Label: "Wake-to-Ready", StartMs: 0, DurationMs: float64(v.WakeToReadyM), IsTotal: true}}
	}
	if exec.Card != nil && exec.Card.DurationMS <= 0 {
		exec.Card.DurationMS = durMS
	}
	return exec
}

func extractTLSHealth(res *tls.CheckResult) *TLSHealthView {
	if res == nil {
		return nil
	}
	view := &TLSHealthView{
		Valid:         res.ChainValid,
		HostnameMatch: res.ChainValid && len(res.ChainErrors) == 0,
		Protocol:      res.TLSVersion,
		Cipher:        res.CipherSuite,
	}
	if len(res.PeerCertificates) > 0 {
		leaf := &res.PeerCertificates[0]
		view.Subject = leaf.Subject
		view.Issuer = formatCertIssuer(leaf.Issuer)
		view.DaysRemaining = leaf.ExpiresInDays
		if !leaf.NotAfter.IsZero() {
			view.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
		}
		if leaf.IsExpired {
			view.Valid = false
		}
	}
	return view
}

func extractDiffHTTPTLSHealth(endpoints []recipes.DiffHTTPEndpoint) *TLSHealthView {
	for i := range endpoints {
		ep := &endpoints[i]
		if ep.ChainValid == nil && ep.ExpiresDays == nil {
			continue
		}
		valid := ep.ChainValid != nil && *ep.ChainValid
		days := 0
		if ep.ExpiresDays != nil {
			days = *ep.ExpiresDays
		}
		return &TLSHealthView{
			Valid:         valid,
			Subject:       firstNonEmpty(extractHostFromURL(ep.URL), formatCertIssuer(ep.Subject)),
			Issuer:        formatCertIssuer(ep.Issuer),
			Protocol:      ep.TLSVersion,
			Cipher:        ep.CipherSuite,
			DaysRemaining: days,
			NotAfter:      ep.NotAfter,
			HostnameMatch: valid,
		}
	}
	return nil
}

func formatCertIssuer(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	var org, cn string
	for i, start, esc := 0, 0, false; i <= len(trimmed); i++ {
		if i < len(trimmed) {
			if esc {
				esc = false
				continue
			}
			if esc = trimmed[i] == '\\'; esc || trimmed[i] != ',' {
				continue
			}
		}
		if k, v, ok := strings.Cut(strings.ReplaceAll(trimmed[start:i], `\,`, `,`), "="); ok {
			val := strings.TrimSpace(v)
			switch strings.ToUpper(strings.TrimSpace(k)) {
			case "O":
				org = firstNonEmpty(org, val)
			case "CN":
				cn = firstNonEmpty(cn, val)
			}
		}
		start = i + 1
	}
	if org != "" && cn != "" && !strings.EqualFold(org, cn) {
		return org + " (" + cn + ")"
	}
	return firstNonEmpty(org, cn, trimmed)
}

func extractHostFromURL(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err == nil && u.Scheme == "" && !strings.Contains(trimmed, "://") {
		u, err = url.Parse("https://" + trimmed)
	}
	if err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return trimmed
}

func extractSplitDNSComparisons(comparisons []probe.SplitDNSComparison) []DNSComparisonRow {
	if len(comparisons) == 0 {
		return nil
	}
	rows := make([]DNSComparisonRow, 0, len(comparisons)*2)
	for i := range comparisons {
		c := &comparisons[i]
		suffix := ""
		if c.RecordType != "" {
			suffix = " (" + c.RecordType + ")"
		}
		match := c.Status == "MATCH"
		status := firstNonEmpty(c.Status, statusINFO)
		rows = append(rows,
			DNSComparisonRow{Resolver: "Local Resolver" + suffix, Answers: slices.Clone(c.LocalAnswers), Status: status, Match: match},
			DNSComparisonRow{Resolver: "Remote DoH" + suffix, Answers: slices.Clone(c.RemoteAnswers), Status: status, Match: match},
		)
	}
	return rows
}

func resolverDNSRow(res *resolver.ResolverResponse) DNSComparisonRow {
	answers := make([]string, 0, len(res.IPv4Addresses)+len(res.IPv6Addresses))
	answers = append(answers, res.IPv4Addresses...)
	answers = append(answers, res.IPv6Addresses...)
	st := statusOK
	match := !res.Failed && len(answers) > 0
	if res.Failed {
		st = statusFAIL
	} else if len(answers) == 0 {
		st = statusWARN
	}
	return DNSComparisonRow{Resolver: "System Resolver", Answers: answers, Status: st, Match: match}
}

func extractDiffPingCharts(data *recipes.DiffPingData) ([]WhiskerPoint, []WaterfallPhase) {
	whiskers := make([]WhiskerPoint, 0, len(data.Hops))
	for i := range data.Hops {
		h := &data.Hops[i]
		whiskers = append(whiskers, WhiskerPoint{
			Label: h.Stage, Segment: h.Stage, Hostname: h.Address,
			MinMs: h.AvgRTTMs, AvgMs: h.AvgRTTMs, MaxMs: h.AvgRTTMs, LossPct: h.LossPct,
		})
	}
	return whiskers, nil
}

func extractSnapshotDiff(data *recipes.DiffSnapshotData, now time.Time) *SnapshotDiffView {
	added, removed, changed := make([]string, 0), make([]string, 0), make([]string, 0)
	for i := range data.Diffs {
		d := &data.Diffs[i]
		line := strings.TrimSpace(fmt.Sprintf("%s %s (%s) %s", d.IP, d.MAC, d.Vendor, d.Detail))
		switch d.DiffType {
		case "[+] ADDED":
			added = append(added, line)
		case "[-] REMOVED":
			removed = append(removed, line)
		default:
			changed = append(changed, line)
		}
	}
	return &SnapshotDiffView{
		BaselineID: data.Baseline, CurrentID: firstNonEmpty(data.SavedAs, "current"),
		CapturedAt: now.UTC().Format(time.RFC3339), Added: added, Removed: removed, Changed: changed,
	}
}

func extractLANInventory(data *recipes.LANRadarData, now time.Time) *LANInventoryView {
	phys := make([]LANHostView, 0, len(data.PhysicalUAA))
	for i := range data.PhysicalUAA {
		n := &data.PhysicalUAA[i]
		phys = append(phys, LANHostView{IP: n.IP, Hostname: n.Hostname, MAC: n.MAC, Vendor: n.Vendor, Segment: "uaa"})
	}
	virt := make([]LANHostView, 0, len(data.VirtualLAA))
	for i := range data.VirtualLAA {
		n := &data.VirtualLAA[i]
		virt = append(virt, LANHostView{IP: n.IP, Hostname: n.Hostname, MAC: n.MAC, Vendor: n.Vendor, Runtime: "Virtual MAC (Docker / VM)", Segment: "laa"})
	}
	return &LANInventoryView{CapturedAt: now.UTC().Format(time.RFC3339), Physical: phys, Virtual: virt}
}

func extractPathAutopsyWhiskers(data *recipes.PathAutopsyData) []WhiskerPoint {
	useTraceroute := data.MTR == nil || (!data.MTR.Reached && data.Traceroute != nil && (data.Traceroute.ReachedDestination || (len(data.MTR.Hops) == 0 && len(data.Traceroute.Hops) > 0)))
	if !useTraceroute {
		out := make([]WhiskerPoint, 0, len(data.MTR.Hops))
		for i := range data.MTR.Hops {
			h := &data.MTR.Hops[i]
			out = append(out, WhiskerPoint{
				Label: fmt.Sprintf("Hop %d (%s)", h.Hop, h.IP), Segment: h.Segment, Hostname: h.Hostname,
				Silent: h.Silent, MinMs: h.BestMs, AvgMs: h.AvgMs, MaxMs: h.WorstMs, LossPct: h.LossPct,
			})
		}
		return out
	}
	if data.Traceroute != nil {
		destLoss := data.Traceroute.DestLossPct
		if destLoss == 0 {
			destLoss = data.DestLossPct
		}
		out := make([]WhiskerPoint, 0, len(data.Traceroute.Hops))
		for i := range data.Traceroute.Hops {
			h := &data.Traceroute.Hops[i]
			isDest := h.Segment == "Destination" || (data.ResolvedIP != "" && h.IP == data.ResolvedIP) || (data.Traceroute.ResolvedIP != "" && h.IP == data.Traceroute.ResolvedIP) || (data.Traceroute.ReachedDestination && i == len(data.Traceroute.Hops)-1)
			wp, _ := tracerouteHopWhisker(h, isDest, destLoss)
			out = append(out, wp)
		}
		return out
	}
	return nil
}

func tracerouteHopWhisker(h *traceroute.HopResult, isDest bool, destLoss float64) (WhiskerPoint, string) {
	hst, loss := statusOK, 0.0
	if h.Silent {
		hst, loss = statusINFO, 100
	} else if h.TimedOut {
		hst, loss = statusWARN, 100
	} else if isDest && destLoss > 0 {
		loss = destLoss
		if destLoss >= 50 {
			hst = statusFAIL
		} else if destLoss >= 20 {
			hst = statusWARN
		}
	}
	minR, maxR := minMaxFloat(h.RTTMs, h.AvgRTTMs)
	return WhiskerPoint{
		Label: fmt.Sprintf("%d: %s", h.Hop, h.IP), Segment: h.Segment, Hostname: h.Hostname,
		Silent: h.Silent, MinMs: minR, AvgMs: h.AvgRTTMs, MaxMs: maxR, LossPct: loss,
	}, hst
}

func minMaxFloat(vals []float64, fallback float64) (float64, float64) {
	if len(vals) == 0 {
		return fallback, fallback
	}
	lo, hi := vals[0], vals[0]
	for _, v := range vals[1:] {
		lo, hi = min(lo, v), max(hi, v)
	}
	return lo, hi
}
