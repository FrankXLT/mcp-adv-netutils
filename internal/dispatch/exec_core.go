package dispatch

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/ascii"
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

type argReader struct {
	m   map[string]any
	err error
}

func (d *Dispatcher) runCoreTool(ctx context.Context, tool string, r *argReader, started time.Time) (*toolExec, error) {
	switch tool {
	case "local_dns_query", "remote_dns_query":
		rt := strings.ToUpper(firstNonEmpty(r.str("record_type"), "A"))
		p := dns.DNSQueryParams{Domain: r.str("domain", "target"), RecordType: rt}
		fn := dns.ExecuteLocal
		if tool == "remote_dns_query" {
			fn = dns.ExecuteRemote
		}
		res, err := fn(ctx, p, d.dnsCfg)
		return wrapExec(tool, err, func() *toolExec { return buildDNSExec(tool, p.Domain, rt, res, msSince(started)) })
	case "whois_query":
		res, err := whois.Execute(ctx, whois.WhoisQueryParams{Domain: r.str("domain", "target")}, d.whoisCfg)
		return wrapExec(tool, err, func() *toolExec { return buildWhoisExec(res, msSince(started)) })
	case "resolve_hostname":
		p := resolver.ResolverParams{Hostname: r.str("hostname", "target"), IPVersion: strings.ToLower(r.str("ip_version"))}
		res, err := resolver.Execute(ctx, p, d.resCfg)
		return wrapExec(tool, err, func() *toolExec { return buildResolverExec(res, msSince(started)) })
	case "ping":
		cnt := r.optI("count")
		if r.err != nil {
			return nil, r.err
		}
		res, err := ping.Execute(ctx, ping.PingParams{Target: r.str("target"), Count: cnt}, d.pingCfg)
		return wrapExec(tool, err, func() *toolExec { return buildPingExec(res, msSince(started)) })
	case "tls_certificate_check":
		p := tls.TLSCheckParams{Domain: r.str("domain", "target"), Port: r.i("port"), IncludeChain: r.optB("include_chain"), CheckExpiry: r.optB("check_expiry"), ServerName: r.str("server_name")}
		if r.err != nil {
			return nil, r.err
		}
		res, err := tls.Execute(ctx, p, d.tlsCfg)
		return wrapExec(tool, err, func() *toolExec { return buildTLSExec(res, msSince(started)) })
	case "http_ping":
		p := http_ping.HTTPPingParams{URL: r.str("url", "target"), Method: r.str("method"), Count: r.optI("count")}
		if r.err != nil {
			return nil, r.err
		}
		res, err := http_ping.Execute(ctx, p, d.httpCfg)
		return wrapExec(tool, err, func() *toolExec { return buildHTTPPingExec(res, msSince(started)) })
	case "mac_vendor_lookup":
		res, err := mac_lookup.Execute(r.str("mac", "target"))
		if err != nil {
			return nil, fmt.Errorf("%w: mac_vendor_lookup: %w", ErrInvalidArgs, err)
		}
		return buildMACLookupExec(res, msSince(started)), nil
	case "traceroute":
		p := traceroute.TracerouteParams{Target: r.str("target"), MaxHops: r.optI("max_hops"), Timeout: r.optI("timeout_seconds")}
		if r.err != nil {
			return nil, r.err
		}
		res, err := traceroute.Execute(ctx, p, d.guard)
		return wrapExec(tool, err, func() *toolExec { return buildTracerouteExec(res, msSince(started)) })
	case "tcp_port_scan":
		p := port_scan.PortScanParams{Target: r.str("target"), Ports: firstNonEmpty(r.str("ports"), "common"), TimeoutMS: r.optI("timeout_ms")}
		if r.err != nil {
			return nil, r.err
		}
		res, err := port_scan.Execute(ctx, p, d.guard)
		return wrapExec(tool, err, func() *toolExec { return buildPortScanExec(res, msSince(started)) })
	case "dns_reverse_batch":
		ips, tmo := r.str("ips", "target"), r.optI("timeout_ms")
		if r.err != nil {
			return nil, r.err
		}
		res, err := dns.ExecuteReverseBatch(ctx, dns.ReverseDNSBatchParams{IPs: ips, TimeoutMS: tmo}, d.dnsCfg)
		return wrapExec(tool, err, func() *toolExec { return buildReverseBatchExec(res, ips, msSince(started)) })
	default:
		p := wol.WOLParams{MAC: r.str("mac", "target"), BroadcastIP: r.str("broadcast_ip"), Port: r.optI("port")}
		if r.err != nil {
			return nil, r.err
		}
		res, err := wol.Execute(ctx, p, d.guard)
		return wrapExec(tool, err, func() *toolExec { return buildWOLExec(res, msSince(started)) })
	}
}

func buildDNSExec(tool, domain, rt string, res *dns.DNSResponse, durMS int64) *toolExec {
	status := statusOK
	if res.Status == 3 {
		status = statusWARN
	} else if res.Status != 0 {
		status = statusFAIL
	}
	rows := make([]ascii.TableRow, 0, len(res.Answer))
	for i := range res.Answer {
		a := &res.Answer[i]
		rows = append(rows, ascii.TableRow{Status: statusOK, Cells: []string{a.Name, firstNonEmpty(a.TypeName, strconv.Itoa(int(a.Type))), strconv.FormatUint(uint64(a.TTL), 10), a.Data}})
	}
	title := "LOCAL DNS QUERY"
	if tool == "remote_dns_query" {
		title = "REMOTE DNS QUERY (DoH)"
	}
	return makeExecCard(&cardSpec{
		tool: tool, title: title, subtitle: rt, target: domain, status: status, durMS: durMS, raw: res,
		summary: formatDNSSummary(domain, rt, res),
		metrics: []ascii.MetricKV{{Label: "Rcode", Value: firstNonEmpty(res.StatusMessage, strconv.Itoa(res.Status))}, {Label: "Answers", Value: strconv.Itoa(len(res.Answer))}},
		headers: []string{"Name", "Type", "TTL", "Data"}, rows: rows,
	})
}

func buildWhoisExec(res *whois.WhoisResponse, durMS int64) *toolExec {
	rows := make([]ascii.TableRow, 0, 8)
	for _, line := range strings.Split(res.Result, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		kl := strings.ToLower(strings.TrimSpace(k))
		if strings.Contains(kl, "registrar") || strings.Contains(kl, "creation") ||
			strings.Contains(kl, "expir") || strings.Contains(kl, "name server") || strings.Contains(kl, "status") {
			rows = append(rows, ascii.TableRow{Status: statusOK, Cells: []string{strings.TrimSpace(k), strings.TrimSpace(v)}})
			if len(rows) >= 8 {
				break
			}
		}
	}
	status := statusOK
	if strings.TrimSpace(res.Result) == "" {
		status = statusWARN
	}
	return makeExecCard(&cardSpec{
		tool: "whois_query", title: "WHOIS QUERY", target: res.Domain, status: status, durMS: durMS, raw: res,
		summary: formatWhoisSummary(res, len(rows)),
		metrics: []ascii.MetricKV{{Label: "Bytes", Value: strconv.Itoa(len(res.Result))}, {Label: "Fields", Value: strconv.Itoa(len(rows))}},
		headers: []string{"Field", "Value"}, rows: rows,
	})
}

func buildResolverExec(res *resolver.ResolverResponse, durMS int64) *toolExec {
	status := statusOK
	rows := make([]ascii.TableRow, 0, len(res.IPv4Addresses)+len(res.IPv6Addresses)+1)
	for _, ip := range res.IPv4Addresses {
		rows = append(rows, ascii.TableRow{Status: statusOK, Cells: []string{"IPv4", ip}})
	}
	for _, ip := range res.IPv6Addresses {
		rows = append(rows, ascii.TableRow{Status: statusOK, Cells: []string{"IPv6", ip}})
	}
	if res.Failed {
		status = statusFAIL
		rows = append(rows, ascii.TableRow{Status: statusFAIL, Cells: []string{"Error", res.Error}})
	}
	return makeExecCard(&cardSpec{
		tool: "resolve_hostname", title: "RESOLVE HOSTNAME", subtitle: res.IPVersion, target: res.Hostname, status: status, durMS: durMS,
		summary: formatResolverSummary(res), raw: res, metrics: []ascii.MetricKV{{Label: "IPv4", Value: strconv.Itoa(len(res.IPv4Addresses))}, {Label: "IPv6", Value: strconv.Itoa(len(res.IPv6Addresses))}},
		headers: []string{"Family", "Address"}, rows: rows,
	})
}

func buildTLSExec(res *tls.CheckResult, durMS int64) *toolExec {
	status, expDays := statusOK, 0
	if len(res.PeerCertificates) == 0 || res.PeerCertificates[0].IsExpired {
		status = statusFAIL
	} else {
		expDays = res.PeerCertificates[0].ExpiresInDays
		if !res.ChainValid || len(res.Warnings) > 0 || expDays <= 30 {
			status = statusWARN
		}
	}
	rows := make([]ascii.TableRow, 0, len(res.PeerCertificates))
	for i := range res.PeerCertificates {
		c, cst := &res.PeerCertificates[i], statusOK
		if c.IsExpired {
			cst = statusFAIL
		} else if c.ExpiresInDays <= 30 {
			cst = statusWARN
		}
		rows = append(rows, ascii.TableRow{Status: cst, Cells: []string{c.Subject, c.Issuer, strconv.Itoa(c.ExpiresInDays) + "d"}})
	}
	return makeExecCard(&cardSpec{
		tool: "tls_certificate_check", title: "TLS CERTIFICATE CHECK", subtitle: res.TLSVersion, target: res.Domain, status: status, durMS: durMS,
		summary: formatTLSSummary(res), raw: res,
		metrics: []ascii.MetricKV{{Label: "Cipher", Value: res.CipherSuite}, {Label: "Chain", Value: strconv.FormatBool(res.ChainValid)}, {Label: "Expires", Value: strconv.Itoa(expDays) + "d"}},
		headers: []string{"Subject", "Issuer", "Exp"}, rows: rows, notes: append(slices.Clone(res.Warnings), res.ChainErrors...),
		tlsHealth: extractTLSHealth(res),
	})
}

func buildMACLookupExec(res *mac_lookup.MACLookupResult, durMS int64) *toolExec {
	badge := "[PHYSICAL - UAA]"
	if res.IsLocallyAdministered {
		badge = "[DOCKER/VM - LAA]"
	}
	return makeExecCard(&cardSpec{
		tool: "mac_vendor_lookup", title: "MAC VENDOR LOOKUP", subtitle: badge, target: res.NormalizedMAC, status: statusOK, durMS: durMS,
		summary: formatMACLookupSummary(res), raw: res,
		metrics: []ascii.MetricKV{{Label: "OUI", Value: res.OUI}, {Label: "Type", Value: res.AddressType}, {Label: "Vendor", Value: res.Vendor}},
		headers: []string{"Field", "Value"},
		rows: []ascii.TableRow{
			{Status: statusOK, Cells: []string{"MAC", res.NormalizedMAC}},
			{Status: statusOK, Cells: []string{"OUI", res.OUI}},
			{Status: statusINFO, Cells: []string{"Assignment", badge}},
			{Status: statusOK, Cells: []string{"Vendor", res.Vendor}},
		},
	})
}

func buildPortScanExec(res *port_scan.PortScanResponse, durMS int64) *toolExec {
	rows, filtered := make([]ascii.TableRow, 0, len(res.Ports)), 0
	for i := range res.Ports {
		p, st := &res.Ports[i], statusINFO
		switch p.State {
		case "open":
			st = statusOK
		case "filtered":
			st = statusWARN
			filtered++
		}
		rows = append(rows, ascii.TableRow{Status: st, Cells: []string{strconv.Itoa(p.Port), p.State, firstNonEmpty(p.Service, "-"), fmt.Sprintf("%.2fms", p.RTTMs)}})
	}
	status := statusOK
	if res.OpenCount == 0 && filtered == len(res.Ports) && len(res.Ports) > 0 {
		status = statusWARN
	}
	return makeExecCard(&cardSpec{
		tool: "tcp_port_scan", title: "TCP PORT SCAN", target: res.Target, status: status, durMS: durMS, raw: res,
		summary: formatPortScanSummary(res, filtered),
		metrics: []ascii.MetricKV{{Label: "IP", Value: res.IP}, {Label: "Scanned", Value: strconv.Itoa(len(res.Ports))}, {Label: "Open", Value: strconv.Itoa(res.OpenCount)}},
		headers: []string{"Port", "State", "Service", "RTT"}, rows: rows,
	})
}

func buildReverseBatchExec(res *dns.ReverseDNSBatchResponse, target string, durMS int64) *toolExec {
	keys := make([]string, 0, len(res.Results))
	for k := range res.Results {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows, resolved := make([]ascii.TableRow, 0, len(keys)), 0
	for _, ip := range keys {
		if ptr := res.Results[ip]; ptr != nil && *ptr != "" {
			resolved++
			rows = append(rows, ascii.TableRow{Status: statusOK, Cells: []string{ip, *ptr}})
		} else {
			rows = append(rows, ascii.TableRow{Status: statusWARN, Cells: []string{ip, "(none)"}})
		}
	}
	status := statusOK
	if res.Count > 0 && resolved == 0 {
		status = statusWARN
	}
	return makeExecCard(&cardSpec{
		tool: "dns_reverse_batch", title: "REVERSE DNS BATCH", target: target, status: status, durMS: durMS, raw: res,
		summary: formatReverseBatchSummary(resolved, res.Count),
		metrics: []ascii.MetricKV{{Label: "IPs", Value: strconv.Itoa(res.Count)}, {Label: "Resolved", Value: strconv.Itoa(resolved)}},
		headers: []string{"IP", "PTR"}, rows: rows,
	})
}

func buildWOLExec(res *wol.WOLResponse, durMS int64) *toolExec {
	status := statusOK
	if !res.Success {
		status = statusFAIL
	}
	summary := formatWOLSummary(res)
	return makeExecCard(&cardSpec{
		tool: "wol_wake", title: "WAKE-ON-LAN", target: res.Normalized, status: status, durMS: durMS, summary: summary, raw: res,
		metrics: []ascii.MetricKV{{Label: "MAC", Value: res.Normalized}, {Label: "Broadcast", Value: res.BroadcastIP}, {Label: "Port", Value: strconv.Itoa(res.Port)}},
		headers: []string{"MAC", "Destination", "Outcome"},
		rows:    []ascii.TableRow{{Status: status, Cells: []string{res.Normalized, res.BroadcastIP + ":" + strconv.Itoa(res.Port), summary}}},
	})
}

func (r *argReader) str(keys ...string) string {
	for _, k := range keys {
		if s, ok := r.m[k].(string); ok {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func (r *argReader) i(keys ...string) int {
	v, _ := r.readInt(keys...)
	return v
}

func (r *argReader) optI(keys ...string) *int {
	v, ok := r.readInt(keys...)
	if !ok {
		return nil
	}
	return &v
}

func (r *argReader) readInt(keys ...string) (int, bool) {
	for _, k := range keys {
		raw, ok := r.m[k]
		if !ok || raw == nil {
			continue
		}
		switch v := raw.(type) {
		case int:
			return v, true
		case int64:
			return int(v), true
		case float64:
			if v != float64(int(v)) {
				r.setErr(fmt.Errorf("%w: %s must be an integer", ErrInvalidArgs, k))
				return 0, false
			}
			return int(v), true
		case json.Number:
			n, err := v.Int64()
			if err != nil {
				r.setErr(fmt.Errorf("%w: %s invalid integer: %w", ErrInvalidArgs, k, err))
				return 0, false
			}
			return int(n), true
		case string:
			trimmed := strings.TrimSpace(v)
			if trimmed == "" {
				continue
			}
			n, err := strconv.Atoi(trimmed)
			if err != nil {
				r.setErr(fmt.Errorf("%w: %s invalid integer %q", ErrInvalidArgs, k, trimmed))
				return 0, false
			}
			return n, true
		default:
			r.setErr(fmt.Errorf("%w: %s must be an integer", ErrInvalidArgs, k))
			return 0, false
		}
	}
	return 0, false
}

func (r *argReader) b(keys ...string) bool {
	v, _ := r.readBool(keys...)
	return v
}

func (r *argReader) optB(keys ...string) *bool {
	v, ok := r.readBool(keys...)
	if !ok {
		return nil
	}
	return &v
}

func (r *argReader) readBool(keys ...string) (bool, bool) {
	for _, k := range keys {
		raw, ok := r.m[k]
		if !ok || raw == nil {
			continue
		}
		switch v := raw.(type) {
		case bool:
			return v, true
		case string:
			trimmed := strings.TrimSpace(v)
			if trimmed == "" {
				continue
			}
			b, err := strconv.ParseBool(trimmed)
			if err != nil {
				r.setErr(fmt.Errorf("%w: %s invalid boolean %q", ErrInvalidArgs, k, trimmed))
				return false, false
			}
			return b, true
		default:
			r.setErr(fmt.Errorf("%w: %s must be a boolean", ErrInvalidArgs, k))
			return false, false
		}
	}
	return false, false
}

func (r *argReader) strs(keys ...string) []string {
	for _, k := range keys {
		raw, ok := r.m[k]
		if !ok || raw == nil {
			continue
		}
		switch v := raw.(type) {
		case []string:
			return splitTrim(v)
		case []any:
			out := make([]string, 0, len(v))
			for _, item := range v {
				s, isStr := item.(string)
				if !isStr {
					r.setErr(fmt.Errorf("%w: %s entries must be strings", ErrInvalidArgs, k))
					return nil
				}
				if trimmed := strings.TrimSpace(s); trimmed != "" {
					out = append(out, trimmed)
				}
			}
			return out
		case string:
			return splitTrim(strings.Split(v, ","))
		default:
			r.setErr(fmt.Errorf("%w: %s must be a string list", ErrInvalidArgs, k))
			return nil
		}
	}
	return nil
}

func (r *argReader) obj(keys ...string) map[string]any {
	for _, k := range keys {
		raw, ok := r.m[k]
		if !ok || raw == nil {
			continue
		}
		m, isMap := raw.(map[string]any)
		if !isMap {
			r.setErr(fmt.Errorf("%w: %s must be an object", ErrInvalidArgs, k))
			return nil
		}
		return maps.Clone(m)
	}
	return nil
}

func (r *argReader) snmpParams() (probe.SNMPParams, error) {
	port, maxEntries := r.i("port"), r.i("max_entries")
	if r.err != nil {
		return probe.SNMPParams{}, r.err
	}
	if port < 0 || port > 65535 {
		return probe.SNMPParams{}, fmt.Errorf("%w: port %d out of uint16 range", ErrInvalidArgs, port)
	}
	return probe.SNMPParams{
		Target: r.str("target"), Port: uint16(port), Version: r.str("version"), Community: r.str("community"),
		Username: r.str("username"), AuthProto: r.str("auth_proto"), AuthPass: r.str("auth_pass"),
		PrivProto: r.str("priv_proto"), PrivPass: r.str("priv_pass"), Mode: r.str("mode"), MaxEntries: maxEntries,
	}, nil
}

func (r *argReader) setErr(err error) {
	if r.err == nil {
		r.err = err
	}
}

func wrapExec(tool string, err error, fn func() *toolExec) (*toolExec, error) {
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tool, err)
	}
	return fn(), nil
}

func splitTrim(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func msSince(started time.Time) int64 { return time.Since(started).Milliseconds() }
