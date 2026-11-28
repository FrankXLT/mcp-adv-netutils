(function (globalScope) {
  "use strict";

  const KEY_OVERRIDES = {
    rtt_ms: "Round-Trip (ms)", avg_rtt_ms: "Average Round-Trip (ms)", min_rtt_ms: "Min Round-Trip (ms)",
    max_rtt_ms: "Max Round-Trip (ms)", response_time_ms: "Response Time (ms)", wireguard_safe_mtu: "WireGuard Safe MTU",
    discovered_mtu: "Discovered MTU", blackhole_detected: "Fragmentation Blocked", packet_loss_percent: "Packet Loss (%)",
    loss_pct: "Loss (%)", stdev_ms: "Jitter (ms)", last_ms: "Last (ms)", avg_ms: "Average (ms)",
    best_ms: "Best (ms)", worst_ms: "Worst (ms)", ttfb_time_ms: "First Byte (ms)",
    avg_ttfb_time_ms: "Average First Byte (ms)", avg_total_time_ms: "Average Total (ms)",
    avg_dns_time_ms: "Average DNS (ms)", avg_connect_time_ms: "Average Connect (ms)",
    avg_tls_time_ms: "Average TLS (ms)", speed_mbps: "Speed (Mbps)", authenticatedData: "Authenticated Data",
    checkingDisabled: "Checking Disabled", ednsClientSubnet: "EDNS Client Subnet",
    statusMessage: "Status Message", is_locally_administered: "Locally Administered",
    expires_in_days: "Days Remaining", not_before: "Valid From", not_after: "Expires"
  };

  const TOKEN_MAP = {
    ttl: "TTL", mtu: "MTU", ip: "IP", ips: "IPs", ipv4: "IPv4", ipv6: "IPv6", mac: "MAC", oui: "OUI",
    dns: "DNS", dnssec: "DNSSEC", edns: "EDNS", tls: "TLS", http: "HTTP", https: "HTTPS", tcp: "TCP",
    udp: "UDP", ptr: "PTR", url: "URL", uri: "URI", uris: "URIs", rtt: "Round-Trip", ttfb: "TTFB",
    snmp: "SNMP", arp: "ARP", wol: "Wake-on-LAN", cidr: "CIDR", ca: "CA", id: "ID", rx: "RX", tx: "TX",
    laa: "LAA", uaa: "UAA", wireguard: "WireGuard", mdns: "mDNS", ssdp: "SSDP", mbps: "Mbps",
    ms: "ms", fdb: "FDB", sys: "System", oper: "Operational"
  };

  const DNS_RCODES = {
    0: "No Error", 1: "Format Error", 2: "Server Failure", 3: "Domain Not Found", 4: "Not Implemented", 5: "Query Refused",
    NOERROR: "No Error", FORMERR: "Format Error", SERVFAIL: "Server Failure", NXDOMAIN: "Domain Not Found", NOTIMP: "Not Implemented", REFUSED: "Query Refused"
  };

  const toArr = (v) => (Array.isArray(v) ? v : []);
  const yesNo = (v) => (v ? "Yes" : "No");
  const capWord = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : "");
  const tbl = (headers, rows) => (Array.isArray(rows) && rows.length ? { headers, rows } : null);
  const view = (summaryFacts, table, chart) => ({ summaryFacts: summaryFacts || [], table: table || null, chart: chart || null });
  const barRow = (label, value, valueText, tone, tooltipLines) => ({ label, value, valueText, tone, tooltipLines });

  function humanizeKey(key) {
    const raw = String(key == null ? "" : key).trim();
    if (!raw) return "";
    if (KEY_OVERRIDES[raw]) return KEY_OVERRIDES[raw];
    let suffix = "", base = raw;
    if (/_ms$/i.test(base)) { base = base.slice(0, -3); suffix = " (ms)"; }
    else if (/_pct$/i.test(base)) { base = base.slice(0, -4); suffix = " (%)"; }
    else if (/_percent$/i.test(base)) { base = base.slice(0, -8); suffix = " (%)"; }
    else if (/_mbps$/i.test(base)) { base = base.slice(0, -5); suffix = " (Mbps)"; }
    const words = base.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2").replace(/[_-]+/g, " ").trim().split(/\s+/).filter(Boolean);
    return words.map((w) => TOKEN_MAP[w.toLowerCase()] || (w.length > 1 && w === w.toUpperCase() ? w : capWord(w.toLowerCase()))).join(" ") + suffix;
  }

  function formatObjectHuman(obj, depth) {
    if (depth >= 2) return "Details available";
    if (obj.port !== undefined && (obj.service || obj.state)) {
      return String(obj.port) + (obj.service ? "/" + obj.service : "") + (obj.state ? " (" + capWord(String(obj.state)) + ")" : "");
    }
    if (obj.data !== undefined && (obj.typeName || obj.type)) return String(obj.typeName || obj.type) + " " + String(obj.data);
    if (obj.ip && (obj.hostname || obj.mac)) return [obj.ip, obj.hostname, obj.mac].filter(Boolean).join(" · ");
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined && obj[k] !== null && obj[k] !== "");
    if (!keys.length) return "None";
    return keys.slice(0, 6).map((k) => humanizeKey(k) + ": " + formatValueHuman(obj[k], depth + 1)).join(" · ");
  }

  function formatValueHuman(val, depth) {
    const d = depth || 0;
    if (val === null || val === undefined) return "—";
    if (typeof val === "boolean") return val ? "Yes" : "No";
    if (typeof val === "number") return Number.isFinite(val) ? String(val) : "—";
    if (typeof val === "string") return val.trim() || "—";
    if (Array.isArray(val)) {
      if (!val.length) return "None";
      const items = val.slice(0, 8).map((item) => formatValueHuman(item, d + 1));
      return items.join(items.some((s) => s.includes(" · ")) ? "; " : ", ");
    }
    return typeof val === "object" ? formatObjectHuman(val, d) : String(val);
  }

  function fmtMs(val, deps) {
    const n = Number(val);
    if (!Number.isFinite(n)) return "—";
    if (deps && typeof deps.fmtMsText === "function") return deps.fmtMsText(n);
    return (Math.abs(n) >= 100 ? Math.round(n) : (Math.abs(n) >= 10 ? n.toFixed(1) : n.toFixed(2))) + " ms";
  }

  function fmtDateShort(iso) {
    const s = String(iso || "").trim();
    return !s ? "—" : (s.length >= 16 && s.includes("T") ? s.replace("T", " ").slice(0, 16) + "Z" : s);
  }

  function fmtCertName(raw) {
    const s = String(raw || "").trim();
    if (!s || !s.includes("=")) return s;
    const segs = [];
    let cur = "", esc = false;
    for (let i = 0; i < s.length; i += 1) {
      const ch = s[i];
      if (esc) { cur += "\\" + ch; esc = false; }
      else if (ch === "\\") esc = true;
      else if (ch === ",") { segs.push(cur); cur = ""; }
      else cur += ch;
    }
    if (esc) cur += "\\";
    segs.push(cur);
    const unescRdn = (v) => v.replace(/\\(.)/g, "$1");
    const parts = {};
    segs.forEach((seg) => {
      const idx = seg.indexOf("=");
      if (idx > 0) {
        const k = unescRdn(seg.slice(0, idx)).trim().toUpperCase(), v = unescRdn(seg.slice(idx + 1)).trim();
        if (!parts[k] && v) parts[k] = v;
      }
    });
    return parts.CN && parts.O && parts.CN.toLowerCase() !== parts.O.toLowerCase() ? parts.O + " (" + parts.CN + ")" : (parts.CN || parts.O || s);
  }

  function dnsStatusLabel(status, msg) {
    const upper = String(msg || "").trim().toUpperCase();
    if (upper && DNS_RCODES[upper]) return DNS_RCODES[upper];
    if (status !== undefined && status !== null && DNS_RCODES[status]) return DNS_RCODES[status];
    return msg ? capWord(String(msg).toLowerCase()) : "OK";
  }

  const pill = (text, state) => ({ pill: String(text), state: state || "nominal" });
  const fmtWhiskerMs = (lossPct, raw) => { const val = Number(raw); return lossPct >= 100 || !(val > 0) ? "—" : val.toFixed(2); };
  const isSilentHop = (h, idx, hops, reachedAny) => {
    if (!h) return false;
    if (h.silent === true) return true;
    const lp = Number(h.loss_pct ?? h.lossPct ?? h.loss ?? 0), avg = Number(h.avg_ms ?? h.avg_rtt_ms ?? h.avgMs ?? 0);
    const zeroReply = Boolean(h.timed_out) || !h.ip || h.ip === "*" || (lp >= 100 && !(avg > 0));
    const downstream = reachedAny || hops.slice(idx + 1).some((nh) => nh && !nh.silent && !nh.timed_out && nh.ip && nh.ip !== "*" && Number(nh.loss_pct ?? nh.lossPct ?? 0) < 100);
    return Boolean(zeroReply && downstream);
  };
  const hopLossPill = (lp, silent) => (silent ? pill("Silent transit (*)", "muted") : lp >= 20 ? pill(lp.toFixed(1) + "% loss", "fault") : lp > 0 ? pill(lp.toFixed(1) + "% loss", "warn") : pill("0.0% loss", "ok"));
  const traceStatusPill = (h, silent) => (silent ? pill("Silent transit (*)", "muted") : h.timed_out ? pill("Timed Out", "fault") : pill("Reached", "ok"));
  const mtrHopTable = (hops, reachedAny) => tbl(["Hop", "Address", "Hostname", "Loss / State", "Avg (ms)", "Best (ms)", "Worst (ms)", "Jitter (ms)"], hops.map((h, idx) => {
    const lp = Number(h.loss_pct || 0), silent = isSilentHop(h, idx, hops, reachedAny);
    return [String(h.hop), h.ip || "*", h.hostname || "—", hopLossPill(lp, silent), silent ? "—" : fmtWhiskerMs(lp, h.avg_ms), silent ? "—" : fmtWhiskerMs(lp, h.best_ms), silent ? "—" : fmtWhiskerMs(lp, h.worst_ms), silent ? "—" : fmtWhiskerMs(lp, h.stdev_ms)];
  }));
  const traceHopTable = (hops, reachedAny, deps) => tbl(["Hop", "Address", "Hostname", "Average RTT", "Status"], hops.map((h, idx) => {
    const silent = isSilentHop(h, idx, hops, reachedAny);
    return [String(h.hop), h.ip || "*", h.hostname || "—", (silent || h.timed_out) ? "—" : fmtMs(h.avg_rtt_ms, deps), traceStatusPill(h, silent)];
  }));

  const whiskersTable = (run) => tbl(["Segment / Hop", "Min (ms)", "Avg (ms)", "Max (ms)", "Loss / State"],
    toArr(run.whiskers).map((w, idx, arr) => {
      const lp = Number(w.lossPct ?? w.loss ?? 0), silent = Boolean(w.silent) || (lp >= 100 && !(Number(w.avgMs ?? w.avg ?? 0) > 0) && /\(\*\)|:\s*\*\s*$|^\s*\*\s*$/.test(String(w.label || "")) && arr.slice(idx + 1).some((nw) => Number(nw.lossPct ?? nw.loss ?? 0) < 100));
      return [w.label || "—", silent ? "—" : fmtWhiskerMs(lp, w.minMs ?? w.min), silent ? "—" : fmtWhiskerMs(lp, w.avgMs ?? w.avg), silent ? "—" : fmtWhiskerMs(lp, w.maxMs ?? w.max), silent ? pill("Silent transit (*)", "muted") : lp.toFixed(1) + "%"];
    }));

  const waterfallTable = (run) => tbl(["Phase", "Start (ms)", "Duration (ms)", "End (ms)"],
    toArr(run.waterfall).map((p) => { const s = Number(p.startMs ?? 0), d = Number(p.durationMs ?? 0); return [p.label || "Phase", s.toFixed(2), d.toFixed(2), (s + d).toFixed(2)]; }));

  const dnsCompTable = (run, deps) => tbl(["Resolver", "Latency", "Answers", "Status"],
    toArr(run.dns_comparisons).map((c) => [c.resolver || "—", c.latency_ms > 0 ? fmtMs(c.latency_ms, deps) : "—", toArr(c.answers).join(", ") || "None", c.status || "OK"]));

  function buildDnsQueryView(run, deps) {
    const d = run.data || {}, answers = toArr(d.answer), comps = toArr(run.dns_comparisons);
    if (d.status !== undefined || d.question || answers.length) {
      const q0 = toArr(d.question)[0], recType = String((q0 && (q0.typeName || q0.type)) || "A");
      const chart = answers.length ? {
        title: "DNS Record TTLs (seconds)", xName: "sec",
        rows: answers.map((a) => {
          const typ = String(a.typeName || a.type || recType), ttl = Number(a.TTL ?? 0), safeTtl = Number.isFinite(ttl) ? ttl : 0;
          return barRow(typ + ": " + String(a.data || a.name || ""), safeTtl, safeTtl + " s", "ok",
            [a.name || run.target || "—", "Type: " + typ, "Answer: " + (a.data || "—"), "TTL: " + safeTtl + " s"]);
        })
      } : null;
      return view([
        ["Status", dnsStatusLabel(d.status, d.statusMessage)], ["Record Type", recType],
        ["Records Found", String(answers.length)], ["DNSSEC Authenticated", yesNo(Boolean(d.authenticatedData))], ["Truncated", yesNo(Boolean(d.truncated))]
      ], tbl(["Record Type", "Host", "Answer", "TTL"], answers.map((a) => [String(a.typeName || a.type || recType), a.name || run.target || "—", a.data || "—", String(a.TTL ?? 0) + " s"])), chart);
    }
    const c0 = comps[0] || {};
    return view(comps.length ? [["Host", run.target || "—"], ["Resolver", c0.resolver || "—"], ["Answers", toArr(c0.answers).join(", ") || "None"], ["Latency", c0.latency_ms > 0 ? fmtMs(c0.latency_ms, deps) : "—"], ["Status", c0.status || run.status || "OK"]] : [], dnsCompTable(run, deps), null);
  }

  function buildResolveView(run, deps) {
    const d = run.data || {}, comps = toArr(run.dns_comparisons);
    if (d.hostname !== undefined || d.ipv4_addresses !== undefined || d.ipv6_addresses !== undefined) {
      const host = d.hostname || run.target || "—", v4 = toArr(d.ipv4_addresses), v6 = toArr(d.ipv6_addresses), ver = String(d.ip_version || "").toLowerCase();
      const verLabel = ver === "both" ? "IPv4 + IPv6" : ver === "ipv4" ? "IPv4" : ver === "ipv6" ? "IPv6" : (v4.length && v6.length ? "IPv4 + IPv6" : v6.length ? "IPv6" : "IPv4");
      const rows = v4.map((ip) => ["IPv4", host, ip, "Resolved"]).concat(v6.map((ip) => ["IPv6", host, ip, "Resolved"]));
      const chart = !comps.length && (v4.length + v6.length > 0) ? {
        title: "Resolved Address Families", xName: "records",
        rows: [
          barRow("IPv4 Addresses", v4.length, v4.length + " records", v4.length ? "ok" : "muted", ["IPv4", v4.length ? v4.join(", ") : "None"]),
          barRow("IPv6 Addresses", v6.length, v6.length + " records", v6.length ? "ok" : "muted", ["IPv6", v6.length ? v6.join(", ") : "None"])
        ]
      } : null;
      return view([["Hostname", host], ["IP Version", verLabel], ["IPv4 Addresses", String(v4.length)], ["IPv6 Addresses", String(v6.length)], ["Status", d.failed ? ("Failed" + (d.error ? ": " + d.error : "")) : (run.status || "OK")]], tbl(["Address Family", "Host", "IP Address", "Status"], rows) || dnsCompTable(run, deps), chart);
    }
    const ans = comps[0] ? toArr(comps[0].answers) : [], v4c = ans.filter((x) => !String(x).includes(":")).length, v6c = ans.filter((x) => String(x).includes(":")).length;
    return view(comps.length ? [["Hostname", run.target || "—"], ["IP Version", v4c > 0 && v6c > 0 ? "IPv4 + IPv6" : (v6c > 0 ? "IPv6" : "IPv4")], ["IPv4 Addresses", String(v4c)], ["IPv6 Addresses", String(v6c)], ["Status", run.status || "OK"]] : [], dnsCompTable(run, deps), null);
  }

  function buildReverseBatchView(run) {
    const d = run.data || {}, comps = toArr(run.dns_comparisons);
    if (d.results && typeof d.results === "object") {
      const keys = Object.keys(d.results).sort();
      let resolved = 0;
      const rows = keys.map((ip) => { const ptr = d.results[ip]; if (ptr) resolved += 1; return [ip, ptr || "—", ptr ? "Resolved" : "Unresolved"]; });
      const unres = keys.length - resolved;
      const chart = !comps.length && keys.length ? {
        title: "Reverse Lookup Results", xName: "addresses",
        rows: [
          barRow("Resolved", resolved, resolved + " IPs", "ok", ["Resolved", resolved + " of " + keys.length + " IPs returned PTR names"]),
          barRow("Unresolved", unres, unres + " IPs", unres > 0 ? "warn" : "muted", ["Unresolved", unres + " IPs had no PTR record"])
        ]
      } : null;
      return view([["IP Addresses Checked", String(d.count ?? keys.length)], ["Names Resolved", String(resolved)], ["Unresolved", String(unres)]], tbl(["IP Address", "Hostname (PTR)", "Status"], rows), chart);
    }
    const resolved = comps.filter((c) => toArr(c.answers).length > 0).length;
    return comps.length ? view([["IP Addresses Checked", String(comps.length)], ["Names Resolved", String(resolved)], ["Unresolved", String(comps.length - resolved)]], tbl(["IP Address", "Hostname (PTR)", "Status"], comps.map((c) => [c.resolver || "—", toArr(c.answers).join(", ") || "—", c.status || "OK"])), null) : view();
  }

  function parseWhoisLines(text) {
    const map = {
      "domain name": "Domain", domain: "Domain", registrar: "Registrar", "registrar url": "Registrar URL", "registrar iana id": "Registrar IANA ID",
      "creation date": "Creation Date", created: "Creation Date", "registry expiry date": "Registry Expiry Date",
      "registrar registration expiration date": "Registry Expiry Date", "expiration date": "Registry Expiry Date", expires: "Registry Expiry Date",
      "updated date": "Updated Date", "domain status": "Domain Status", status: "Domain Status", "name server": "Name Server",
      nserver: "Name Server", dnssec: "DNSSEC", "registrant organization": "Registrant Organization"
    };
    const multi = { "Domain Status": 1, "Name Server": 1 }, out = new Map();
    String(text || "").split(/\r?\n/).forEach((line) => {
      const t = line.trim();
      if (!t || /^[%#>]/.test(t) || /^(notice|terms of use|for more|url of the icann)/i.test(t)) return;
      const idx = t.indexOf(":");
      if (idx <= 0 || idx > 44) return;
      const label = map[t.slice(0, idx).trim().toLowerCase()];
      let val = t.slice(idx + 1).trim();
      if (!label || !val || /^(redacted|data protected|not disclosed|please query|statutory)/i.test(val)) return;
      if (label === "Domain Status") val = val.replace(/\s+https?:\/\/\S+/gi, "").trim();
      if (label === "Name Server") val = val.toLowerCase();
      if (multi[label]) { const list = out.get(label) || []; if (!list.includes(val) && list.length < 6) list.push(val); out.set(label, list); }
      else if (!out.has(label)) out.set(label, val);
    });
    return Array.from(out.entries()).map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : v]);
  }

  function buildWhoisView(run) {
    const d = run.data || {};
    if (typeof d.result === "string" && d.result.trim()) {
      const rows = parseWhoisLines(d.result), getF = (lbl) => { const f = rows.find((r) => r[0] === lbl); return f ? f[1] : ""; };
      const exp = getF("Registry Expiry Date");
      return view([["Domain", d.domain || getF("Domain") || run.target || "—"], ["Registrar", getF("Registrar") || "—"], ["Status", getF("Domain Status") || "—"], exp ? ["Expires", fmtDateShort(exp)] : ["Fields Parsed", String(rows.length)]], tbl(["Registration Field", "Value"], rows), null);
    }
    const keys = Object.keys(d).filter((k) => d[k] !== undefined && d[k] !== null && d[k] !== "");
    if (!keys.length) return view();
    return view([["Domain", d.domain || run.target || "—"], ["Registrar", d.registrar || "—"], ["Status", d.status || "—"], d.expires ? ["Expires", fmtDateShort(d.expires)] : ["Fields Parsed", String(keys.length)]], tbl(["Registration Field", "Value"], keys.map((k) => [humanizeKey(k), formatValueHuman(d[k])])), null);
  }

  function buildPortScanView(run, deps) {
    const d = run.data || {}, rawList = Array.isArray(d.ports) ? d.ports : (Array.isArray(d.open_ports) ? d.open_ports : []), order = { open: 0, filtered: 1, closed: 2 };
    const ports = rawList.map((p) => ({
      port: Number(p.port || 0), service: p.service || "—", state: String(p.state || "open").toLowerCase(),
      rtt: p.rtt_ms !== undefined ? Number(p.rtt_ms) : (p.latency_ms !== undefined ? Number(p.latency_ms) : null)
    })).sort((a, b) => (order[a.state] ?? 3) - (order[b.state] ?? 3) || a.port - b.port);
    const openCnt = ports.filter((p) => p.state === "open").length, filtCnt = ports.filter((p) => p.state === "filtered").length, closedCnt = ports.filter((p) => p.state === "closed").length;
    let chart = null;
    if (ports.length && filtCnt === 0 && closedCnt === 0 && ports.every((p) => p.rtt !== null && p.rtt > 0)) {
      chart = { title: "Open Port Connect Times (ms)", xName: "ms", rows: ports.slice(0, 16).map((p) => barRow(p.port + " (" + p.service + ")", p.rtt, fmtMs(p.rtt, deps), "ok", ["Port " + p.port, "Service: " + p.service, "State: Open", "Connect Time: " + fmtMs(p.rtt, deps)])) };
    } else if (ports.length) {
      chart = { title: "Port State Breakdown", xName: "ports", rows: [barRow("Open", openCnt, openCnt + " ports", "ok", ["Open Ports", openCnt + " accepting connections"]), barRow("Filtered", filtCnt, filtCnt + " ports", filtCnt > 0 ? "warn" : "muted", ["Filtered Ports", filtCnt + " timed out / blocked"]), barRow("Closed", closedCnt, closedCnt + " ports", "muted", ["Closed Ports", closedCnt + " refused connection"])] };
    }
    return view([["Target", d.target || run.target || "—"], ["Resolved IP", d.ip || d.target || run.target || "—"], ["Scanned Ports", String(ports.length)], ["Open Ports", String(d.open_count ?? openCnt)], ["Filtered / Closed", filtCnt + " / " + closedCnt]], tbl(["Port", "Service", "State", "Connect Time"], ports.map((p) => [String(p.port), p.service, capWord(p.state), p.rtt !== null && p.rtt > 0 ? fmtMs(p.rtt, deps) : "—"])), chart);
  }

  function buildTlsCheckView(run) {
    const tls = run.tls_health || {}, d = run.data || {}, certs = toArr(d.peer_certificates), leaf = certs[0] || {};
    const chainValid = d.chain_valid !== undefined ? Boolean(d.chain_valid) : Boolean(tls.valid), daysLeft = tls.days_remaining ?? leaf.expires_in_days;
    const summaryFacts = [["Subject", tls.subject || fmtCertName(leaf.subject) || d.domain || run.target || "—"], ["Issuer", tls.issuer || fmtCertName(leaf.issuer) || "—"], ["Protocol", tls.protocol || d.tls_version || "—"], ["Cipher", tls.cipher || d.cipher_suite || "—"], ["Chain Valid", yesNo(chainValid)], ["Days Remaining", daysLeft !== undefined ? String(daysLeft) : "—"]];
    const table = certs.length ? tbl(["Certificate", "Subject", "Issuer", "Expires", "Days Left"], certs.map((c, idx) => [idx === 0 ? "Leaf" : "Intermediate / Root", fmtCertName(c.subject) || "—", fmtCertName(c.issuer) || "—", fmtDateShort(c.not_after), c.is_expired ? "Expired" : (String(c.expires_in_days ?? 0) + " d")])) :
      (run.tls_health ? tbl(["Property", "Value"], [["Subject", tls.subject || "—"], ["Issuer", tls.issuer || "—"], ["Protocol", tls.protocol || "—"], ["Cipher", tls.cipher || "—"], ["Expires", fmtDateShort(tls.not_after)], ["Days Remaining", String(tls.days_remaining ?? "—")], ["Chain Valid", yesNo(Boolean(tls.valid))], ["Hostname Match", yesNo(Boolean(tls.hostname_match))]]) : null);
    const chart = certs.length ? {
      title: "Certificate Validity (Days Remaining)", xName: "days",
      rows: certs.map((c, idx) => {
        const days = Math.max(0, Number(c.expires_in_days ?? 0)), role = idx === 0 ? "Leaf" : "Intermediate / Root", subj = fmtCertName(c.subject) || role;
        return barRow(role + ": " + subj, days, c.is_expired ? "Expired" : (days + " d"), c.is_expired || days <= 7 ? "fault" : (days < 30 ? "warn" : "ok"), [subj, "Role: " + role, "Issuer: " + (fmtCertName(c.issuer) || "—"), "Expires: " + fmtDateShort(c.not_after)]);
      })
    } : null;
    return view(summaryFacts, table, chart);
  }

  function buildMtuProbeView(run, deps) {
    const d = run.data || {}, steps = toArr(d.steps), wf = toArr(run.waterfall);
    if (d.discovered_mtu !== undefined || steps.length) {
      return view([["Discovered Limit", (d.discovered_mtu ?? 0) + " B"], ["WireGuard Safe Limit", (d.wireguard_safe_mtu ?? 0) + " B"], ["Fragmentation Blocked", yesNo(Boolean(d.blackhole_detected))], ["Probe Mode", d.probe_mode || "—"]],
        tbl(["Wire Packet Size", "Payload Size", "Round-Trip", "Outcome"], steps.map((s) => [s.wire_mtu + " B", s.payload_size + " B", s.rtt_ms > 0 ? fmtMs(s.rtt_ms, deps) : "—", s.success ? "Passed" : (s.error || "Too Large")])) || waterfallTable(run), null);
    }
    return view(wf.length ? [["Target", run.target || "—"], ["Probe Steps", String(wf.length)], ["Status", run.status || "OK"]] : [], waterfallTable(run), null);
  }

  function traceFacts(base, d, hops, reached, wh) {
    const silent = d.silent_transit_hops ?? hops.filter((h, i) => isSilentHop(h, i, hops, reached)).length;
    const last = hops.slice().reverse().find((h) => h && !h.timed_out && h.ip && h.ip !== "*") || hops[hops.length - 1];
    const dLoss = d.dest_loss_pct ?? (last && last.loss_pct != null ? Number(last.loss_pct) : (last && last.timed_out ? 100 : undefined));
    const out = base.concat([
      ["Probe Mode", pill(d.probe_mode || "ICMP", "nominal")],
      ["Reached", pill(yesNo(reached), reached ? "ok" : "warn")],
      ["Silent Transit Hops", pill(String(silent), silent > 0 ? "muted" : "nominal")]
    ]);
    if (dLoss !== undefined) out.push(["Destination Loss %", pill(Number(dLoss).toFixed(1) + "%", Number(dLoss) >= 20 ? "fault" : Number(dLoss) > 0 ? "warn" : "ok")]);
    else if (!hops.length && wh.length) out.push(["Hops", String(wh.length)]);
    return out;
  }

  function buildMtrView(run) {
    const d = run.data || {}, hops = toArr(d.hops), wh = toArr(run.whiskers), reached = Boolean(d.reached);
    if (hops.length || d.cycles !== undefined) {
      return view(traceFacts([["Target", d.target || run.target || "—"], ["Cycles", String(d.cycles ?? "—")], ["Hops", String(hops.length)]], d, hops, reached, wh), mtrHopTable(hops, reached) || whiskersTable(run), null);
    }
    return view(wh.length ? traceFacts([["Target", run.target || "—"]], d, hops, Boolean(d.reached ?? String(run.status).toUpperCase() === "OK"), wh) : [], whiskersTable(run), null);
  }

  function buildDiscoverView(run) {
    const d = run.data || {}, svcs = toArr(d.services), counts = new Map(), warns = toArr(d.warnings);
    const rows = svcs.map((s) => {
      const name = s.name || s.service || s.service_type || s.server || "—", proto = s.protocol ? String(s.protocol).toUpperCase() : (String(name).includes(".local") ? "MDNS" : "SSDP");
      counts.set(proto, (counts.get(proto) || 0) + 1);
      return [proto, name, s.host || s.server || "—", s.ip || s.location || "—", s.port ? String(s.port) : "—"];
    });
    const chart = svcs.length ? { title: "Discovered Services by Protocol", xName: "services", rows: Array.from(counts.entries()).map(([p, c]) => barRow(p, c, c + (c === 1 ? " service" : " services"), "ok", [p, c + (c === 1 ? " discovered service" : " discovered services")])) } : null;
    return view([["Protocol", d.protocol ? String(d.protocol).toUpperCase() : "mDNS / SSDP"], ["Services Found", String(d.count ?? svcs.length)], ["Warnings", warns.length ? String(warns.length) : "None"]], tbl(["Protocol", "Service", "Host", "Address", "Port"], rows), chart);
  }

  function buildPingView(run, deps) {
    const d = run.data || {}, results = toArr(d.results), w0 = toArr(run.whiskers)[0];
    if (d.packets_sent !== undefined || results.length) {
      return view([["Target", d.target || run.target || "—"], ["Resolved IP", d.resolved_ip || "—"], ["Packets Returned", (d.packets_received ?? 0) + " / " + (d.packets_sent ?? 0)], ["Packet Loss", Number(d.packet_loss_percent ?? 0).toFixed(1) + "%"], ["Probe Mode", d.probe_mode || "—"]],
        tbl(["Sequence", "Round-Trip", "TTL", "Status"], results.map((r) => [String(r.sequence), r.success ? fmtMs(r.response_time_ms, deps) : "—", r.ttl ? String(r.ttl) : "—", r.success ? "Reply" : (r.error || "Timed Out")])) || whiskersTable(run), null);
    }
    if (!w0) return view([], whiskersTable(run), null);
    const lossPct = Number(w0.lossPct ?? w0.loss ?? 0), avgVal = w0.avgMs ?? w0.avg, noRtt = lossPct >= 100 || avgVal == null || (Number(avgVal) <= 0 && lossPct > 0);
    return view([["Target", run.target || w0.label || "—"], ["Average RTT", noRtt ? "—" : fmtMs(avgVal, deps)], ["Packet Loss", lossPct.toFixed(1) + "%"]], whiskersTable(run), null);
  }

  function buildTracerouteView(run, deps) {
    const d = run.data || {}, hops = toArr(d.hops), wh = toArr(run.whiskers), reached = Boolean(d.reached_destination ?? d.reached);
    if (hops.length || d.reached_destination !== undefined) {
      return view(traceFacts([["Target", d.target || run.target || "—"], ["Resolved IP", d.resolved_ip || "—"], ["Hops", String(hops.length)]], d, hops, reached, wh), traceHopTable(hops, reached, deps) || whiskersTable(run), null);
    }
    return view(wh.length ? traceFacts([["Target", run.target || "—"]], d, hops, Boolean(d.reached_destination ?? String(run.status).toUpperCase() === "OK"), wh) : [], whiskersTable(run), null);
  }

  function buildPathAutopsyView(run, deps) {
    const d = run.data || {}, mtr = d.mtr || {}, tr = d.traceroute || {}, mtu = d.mtu || {}, wh = toArr(run.whiskers);
    const mtrHops = toArr(mtr.hops), trHops = toArr(tr.hops), hops = mtrHops.length ? mtrHops : (trHops.length ? trHops : toArr(d.hops));
    const reached = Boolean(d.reached ?? d.reached_destination ?? mtr.reached ?? tr.reached_destination ?? (String(run.status).toUpperCase() !== "FAIL"));
    const probeMode = d.probe_mode || mtr.probe_mode || tr.probe_mode || mtu.probe_mode || "ICMP";
    const pathMtu = d.path_mtu ?? d.discovered_mtu ?? mtu.discovered_mtu;
    const meta = { probe_mode: probeMode, silent_transit_hops: d.silent_transit_hops ?? mtr.silent_transit_hops ?? tr.silent_transit_hops, dest_loss_pct: d.dest_loss_pct ?? mtr.dest_loss_pct ?? tr.dest_loss_pct };
    const base = pathMtu != null ? [["Path MTU", String(pathMtu) + " B"]] : [];
    const tblData = mtrHops.length ? mtrHopTable(mtrHops, reached) : (hops.length && hops[0].avg_ms !== undefined ? mtrHopTable(hops, reached) : (hops.length ? traceHopTable(hops, reached, deps) : null));
    return view(traceFacts(base, meta, hops, reached, wh), tblData || whiskersTable(run), null);
  }

  function buildHttpPingView(run, deps) {
    const d = run.data || {}, results = toArr(d.results), wf = toArr(run.waterfall);
    if (d.requests_sent !== undefined || results.length) {
      const sent = Number(d.requests_sent ?? results.length), okCnt = Number(d.success_count ?? results.filter((r) => r.success).length);
      const noSuccess = sent > 0 && okCnt === 0;
      const tot = noSuccess || d.avg_total_time_ms == null ? "—" : fmtMs(d.avg_total_time_ms, deps);
      const ttfb = noSuccess || d.avg_ttfb_time_ms == null ? "—" : fmtMs(d.avg_ttfb_time_ms, deps);
      return view([["Target", d.target || run.target || "—"], ["HTTP Method", d.method || "GET"], ["Requests Succeeded", (d.success_count ?? 0) + " / " + (d.requests_sent ?? 0)], ["Average Total", tot], ["First Byte (TTFB)", ttfb]],
        tbl(["Request", "HTTP Status", "Total Time", "First Byte", "Outcome"], results.map((r) => [String(r.sequence), r.status_code ? String(r.status_code) : "—", r.total_time_ms > 0 ? fmtMs(r.total_time_ms, deps) : "—", r.ttfb_time_ms > 0 ? fmtMs(r.ttfb_time_ms, deps) : "—", r.success ? (r.status || "OK") : (r.error || "Failed")])) || waterfallTable(run), null);
    }
    return view(wf.length ? [["Target", run.target || "—"], ["Phases Measured", String(wf.length)], ["Status", run.status || "OK"]] : [], waterfallTable(run), null);
  }

  function buildSplitDnsView(run, deps) {
    const d = run.data || {}, cmps = toArr(d.comparisons), dComps = toArr(run.dns_comparisons);
    if (d.domain !== undefined || d.overall_status !== undefined || cmps.length) {
      return view([["Domain", d.domain || run.target || "—"], ["Overall Status", d.overall_status || run.status || "OK"], ["Split Detected", yesNo(Boolean(d.split_detected))]],
        tbl(["Record Type", "Status", "Local Answers", "Public Answers"], cmps.map((c) => [c.record_type || "A", c.status || "OK", toArr(c.local_answers).join(", ") || c.local_err || "None", toArr(c.remote_answers).join(", ") || c.remote_err || "None"])) || dnsCompTable(run, deps), null);
    }
    return view(dComps.length ? [["Domain", run.target || "—"], ["Resolvers Compared", String(dComps.length)], ["Split Detected", yesNo(dComps.some((c) => !c.match || /MISMATCH|SPLIT/i.test(String(c.status || ""))))]] : [], dnsCompTable(run, deps), null);
  }

  function buildArpSweepView(run) {
    const d = run.data || {}, nbrs = toArr(d.neighbors), phys = Number(d.physical_count ?? 0), virt = Number(d.virtual_count ?? 0), total = Number(d.total_count ?? (phys + virt)), subnet = d.cidr || d.subnet || run.target || "Local LAN";
    const facts = [["Subnet", subnet], ["Total Devices", String(total)], ["Physical Hardware", String(phys)], ["Virtual / Containers", String(virt)]];
    if (d.probe_mode) facts.push(["Probe Mode", d.probe_mode]);
    const table = nbrs.length ? tbl(["IP Address", "Hostname", "MAC Address", "Vendor", "Segment"], nbrs.map((n) => [n.ip || "—", n.hostname || "—", n.mac || "—", n.vendor || "—", n.is_laa ? "Virtual MAC (Docker / VM)" : "Physical Hardware"])) :
      tbl(["Metric", "Value"], [["Subnet", subnet], ["Physical Hardware", String(phys)], ["Virtual / Containers", String(virt)], ["Total Devices", String(total)]]);
    return view(facts, table, {
      title: "Discovered Devices by Type", xName: "devices",
      rows: [
        barRow("Physical Hardware", phys, phys + (phys === 1 ? " device" : " devices"), "ok", ["Physical Hardware", phys + (phys === 1 ? " hardware device" : " hardware devices")]),
        barRow("Virtual / Containers", virt, virt + (virt === 1 ? " device" : " devices"), "info", ["Virtual / Containers", virt + (virt === 1 ? " virtual MAC device" : " virtual MAC devices")])
      ]
    });
  }

  function buildSnmpView(run) {
    const d = run.data || {}, ifcs = toArr(d.interfaces), fdb = toArr(d.fdb), nbrs = toArr(d.neighbors);
    if (ifcs.length || fdb.length || nbrs.length || d.sys_name !== undefined) {
      const table = tbl(["Index", "Port", "Status", "Speed", "Description"], ifcs.map((i) => [String(i.index), i.name || "—", i.oper_status || i.admin_status || "—", (i.speed_mbps ?? 0) + " Mbps", i.alias || i.mac || "—"])) ||
        tbl(["MAC Address", "Bridge Port", "Interface", "Status"], fdb.map((f) => [f.mac || "—", String(f.bridge_port ?? "—"), f.if_name || String(f.if_index ?? "—"), f.status || "—"])) ||
        tbl(["Local Port", "Interface", "Neighbor", "Remote Port"], nbrs.map((n) => [String(n.local_port ?? "—"), n.if_name || "—", n.sys_name || n.chassis_id || "—", n.port_id || n.port_desc || "—"]));
      return view([["Target", d.target || run.target || "—"], ["System Name", d.sys_name || "—"], ["Uptime", d.sys_uptime || "—"], ["Interfaces", String(ifcs.length)], ["FDB Entries", String(fdb.length)]],
        table,
        ifcs.length ? { title: "Switch Port Speeds (Mbps)", xName: "Mbps", rows: ifcs.slice(0, 16).map((i) => barRow(i.name || ("Port " + i.index), Number(i.speed_mbps || 0), (i.speed_mbps || 0) + " Mbps (" + (i.oper_status || "unknown") + ")", String(i.oper_status || "").toLowerCase() === "up" ? "ok" : "warn", [i.name || ("Port " + i.index), "Status: " + (i.oper_status || "—"), "Speed: " + (i.speed_mbps || 0) + " Mbps"])) } : null);
    }
    const keys = Object.keys(d).filter((k) => d[k] !== undefined && d[k] !== null && d[k] !== "");
    return view([["Switch", run.target || "—"], ["Port", d.port || "—"], ["Link State", d.link || "—"], ["Speed", (d.speed_mbps ?? 0) + " Mbps"], ["Errors (RX / TX)", (d.rx_errors ?? 0) + " / " + (d.tx_errors ?? 0)]],
      tbl(["Metric", "Value"], keys.map((k) => [humanizeKey(k), formatValueHuman(d[k])])),
      d.speed_mbps !== undefined ? { title: "Switch Port Speed (Mbps)", xName: "Mbps", rows: [barRow(d.port || "Port", Number(d.speed_mbps || 0), (d.speed_mbps || 0) + " Mbps (" + (d.link || "UP") + ")", String(d.link || "").toUpperCase() === "UP" ? "ok" : "warn", [d.port || "Port", "Link: " + (d.link || "—"), "Speed: " + (d.speed_mbps || 0) + " Mbps"])] } : null);
  }

  function formatMacAssignment(d) {
    const src = d && typeof d === "object" ? d : {};
    const raw = String(src.address_type || src.assignment || "").trim(), low = raw.toLowerCase();
    if (low.includes("multicast")) return "Multicast";
    if (low.includes("laa") || low.includes("locally_administered") || low.includes("virtual")) return "Virtual MAC (Docker / VM)";
    if (low.includes("uaa") || low.includes("physical")) return "Physical Hardware";
    if (src.is_locally_administered === true) return "Virtual MAC (Docker / VM)";
    if (src.is_locally_administered === false) return "Physical Hardware";
    return raw || "Unknown";
  }

  function buildMacLookupView(run) {
    const d = run.data || {}, mac = d.normalized_mac || d.mac || run.target || "—", facts = [["MAC Address", mac], ["Vendor", d.vendor || "Unknown"], ["Assignment", formatMacAssignment(d)]];
    if (d.oui) facts.push(["OUI Prefix", d.oui]);
    return view(facts, tbl(["Property", "Value"], facts), null);
  }
  function buildWolView(run) {
    const d = run.data || {}, mac = d.normalized_mac || d.mac || run.target || "—", bcast = d.broadcast_ip || "255.255.255.255", port = String(d.port ?? 9), sent = yesNo(d.success !== undefined ? d.success : String(run.status || "OK").toUpperCase() === "OK");
    return view([["Target MAC", mac], ["Broadcast IP", bcast], ["UDP Port", port], ["Packet Sent", sent]], tbl(["Property", "Value"], [["Target MAC", mac], ["Broadcast IP", bcast], ["UDP Port", port], ["Packet Sent", sent], ["Outcome", d.message || run.summary || "Magic packet sent"]]), null);
  }
  function buildDiffHttpView(run, deps) {
    const d = run.data || {}, eps = toArr(d.endpoints).filter((e) => e && typeof e === "object");
    if (eps.length <= 1) return view([], null, null);
    return view([], tbl(["URL", "Status", "DNS", "TCP", "TLS", "First Byte", "Total", "Issuer"], eps.map((e) => [
      e.url || "—", e.status_code ? (String(e.status_code) + " " + String(e.status || "OK")) : String(e.status || "FAIL"),
      e.dns_ms > 0 ? fmtMs(e.dns_ms, deps) : "—", e.tcp_ms > 0 ? fmtMs(e.tcp_ms, deps) : "—", e.tls_ms > 0 ? fmtMs(e.tls_ms, deps) : "—",
      e.ttfb_ms > 0 ? fmtMs(e.ttfb_ms, deps) : "—", e.total_ms > 0 ? fmtMs(e.total_ms, deps) : "—", fmtCertName(e.issuer) || "—"
    ])), null);
  }
  function buildRecipeView(run, deps) {
    const d = run.data && typeof run.data === "object" ? run.data : null, hasChart = Boolean(toArr(run.whiskers).length || toArr(run.waterfall).length || toArr(run.dns_comparisons).length);
    if (!d) return view();
    if (run.tool === "recipe_host_card") {
      const facts = [], mac = d.mac || (d.arp && d.arp.mac);
      if (d.resolved_ip) facts.push(["Resolved IP", d.resolved_ip]); if (mac) facts.push(["MAC Address", mac]);
      if (d.open_ports) facts.push(["Open Ports", formatValueHuman(d.open_ports)]);
      else if (d.ports && Array.isArray(d.ports.ports)) facts.push(["Open Ports", d.ports.ports.filter((p) => p.state === "open").map((p) => p.port + (p.service ? "/" + p.service : "")).join(", ") || "None"]);
      if (d.ping) { const noReply = Number(d.ping.packets_received ?? 1) === 0 || d.ping.avg_rtt_ms == null; facts.push(["Ping Average", noReply ? "—" : fmtMs(d.ping.avg_rtt_ms, deps)]); }
      return view(facts, hasChart ? null : tbl(["Metric", "Value"], facts), null);
    }
    if (run.tool === "recipe_wake_verify") {
      const facts = [["Target MAC", d.mac || "—"]], bcast = d.broadcast_ip || (d.wol && d.wol.broadcast_ip);
      if (bcast) facts.push(["Broadcast IP", bcast]);
      if (d.verified !== undefined || d.ready !== undefined) facts.push(["Verified Online", yesNo(Boolean(d.verified ?? d.ready))]);
      if (d.ready_via) facts.push(["Ready Via", d.ready_via]);
      return view(facts, hasChart ? null : tbl(["Metric", "Value"], facts), null);
    }
    if (run.tool === "recipe_lan_radar" && !hasChart) {
      const phys = toArr(d.physical_uaa), virt = toArr(d.virtual_laa);
      const rows = phys.map((n) => ["Physical", n.ip || "—", n.hostname || "—", n.mac || "—", n.vendor || "—"]).concat(virt.map((n) => ["Virtual", n.ip || "—", n.hostname || "—", n.mac || "—", n.vendor || "—"]));
      return view([["Subnet", d.cidr || run.target || "Local LAN"], ["Physical Hardware", String(phys.length)], ["Virtual / Containers", String(virt.length)], ["Services", String(toArr(d.services).length)]], tbl(["Group", "IP Address", "Hostname", "MAC Address", "Vendor"], rows), null);
    }
    if (hasChart || run.tls_health || run.snapshot_diff || run.added || run.removed || run.changed || d.added || d.removed || d.changed) return view();
    return buildFallbackView(run);
  }
  function buildFallbackView(run) {
    const d = run && run.data && typeof run.data === "object" && !Array.isArray(run.data) ? run.data : null;
    if (!d || Boolean(toArr(run.whiskers).length || toArr(run.waterfall).length || toArr(run.dns_comparisons).length || run.tls_health)) return view();
    const rows = Object.keys(d).slice(0, 16).map((k) => [humanizeKey(k), formatValueHuman(d[k])]);
    return rows.length ? view(rows.slice(0, 8), tbl(["Metric", "Value"], rows), null) : view();
  }
  const TOOL_BUILDERS = {
    local_dns_query: buildDnsQueryView, remote_dns_query: buildDnsQueryView, resolve_hostname: buildResolveView,
    dns_reverse_batch: buildReverseBatchView, whois_query: buildWhoisView, tcp_port_scan: buildPortScanView,
    tls_certificate_check: buildTlsCheckView, mtu_path_probe: buildMtuProbeView, mtr_path_quality: buildMtrView,
    mdns_ssdp_discover: buildDiscoverView, ping: buildPingView, traceroute: buildTracerouteView,
    http_ping: buildHttpPingView, split_dns_audit: buildSplitDnsView, arp_neighbor_sweep: buildArpSweepView,
    snmp_switch_port: buildSnmpView, mac_vendor_lookup: buildMacLookupView, wol_wake: buildWolView,
    recipe_diff_http: buildDiffHttpView, recipe_diff_ping: buildRecipeView, recipe_diff_dns: buildRecipeView,
    recipe_path_autopsy: buildPathAutopsyView, recipe_diff_snapshot: buildRecipeView, render_run_digest: buildRecipeView,
    recipe_host_card: buildRecipeView, recipe_wake_verify: buildRecipeView, recipe_lan_radar: buildRecipeView
  };
  function buildToolView(run, deps) {
    const r = run || {}, builder = TOOL_BUILDERS[r.tool], out = builder ? builder(r, deps) : buildFallbackView(r);
    return view(out && out.summaryFacts, out && out.table, out && out.chart);
  }
  globalScope.NetutilsToolViews = { buildToolView, humanizeKey, formatValueHuman, fmtCertName, formatMacAssignment };
})(typeof window !== "undefined" ? window : globalThis);
