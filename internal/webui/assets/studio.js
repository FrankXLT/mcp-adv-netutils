(function (globalScope) {
  "use strict";

  const THEME_KEY = "netutils_theme", DENSITY_KEY = "netutils_density";
  const THEMES = { white: 1, paper: 1, dark: 1, "dark-paper": 1 };
  const CHECKS = {
    recipe_diff_ping: { goal: "path", label: "Multi-Point Ping", groupLabel: "Path & Ping", placeholder: "canary.example.net", hint: "Compare latency from local adapter, gateway, ISP, and destination." },
    ping: { goal: "path", label: "Standard Ping", groupLabel: "Path & Ping", placeholder: "canary.example.net", hint: "Measure round-trip latency and packet loss to one target." },
    recipe_path_autopsy: { goal: "path", label: "Full Path Autopsy", groupLabel: "Path & Ping", placeholder: "198.51.100.44", hint: "Trace hops, packet loss, jitter, and path packet size limit." },
    mtr_path_quality: { goal: "path", label: "Hop-by-Hop Latency & Loss", groupLabel: "Path & Ping", placeholder: "198.51.100.44", hint: "Measure packet loss and latency spikes at each hop." },
    traceroute: { goal: "path", label: "Network Route Trace", groupLabel: "Path & Ping", placeholder: "203.0.113.8", hint: "Show every router hop along the path." },
    mtu_path_probe: { goal: "path", label: "Path Packet Size Limit", groupLabel: "Path & Ping", placeholder: "canary.example.net", hint: "Find largest packet size supported without fragmentation." },
    recipe_diff_http: { goal: "web", label: "Website & TLS Health Check", groupLabel: "Web & DNS", placeholder: "https://api.example.com/health", hint: "Measure page timing phases and verify TLS certificate health." },
    http_ping: { goal: "web", label: "Website Timing Breakdown", groupLabel: "Web & DNS", placeholder: "https://api.example.com/health", hint: "Time DNS lookup, TCP connect, TLS handshake, and first byte." },
    tls_certificate_check: { goal: "web", label: "TLS Certificate & Expiry", groupLabel: "Web & DNS", placeholder: "api.example.com", hint: "Inspect certificate chain, issuer, cipher, and days remaining." },
    recipe_diff_dns: { goal: "web", label: "Split DNS Check", groupLabel: "Web & DNS", placeholder: "api.example.com", hint: "Compare local router DNS answers against public resolvers." },
    split_dns_audit: { goal: "web", label: "Full Split DNS Comparison", groupLabel: "Web & DNS", placeholder: "api.example.com", hint: "Check A and AAAA parity across local and encrypted resolvers." },
    resolve_hostname: { goal: "web", label: "System DNS Lookup", groupLabel: "Web & DNS", placeholder: "api.example.com", hint: "Resolve a hostname using the system resolver." },
    local_dns_query: { goal: "web", label: "Local Router DNS Lookup", groupLabel: "Web & DNS", placeholder: "api.example.com", hint: "Query your local DNS server directly." },
    remote_dns_query: { goal: "web", label: "Public Encrypted DNS Lookup", groupLabel: "Web & DNS", placeholder: "api.example.com", hint: "Query a public DNS-over-HTTPS resolver." },
    dns_reverse_batch: { goal: "web", label: "Reverse IP Name Lookup", groupLabel: "Web & DNS", placeholder: "192.0.2.1,192.0.2.10", hint: "Look up hostnames for comma-separated IP addresses." },
    whois_query: { goal: "web", label: "Domain Registration Lookup", groupLabel: "Web & DNS", placeholder: "example.net", hint: "Retrieve domain registrar and registration status." },
    tcp_port_scan: { goal: "ports", label: "Open TCP Ports", groupLabel: "Ports & Host", placeholder: "192.0.2.10", hint: "Check which TCP service ports accept connections.", ports: true },
    recipe_host_card: { goal: "ports", label: "Device Summary Card", groupLabel: "Ports & Host", placeholder: "192.0.2.10", hint: "Combine ping, DNS, TLS, and open ports for one device.", ports: true },
    snmp_switch_port: { goal: "ports", label: "Switch Port Status", groupLabel: "Ports & Host", placeholder: "192.0.2.14", hint: "Read link speed and error counters from a switch." },
    mac_vendor_lookup: { goal: "ports", label: "Hardware Vendor Lookup", groupLabel: "Ports & Host", placeholder: "00:00:5E:00:53:10", hint: "Identify the manufacturer from a device MAC address." },
    recipe_wake_verify: { goal: "wake", label: "Wake & Confirm Online", groupLabel: "Wake", placeholder: "192.0.2.42 (optional if MAC set)", hint: "Send a Wake packet and verify device responds online.", mac: true, targetOptional: true },
    wol_wake: { goal: "wake", label: "Send Wake Packet", groupLabel: "Wake", placeholder: "00:00:5E:00:53:42", hint: "Send a Wake-on-LAN magic packet to a device MAC.", mac: true, targetOptional: true },
    recipe_lan_radar: { goal: "lan", label: "Local Network Radar", groupLabel: "Local Network (LAN)", placeholder: "192.0.2.0/24 (optional)", hint: "Discover local hardware, containers, and VMs.", targetOptional: true },
    recipe_diff_snapshot: { goal: "lan", label: "Network Changes vs. Baseline", groupLabel: "Local Network (LAN)", placeholder: "snapshot ID (optional)", hint: "Compare current devices and ports against a baseline.", targetOptional: true },
    arp_neighbor_sweep: { goal: "lan", label: "Connected Devices Sweep", groupLabel: "Local Network (LAN)", placeholder: "192.0.2.0/24 (optional)", hint: "List active devices visible on the local subnet.", targetOptional: true },
    mdns_ssdp_discover: { goal: "lan", label: "Local Service Discovery", groupLabel: "Local Network (LAN)", placeholder: "192.0.2.0/24 (optional)", hint: "Find advertised local mDNS and SSDP services.", targetOptional: true },
    render_run_digest: { goal: "history", label: "Recent Activity Summary", groupLabel: "History", placeholder: "30d (optional)", hint: "Summarize recent health and problem counts.", targetOptional: true, allowSavedDest: false }
  };

  const state = {
    mode: "locked", deadboltEnabled: true, activeTab: "checks", goalFilter: "path", lanSegment: "all", historyRange: "30d",
    demoSnapshot: null, demoJobsById: {}, lastRun: null, destinationsLoaded: false, liveJobSeq: 0,
    lanData: { physical: [], virtual: [] }, snapshotDiff: null, savedBaseline: null, lastSummary: null
  };

  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined && text !== null) n.textContent = String(text); return n; };
  const getCheckMeta = (id) => CHECKS[id] || { goal: "path", label: id || "Check", placeholder: "canary.example.net", hint: "Enter a host, IP, or URL." };
  const getCheckLabel = (id) => getCheckMeta(id).label;
  const announce = (msg) => { const l = $("a11yAnnouncer"); if (l && msg) { l.textContent = ""; globalScope.setTimeout(() => { l.textContent = String(msg); }, 20); } };
  const storeVal = (s, k, v) => { try { if (v === undefined) return s.getItem(k) || ""; if (v) s.setItem(k, v); else s.removeItem(k); } catch (_) {} return ""; };
  const badgeVariant = (raw) => /^(OK|UP|HEALTHY|PASS|MATCH|UNLOCKED|OPEN)$/i.test(String(raw || "").trim()) ? "nominal" : /^(WARN|WARNING|DEGRADED|RUNNING|DEMO)$/i.test(String(raw || "").trim()) ? "warn" : /^(FAIL|ERROR|DOWN|ALERT|LOCKED|MISMATCH)$/i.test(String(raw || "").trim()) ? "fault" : "nominal";
  const setStatusPill = (p, txt, st) => { if (!p) return; const u = String(txt || "IDLE").toUpperCase(); p.textContent = u; p.setAttribute("data-variant", "status"); p.setAttribute("data-state", st || badgeVariant(u)); };
  const fmtTime = (iso) => { const ms = iso ? Date.parse(iso) : NaN; return Number.isFinite(ms) ? new Date(ms).toISOString().replace("T", " ").slice(0, 16) + "Z" : (iso || "—"); };
  const fmtMsText = (ms) => { const n = Number(ms); return !Number.isFinite(n) ? "—" : n >= 1000 ? (n / 1000).toFixed(2) + " s" : (n >= 10 ? n.toFixed(1) : n.toFixed(2)) + " ms"; };
  const syncValidity = (inp, msg) => {
    if (!inp) return true;
    const err = inp.getAttribute("data-error") ? $(inp.getAttribute("data-error")) : null;
    inp.setCustomValidity(msg || ""); inp.setAttribute("aria-invalid", msg ? "true" : "false");
    if (err) err.textContent = msg || "";
    return !msg;
  };
  const wireRequired = (inp, msg) => { if (!inp) return; inp.addEventListener("input", () => { if (!inp.required || inp.value.trim()) syncValidity(inp, ""); }); inp.addEventListener("blur", () => { if (inp.required && !inp.value.trim()) syncValidity(inp, msg); }); };
  const wireSegmented = (id, attr, fn) => {
    const g = $(id); if (!g) return;
    g.addEventListener("click", (ev) => { const b = ev.target.closest("[" + attr + "]"); if (!b) return; g.querySelectorAll("[" + attr + "]").forEach((x) => x.setAttribute("aria-pressed", x === b ? "true" : "false")); fn(b.getAttribute(attr)); });
  };

  function populateCheckSelect(goalFilter, preferredTool) {
    const sel = $("checkSelect"); if (!sel) return;
    const goal = goalFilter || state.goalFilter || "path", frag = document.createDocumentFragment();
    Object.keys(CHECKS).forEach((id) => {
      const c = CHECKS[id];
      if (c.goal === goal) {
        const o = document.createElement("option"); o.value = id; o.textContent = c.label; frag.appendChild(o);
      }
    });
    sel.replaceChildren(frag);
    if (preferredTool && Array.from(sel.options).some((o) => o.value === preferredTool)) sel.value = preferredTool;
  }

  function setGoalFilter(goal, preferredTool) {
    const valid = goal === "web" || goal === "ports" || goal === "wake" ? goal : "path";
    state.goalFilter = valid;
    document.querySelectorAll("#goalFilterGroup [data-goal]").forEach((b) => b.setAttribute("aria-pressed", b.getAttribute("data-goal") === valid ? "true" : "false"));
    populateCheckSelect(valid, preferredTool);
    syncCheckContext();
  }

  function applyTheme(theme) {
    const next = THEMES[theme] ? theme : "white";
    document.documentElement.dataset.theme = next;
    const meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) meta.setAttribute("content", next === "dark" || next === "dark-paper" ? "dark" : "light");
    if ($("themeSelect") && $("themeSelect").value !== next) $("themeSelect").value = next;
    storeVal(globalScope.localStorage, THEME_KEY, next);
  }
  function applyDensity(density) {
    const next = density === "d3" ? "d3" : "d2";
    document.documentElement.dataset.density = next;
    document.querySelectorAll("#densityToggle [data-density]").forEach((b) => b.setAttribute("aria-pressed", b.getAttribute("data-density") === next ? "true" : "false"));
    storeVal(globalScope.localStorage, DENSITY_KEY, next);
  }
  function syncResponsiveNav() {
    const compact = globalScope.matchMedia ? globalScope.matchMedia("(max-width: 699px)").matches : globalScope.innerWidth < 700;
    document.documentElement.dataset.effectiveNav = compact ? "n4" : "n3";
  }

  async function apiFetch(url, opts) {
    const cfg = opts || {}, headers = { Accept: "application/json" };
    const req = { method: cfg.method || "GET", headers, credentials: "same-origin" };
    if (cfg.bodyObj !== undefined) { headers["Content-Type"] = "application/json"; req.body = JSON.stringify(cfg.bodyObj); }
    const res = await globalScope.fetch(url, req), raw = await res.text();
    let data = {};
    if (raw) { try { data = JSON.parse(raw); } catch (_) { data = { raw }; } }
    if ((res.status === 401 || res.status === 403) && !cfg.skipAuthRedirect && state.mode === "live") enterLockedMode("Session expired. Re-enter operator passphrase.");
    return { res, data };
  }
  function setStudioModeUI(mode, deadboltEnabled) {
    state.mode = mode; state.deadboltEnabled = Boolean(deadboltEnabled);
    if (mode === "locked") { state.destinationsLoaded = false; state.lastRun = null; state.liveJobSeq += 1; }
    if (globalScope.NetutilsDestinations) globalScope.NetutilsDestinations.setMode(mode);
    $("lockGateSection").hidden = mode !== "locked"; $("studioMain").hidden = mode === "locked"; $("demoBanner").hidden = mode !== "demo";
    const cfg = mode === "demo" ? ["DEMO", "warn", "Live Mode", "live"] : mode === "locked" ? ["LOCKED", "fault", "Demo", "demo"] :
      state.deadboltEnabled ? ["UNLOCKED", "ok", "Lock", "lock"] : ["OPEN", "ok", "Demo", "demo"];
    setStatusPill($("deadboltPill"), cfg[0], cfg[1]);
    $("lockModeBtn").textContent = cfg[2]; $("lockModeBtn").setAttribute("data-action", cfg[3]);
  }
  function enterLockedMode(msg) { setStudioModeUI("locked", true); syncValidity($("passphraseInput"), msg || ""); announce(msg || "Network studio locked."); }

  function renderSummary(summary) {
    const s = summary || state.lastSummary || {};
    state.lastSummary = s;
    const totalTargets = Number(s.total_targets ?? 0);
    const hasSched = s.cron_health_pct !== null && s.cron_health_pct !== undefined && totalTargets > 0;
    const pct = Number(s.cron_health_pct), clamped = hasSched && Number.isFinite(pct) ? Math.max(0, Math.min(100, pct)) : 0;
    $("kpiUptimeVal").textContent = hasSched ? clamped.toFixed(1) + "%" : "—";
    $("kpiUptimeProgress").setAttribute("aria-valuenow", String(Math.round(clamped)));
    $("kpiUptimeBar").setAttribute("width", String(clamped));
    const card = $("kpiUptimeCard");
    if (card) { if (hasSched) card.setAttribute("data-state", clamped >= 95 ? "ok" : clamped >= 80 ? "warn" : "fault"); else card.removeAttribute("data-state"); }
    $("kpiUptimeMeta").textContent = hasSched ? ((s.healthy_targets ?? 0) + " / " + totalTargets + " checks healthy") : "No scheduled checks yet";

    const alerts = Number(s.active_alerts ?? 0);
    $("kpiProblemsVal").textContent = String(alerts);
    $("kpiProblemsMeta").textContent = alerts > 0 ? "Targets needing attention" : "All targets healthy";

    const dests = globalScope.NetutilsDestinations ? globalScope.NetutilsDestinations.getDestinations() : [];
    const destCount = state.destinationsLoaded ? dests.length : Number(s.saved_destinations ?? 0);
    $("kpiDestinationsVal").textContent = String(destCount);
    $("kpiDestinationsMeta").textContent = state.destinationsLoaded
      ? (dests.filter((d) => d.pinned).length + " pinned · " + dests.filter((d) => d.monitor_enabled).length + " monitored")
      : "Saved check targets";
    const usedMb = Number(s.archive_mb), maxMb = Number(s.archive_max_mb || 256), jobCount = Number(s.retained_jobs ?? 0);
    $("kpiHistorySizeVal").textContent = Number.isFinite(usedMb) ? usedMb.toFixed(1) + " MB of " + Math.round(maxMb) + " MB" : "—";
    $("kpiHistorySizeMeta").textContent = jobCount + (jobCount === 1 ? " saved run (30d limit)" : " saved runs (30d limit)");
  }

  const renderTableRows = (tbodyEl, items, rowSpec) => globalScope.NetutilsResults.renderTableRows(tbodyEl, items, rowSpec);
  const makeSvgBar = (rttMs) => globalScope.NetutilsResults.makeSvgBar(rttMs);

  function isHostChanged(host) {
    const d = state.snapshotDiff;
    if (!d) return false;
    const all = [].concat(d.added || [], d.changed || []).join(" ").toLowerCase();
    return Boolean((host.ip && all.includes(String(host.ip).toLowerCase())) || (host.hostname && all.includes(String(host.hostname).toLowerCase())));
  }

  function upsertBaselineOption(id, selectNow) {
    const sel = $("baselineSelect"), clean = String(id || "").trim();
    if (!sel || !clean || clean === "custom" || clean === "current") return;
    if (!Array.from(sel.options).some((o) => o.value === clean)) { const o = document.createElement("option"); o.value = clean; o.textContent = clean; sel.insertBefore(o, sel.lastElementChild); }
    if (selectNow || !sel.value) { sel.value = clean; $("customBaselineWrap").hidden = sel.value !== "custom"; }
  }
  const getSelectedBaseline = () => { const sel = $("baselineSelect"); return !sel ? "" : sel.value === "custom" ? ($("baselineInput") ? $("baselineInput").value.trim() : "") : sel.value; };
  const deriveLanCidr = () => {
    const cidrRe = /^(?:\d{1,3}\.){3}\d{1,3}\/(?:[0-9]|[12]\d|3[0-2])$/;
    const lanQ = ($("lanFilterInput") ? $("lanFilterInput").value : "").trim(), tgtQ = ($("targetInput") ? $("targetInput").value : "").trim();
    return cidrRe.test(lanQ) ? lanQ : (cidrRe.test(tgtQ) ? tgtQ : "");
  };

  function ingestLanData(lan) {
    const src = lan || {};
    state.lanData = { physical: Array.isArray(src.physical) ? src.physical : [], virtual: Array.isArray(src.virtual) ? src.virtual : [] };
    if (src.snapshot_diff) state.snapshotDiff = src.snapshot_diff;
    upsertBaselineOption(src.baseline_id, false);
    applyLanFilters();
  }

  function applyLanFilters() {
    const q = ($("lanFilterInput") ? $("lanFilterInput").value : "").trim().toLowerCase(), onlyChg = state.lanSegment === "changed";
    const matches = (h) => (!q || [h.ip, h.hostname, h.mac, h.vendor, h.runtime, h.open_ports].join(" ").toLowerCase().includes(q)) && (!onlyChg || isHostChanged(h));
    const showUaa = state.lanSegment === "all" || state.lanSegment === "uaa" || onlyChg, showLaa = state.lanSegment === "all" || state.lanSegment === "laa" || onlyChg;
    const phys = showUaa ? state.lanData.physical.filter(matches) : [], virt = showLaa ? state.lanData.virtual.filter(matches) : [];
    const mkBtn = (lbl, act, h) => { const b = el("button", "va-btn va-btn-xs va-btn-ghost", lbl); b.type = "button"; b.dataset.lanAction = act; b.dataset.ip = h.ip || ""; b.dataset.mac = h.mac || ""; b.dataset.name = h.hostname || h.ip || ""; b.dataset.seg = h.segment || "uaa"; return b; };
    const spec = (isV) => (h) => {
      const rtt = el("div", "rtt-cell"), acts = el("div", "row-actions");
      if (h.rtt_ms !== undefined) rtt.append(makeSvgBar(h.rtt_ms), el("span", "tabular-nums", Number(h.rtt_ms).toFixed(2) + " ms")); else rtt.append(el("span", "", "—"));
      if (Array.isArray(h.open_ports) && h.open_ports.length) rtt.append(el("span", "card-meta", " · [" + h.open_ports.join(", ") + "]"));
      acts.append(mkBtn("Ping", "ping", h), mkBtn("Check Ports", "ports", h));
      if (h.mac) acts.append(mkBtn("Wake", "wake", h));
      acts.append(mkBtn("Save", "save", h));
      return { cells: [["IP Address", h.ip, "tabular-nums"], ["Device Name", (h.hostname || "—") + (isHostChanged(h) ? " (Changed)" : "")], ["MAC Address", h.mac || "—", "tabular-nums"], [isV ? "Runtime / Vendor" : "Vendor", isV && h.runtime ? h.runtime + " · " + (h.vendor || "") : (h.vendor || "—")], ["Response & Open Ports", rtt], ["Actions", acts]] };
    };
    renderTableRows($("lanPhysicalBody"), phys, spec(false)); renderTableRows($("lanVirtualBody"), virt, spec(true));
    $("lanPhysicalCount").textContent = phys.length + (phys.length === 1 ? " device" : " devices");
    $("lanVirtualCount").textContent = virt.length + (virt.length === 1 ? " device" : " devices");
    document.querySelector('[data-segment-section="uaa"]').hidden = !showUaa || phys.length === 0;
    document.querySelector('[data-segment-section="laa"]').hidden = !showLaa || virt.length === 0;
    const empty = phys.length + virt.length === 0;
    $("lanEmptyState").hidden = !empty; $("lanTableWrap").hidden = empty;
    if (empty) $("lanEmptyMessage").textContent = q || state.lanSegment !== "all" ? "No local network devices match the active filter." : "No devices discovered yet. Click Scan Network to inspect your LAN.";
  }

  function renderSnapshotDiff(diff) {
    const d = diff || {}; state.snapshotDiff = d; $("snapshotDiffPanel").hidden = false;
    upsertBaselineOption(d.baseline_id, false); upsertBaselineOption(d.current_id, false);
    $("snapshotDiffMeta").textContent = (d.baseline_id || "baseline") + " -> " + (d.current_id || "current");
    [["diffAddedList", "diffAddedCount", d.added], ["diffRemovedList", "diffRemovedCount", d.removed], ["diffChangedList", "diffChangedCount", d.changed]].forEach(([lId, cId, raw]) => {
      const list = Array.isArray(raw) ? raw : [], frag = document.createDocumentFragment();
      $(cId).textContent = String(list.length);
      if (!list.length) frag.appendChild(el("li", "diff-item-empty", "None"));
      list.forEach((item) => frag.appendChild(el("li", "diff-item", typeof item === "string" ? item : JSON.stringify(item))));
      $(lId).replaceChildren(frag);
    });
    applyLanFilters();
  }

  function renderHistory(cronData, jobsOverride) {
    const cron = cronData || {}, jobs = Array.isArray(jobsOverride) ? jobsOverride : (Array.isArray(cron.jobs) ? cron.jobs : []), ts = Array.isArray(cron.timeseries) ? cron.timeseries : [];
    const wl = Array.isArray(cron.watchlist) ? cron.watchlist : [];
    const sampleCount = Number(cron.summary && cron.summary.sample_count ? cron.summary.sample_count : (ts.reduce((a, b) => a + Number(b.total_count || 0), 0) || jobs.length));
    $("historyWarmupBanner").hidden = !(Boolean(cron.warmup) || sampleCount < 10);
    $("historyWarmupText").textContent = "Warming up — " + sampleCount + (sampleCount === 1 ? " check collected" : " checks collected") + (sampleCount < 10 ? " (collecting baseline samples)." : ".");
    $("historySampleMeta").textContent = sampleCount + (sampleCount === 1 ? " check" : " checks") + " · " + state.historyRange;
    if (globalScope.NetutilsCharts) globalScope.NetutilsCharts.renderHistoryTimeline($("historyTimelineHost"), ts);
    $("watchlistEmptyState").hidden = wl.length > 0; $("watchlistTableWrap").hidden = wl.length === 0;
    renderTableRows($("watchlistBody"), wl, (w) => {
      const pill = el("span", "va-pill", String(w.health || "OK").toUpperCase()), wrap = el("div", "uptime-strip-cell"), segs = el("span", "uptime-segments");
      setStatusPill(pill, pill.textContent);
      const slots = Array.isArray(cron.strip) && cron.strip.length ? cron.strip.slice(-8) : [], cnt = Math.max(6, slots.length);
      for (let i = 0; i < cnt; i += 1) {
        const seg = el("span", "uptime-seg"), rawSt = slots[i] ? String(slots[i].status || "OK").toUpperCase() : (i === cnt - 1 ? pill.textContent : "OK");
        seg.setAttribute("data-state", rawSt === "FAIL" ? "fail" : rawSt === "WARN" ? "warn" : "ok");
        segs.appendChild(seg);
      }
      wrap.append(segs, el("span", "tabular-nums card-meta", w.uptime_pct !== undefined ? Number(w.uptime_pct).toFixed(1) + "%" : (w.hysteresis || "Healthy")));
      const rtt = (w.avg_ms !== undefined ? Number(w.avg_ms).toFixed(1) : "—") + " / " + (w.max_ms !== undefined ? Number(w.max_ms).toFixed(1) : "—") + " ms";
      return { cells: [["Destination", w.target], ["Check", getCheckLabel(w.check)], ["Status", pill], ["Uptime & Trend", wrap], ["Avg / Peak Time", rtt, "tabular-nums"], ["Last Checked", fmtTime(w.last_tick), "tabular-nums"]] };
    });
    $("jobArchiveEmpty").hidden = jobs.length > 0; $("jobArchiveTableWrap").hidden = jobs.length === 0;
    renderTableRows($("jobArchiveBody"), jobs, (job) => {
      const btn = el("button", "va-btn va-btn-xs va-btn-ghost tabular-nums", (job.job_id || "—").slice(0, 22)), pill = el("span", "va-pill", String(job.status || "OK").toUpperCase());
      btn.type = "button"; setStatusPill(pill, pill.textContent);
      return { jobId: job.job_id || "", cells: [["Run", btn], ["Check", getCheckLabel(job.tool)], ["Destination", job.target], ["Status", pill], ["Summary", job.summary || "—"], ["Recorded", fmtTime(job.created_at), "tabular-nums"]] };
    });
    $("jobArchiveCount").textContent = jobs.length + (jobs.length === 1 ? " run" : " runs");
  }

  function buildDemoOutcome(tool, target, extra) {
    const snap = state.demoSnapshot || {}, jobs = (snap.cron && snap.cron.jobs) || [];
    const tpl = (tool === "recipe_diff_ping" && snap.default_run) || (snap.tool_runs && snap.tool_runs[tool]) || jobs.find((j) => j.tool === tool) || snap.default_run || {};
    const tgt = target || (extra && extra.mac) || (snap.default_targets && snap.default_targets[tool]) || "canary.example.net";
    return {
      job_id: "job-demo-" + Date.now().toString(36), tool, target: tgt, status: tpl.status || "OK", duration_ms: tpl.duration_ms || 14,
      summary: tpl.summary || (getCheckLabel(tool) + " completed for " + tgt + "."), created_at: new Date().toISOString(), expires_at: tpl.expires_at || "2026-12-26T23:00:00Z",
      waterfall: tpl.waterfall, whiskers: tpl.whiskers, tls_health: tpl.tls_health, dns_comparisons: tpl.dns_comparisons, data: tpl.data,
      lan_inventory: tool === "recipe_lan_radar" ? snap.lan_inventory : null,
      snapshot_diff: tool === "recipe_diff_snapshot" && snap.lan_inventory ? snap.lan_inventory.snapshot_diff : null
    };
  }

  async function executeRun(payload, triggerBtn, opts) {
    if (opts && opts.focusResult && globalScope.NetutilsResults) globalScope.NetutilsResults.beginRunFocus(payload.tool, payload.target, state.mode === "live");
    if (state.mode === "demo") {
      const out = buildDemoOutcome(payload.tool, payload.target, payload.args);
      state.demoJobsById[out.job_id] = out;
      if (globalScope.NetutilsResults) globalScope.NetutilsResults.renderOutcome(out, true);
      announce("Completed " + getCheckLabel(payload.tool) + ".");
      return out;
    }
    state.liveJobSeq += 1;
    const btn = triggerBtn || $("runCheckBtn");
    if (btn) btn.setAttribute("aria-busy", "true");
    setStatusPill($("runStatusBadge"), "[RUNNING]", "warn"); announce("Running " + getCheckLabel(payload.tool) + "...");
    try {
      const r = await apiFetch("./api/run", { method: "POST", bodyObj: Object.assign({ style: "json" }, payload) });
      if (!r.res.ok) { setStatusPill($("runStatusBadge"), "[FAIL]", "fault"); $("runResultSummary").textContent = (r.data && (r.data.error || r.data.message)) || "Check failed."; announce("Check failed."); return null; }
      if (globalScope.NetutilsResults) globalScope.NetutilsResults.renderOutcome(r.data, true);
      announce("Completed " + getCheckLabel(payload.tool) + "."); loadLiveWorkspace();
      return r.data;
    } catch (_) { setStatusPill($("runStatusBadge"), "[FAIL]", "fault"); announce("Network error while running check."); return null; }
    finally { if (btn) btn.setAttribute("aria-busy", "false"); }
  }

  function applyDemoRange(range) {
    const snap = state.demoSnapshot; if (!snap || !snap.cron) return;
    const tsMap = snap.cron.timeseries_by_range || {}, ts = Array.isArray(tsMap[range]) ? tsMap[range] : (snap.cron.timeseries || []);
    const refMs = Date.parse(snap.generated_at || "2026-11-26T23:00:00Z"), maxAge = (range === "24h" ? 1 : range === "7d" ? 7 : 30) * 86400000;
    const jobs = (snap.cron.jobs || []).filter((j) => { const t = Date.parse(j.created_at || ""); return !Number.isFinite(t) || !Number.isFinite(refMs) || (refMs - t) <= maxAge; });
    renderHistory({ warmup: snap.cron.warmup, strip: snap.cron.strip, watchlist: snap.cron.watchlist, timeseries: ts, summary: snap.summary }, jobs);
  }

  async function loadLiveWorkspace() {
    const wsSeq = state.liveJobSeq;
    const [cronPair, jobsPair] = await Promise.all([apiFetch("./api/cron?period=30d&range=" + encodeURIComponent(state.historyRange)), apiFetch("./api/jobs")]);
    if (globalScope.NetutilsDestinations) await globalScope.NetutilsDestinations.refresh();
    const cronRes = cronPair.data || {}, jobsRes = jobsPair.data, jobs = Array.isArray(jobsRes) ? jobsRes : (jobsRes && Array.isArray(jobsRes.jobs) ? jobsRes.jobs : (cronRes.jobs || []));
    renderSummary(cronRes.summary || (jobsRes && jobsRes.summary) || { retained_jobs: jobs.length });
    renderHistory(cronRes, jobs);
    if (cronRes.lan_inventory) ingestLanData(cronRes.lan_inventory); else applyLanFilters();
    if (jobs.length > 0 && !state.lastRun && jobs[0].job_id && wsSeq === state.liveJobSeq) {
      const jobSeq = ++state.liveJobSeq;
      const d = await apiFetch("./api/jobs/" + encodeURIComponent(jobs[0].job_id) + "?style=json");
      if (jobSeq === state.liveJobSeq && !state.lastRun && state.mode === "live" && d.res.ok && globalScope.NetutilsResults) globalScope.NetutilsResults.renderOutcome(d.data, true);
    }
  }

  function setActiveTab(tabId, opts) {
    const valid = tabId === "lan" || tabId === "history" ? tabId : "checks", map = { checks: "panelChecks", lan: "panelLan", history: "panelHistory" };
    state.activeTab = valid;
    document.querySelectorAll("#studioTabs [role='tab']").forEach((t) => { const on = t.getAttribute("data-tab") === valid; t.setAttribute("aria-selected", on ? "true" : "false"); t.setAttribute("tabindex", on ? "0" : "-1"); if (on && opts && opts.focusTab) t.focus(); });
    document.querySelectorAll("#mobileNavDock [data-tab]").forEach((d) => d.setAttribute("aria-pressed", d.getAttribute("data-tab") === valid ? "true" : "false"));
    Object.keys(map).forEach((k) => { const p = $(map[k]); if (p) { if (k === valid) p.removeAttribute("hidden"); else p.setAttribute("hidden", "until-found"); } });
    if (globalScope.NetutilsCharts) globalScope.NetutilsCharts.refreshInContainer($(map[valid]));
  }

  function syncCheckContext() {
    const meta = getCheckMeta($("checkSelect").value), targetEl = $("targetInput");
    $("portsWrap").hidden = !meta.ports; $("wakeMacWrap").hidden = !meta.mac;
    $("customPortsWrap").hidden = !meta.ports || $("portsPresetSelect").value !== "custom";
    if ($("customBaselineWrap")) $("customBaselineWrap").hidden = $("baselineSelect").value !== "custom";
    targetEl.placeholder = meta.placeholder; $("targetHint").textContent = meta.hint;
    targetEl.required = !meta.targetOptional && !Boolean(meta.mac && $("wakeMacInput").value.trim());
    if (!targetEl.required) syncValidity(targetEl, "");
  }

  function buildCheckPayload() {
    const tool = $("checkSelect").value, meta = getCheckMeta(tool), mac = $("wakeMacInput").value.trim(), payload = { tool, target: $("targetInput").value.trim() };
    if (meta.ports) payload.ports = $("portsPresetSelect").value === "custom" ? $("customPortsInput").value.trim() : $("portsPresetSelect").value;
    if (meta.mac && mac) { payload.args = { mac }; if (!payload.target) payload.target = mac; }
    return payload;
  }

  const bindDialogDismiss = (dlg) => globalScope.NetutilsResults.bindDialogDismiss(dlg);

  async function handleUnlockSubmit(ev) {
    ev.preventDefault();
    const passInput = $("passphraseInput"), candidate = passInput.value.trim(), btn = $("unlockSubmitBtn");
    if (!syncValidity(passInput, candidate ? "" : "Enter the operator passphrase.")) return passInput.focus();
    btn.setAttribute("aria-busy", "true");
    try {
      const r = await apiFetch("./api/unlock", { method: "POST", bodyObj: { passphrase: candidate }, skipAuthRedirect: true });
      if (!r.res.ok || r.data.locked === true) { const msg = r.res.status === 429 || r.data.locked_out ? "Too many failed attempts. Try again shortly." : "Invalid operator passphrase."; syncValidity(passInput, msg); announce(msg); return passInput.focus(); }
      passInput.value = ""; syncValidity(passInput, ""); setStudioModeUI("live", r.data.enabled !== false && r.data.deadbolt_enabled !== false);
      announce("Network studio unlocked."); loadLiveWorkspace();
    } catch (_) { syncValidity(passInput, "Unable to reach studio unlock endpoint."); } finally { btn.setAttribute("aria-busy", "false"); }
  }

  function bindCheckAndLanEvents() {
    ["checkSelect", "portsPresetSelect", "baselineSelect", "wakeMacInput"].forEach((id) => $(id).addEventListener("change", syncCheckContext));
    $("wakeMacInput").addEventListener("input", syncCheckContext);
    $("checkForm").addEventListener("submit", (ev) => {
      ev.preventDefault(); syncCheckContext();
      const targetEl = $("targetInput"), payload = buildCheckPayload();
      if (targetEl.required && !syncValidity(targetEl, targetEl.value.trim() ? "" : "Enter a destination host, IP, or URL.")) return targetEl.focus();
      executeRun(payload, $("runCheckBtn"), { focusResult: globalScope.innerWidth < 820 });
    });
    wireSegmented("goalFilterGroup", "data-goal", (g) => setGoalFilter(g));
    $("jumpToLanBtn").addEventListener("click", () => { setActiveTab("lan"); globalScope.requestAnimationFrame(() => $("lanRadarBtn").focus()); });
    $("archiveRunCheckBtn").addEventListener("click", () => { setActiveTab("checks"); globalScope.requestAnimationFrame(() => $("targetInput").focus()); });
    $("saveCurrentDestBtn").addEventListener("click", () => { if (globalScope.NetutilsDestinations) globalScope.NetutilsDestinations.openEditor({ name: $("targetInput").value.trim(), target: $("targetInput").value.trim(), mac: $("wakeMacInput").value.trim(), default_check: $("checkSelect").value }); });
    $("lanFilterInput").addEventListener("input", applyLanFilters);
    $("lanClearFiltersBtn").addEventListener("click", () => {
      $("lanFilterInput").value = ""; state.lanSegment = "all";
      document.querySelectorAll("#lanSegmentGroup [data-segment]").forEach((b) => b.setAttribute("aria-pressed", b.getAttribute("data-segment") === "all" ? "true" : "false"));
      applyLanFilters(); $("lanFilterInput").focus();
    });
    $("lanRadarBtn").addEventListener("click", () => executeRun({ tool: "recipe_lan_radar", target: deriveLanCidr() }, $("lanRadarBtn")));
    $("saveSnapshotBtn").addEventListener("click", async () => {
      const snapId = "snap-" + new Date().toISOString().replace(/[-:TZ.]/g, "").slice(0, 14);
      if (state.mode === "demo") { state.savedBaseline = { id: snapId }; upsertBaselineOption(snapId, true); return announce("Saved network baseline " + snapId + "."); }
      const cidr = deriveLanCidr(), args = cidr ? { save_as: snapId, cidr } : { save_as: snapId };
      const out = await executeRun({ tool: "recipe_diff_snapshot", target: cidr, baseline: snapId, args }, $("saveSnapshotBtn"));
      if (!out) return;
      const diff = out.snapshot_diff || {}, savedId = (diff.current_id && diff.current_id !== "current" ? diff.current_id : diff.baseline_id) || snapId;
      state.savedBaseline = { id: savedId }; upsertBaselineOption(savedId, true); announce("Saved network baseline " + savedId + ".");
    });
    $("diffSnapshotBtn").addEventListener("click", () => {
      const chosen = getSelectedBaseline();
      if (state.mode === "demo" && state.demoSnapshot && state.demoSnapshot.lan_inventory) {
        const baseDiff = state.demoSnapshot.lan_inventory.snapshot_diff || {};
        return renderSnapshotDiff(chosen && chosen !== baseDiff.baseline_id ? Object.assign({}, baseDiff, { baseline_id: chosen }) : baseDiff);
      }
      const baseline = chosen || (state.savedBaseline && state.savedBaseline.id) || "";
      if (!baseline) { $("snapshotDiffPanel").hidden = false; $("snapshotDiffMeta").textContent = "No baseline saved yet — click Save Baseline first."; return announce("Save a baseline first or choose a snapshot ID."); }
      const cidr = deriveLanCidr();
      executeRun({ tool: "recipe_diff_snapshot", target: cidr, baseline, args: cidr ? { cidr } : undefined }, $("diffSnapshotBtn"));
    });
    $("lanTableWrap").addEventListener("click", (ev) => {
      const btn = ev.target.closest("[data-lan-action]"); if (!btn) return;
      const act = btn.dataset.lanAction, ip = btn.dataset.ip, mac = btn.dataset.mac, name = btn.dataset.name, seg = btn.dataset.seg;
      if (act === "save") return globalScope.NetutilsDestinations.openEditor({ name, target: ip, mac, category: seg === "laa" ? "Containers" : "LAN", default_check: "ping" });
      setActiveTab("checks");
      setGoalFilter(act === "ports" ? "ports" : act === "wake" ? "wake" : "path", act === "ports" ? "tcp_port_scan" : act === "wake" ? "recipe_wake_verify" : "ping");
      $("targetInput").value = ip; if (act === "wake") $("wakeMacInput").value = mac;
      syncCheckContext(); executeRun(buildCheckPayload(), btn, { focusResult: true });
    });
  }

  function bindGlobalEvents() {
    $("themeSelect").addEventListener("change", (ev) => applyTheme(ev.target.value));
    wireSegmented("densityToggle", "data-density", applyDensity);
    wireSegmented("lanSegmentGroup", "data-segment", (seg) => { state.lanSegment = seg; applyLanFilters(); });
    wireSegmented("historyRangeGroup", "data-range", (r) => { state.historyRange = r; if (state.mode === "demo") applyDemoRange(r); else loadLiveWorkspace(); });
    wireRequired($("passphraseInput"), "Enter the operator passphrase."); wireRequired($("targetInput"), "Enter a destination host, IP, or URL.");
    $("unlockForm").addEventListener("submit", handleUnlockSubmit);
    $("lockModeBtn").addEventListener("click", async () => {
      const act = $("lockModeBtn").getAttribute("data-action");
      if (act === "live") globalScope.location.assign("./"); else if (act === "demo") globalScope.location.assign("?demo=1");
      else if (act === "lock") { try { await apiFetch("./api/lock", { method: "POST", skipAuthRedirect: true }); } finally { enterLockedMode(""); } }
    });
    const jumpHistory = (secId) => { setActiveTab("history"); globalScope.requestAnimationFrame(() => { if (globalScope.NetutilsResults) globalScope.NetutilsResults.focusTargetSection($(secId)); }); };
    $("kpiUptimeCard").addEventListener("click", () => jumpHistory("cronHealthCard"));
    $("kpiProblemsCard").addEventListener("click", () => jumpHistory("cronHealthCard"));
    $("kpiHistoryCard").addEventListener("click", () => jumpHistory("jobArchiveCard"));
    $("kpiDestinationsCard").addEventListener("click", () => {
      const dests = globalScope.NetutilsDestinations ? globalScope.NetutilsDestinations.getDestinations() : [];
      if (!dests.length && globalScope.NetutilsDestinations) return globalScope.NetutilsDestinations.openEditor({});
      setActiveTab("checks"); globalScope.requestAnimationFrame(() => { if (globalScope.NetutilsResults) globalScope.NetutilsResults.focusTargetSection($("savedDestinationsSection")); });
    });
    $("refreshHistoryBtn").addEventListener("click", () => { if (state.mode === "demo") applyDemoRange(state.historyRange); else loadLiveWorkspace(); announce("History refreshed."); });
    $("jobArchiveBody").addEventListener("click", (ev) => { const row = ev.target.closest("tr[data-job-id]"); if (row && globalScope.NetutilsResults) globalScope.NetutilsResults.openJobDrawer(row.getAttribute("data-job-id")); });
    document.addEventListener("click", (ev) => { const vb = ev.target.closest('[data-qe-view="chart"]'); if (vb && globalScope.NetutilsCharts) globalScope.NetutilsCharts.refreshInContainer(vb.closest(".va-figure-card")); });
    [$("studioTabs"), $("mobileNavDock")].forEach((n) => n.addEventListener("click", (ev) => { const b = ev.target.closest("[data-tab]"); if (b) setActiveTab(b.getAttribute("data-tab")); }));
    [["panelChecks", "checks"], ["panelLan", "lan"], ["panelHistory", "history"]].forEach(([id, tab]) => { if ($(id)) $(id).addEventListener("beforematch", () => setActiveTab(tab)); });
  }

  function hydrateDemoSnapshot(snap) {
    state.demoSnapshot = snap || {};
    if (snap.banner) $("demoBannerText").textContent = snap.banner;
    setStudioModeUI("demo", false);
    if (globalScope.NetutilsDestinations) globalScope.NetutilsDestinations.setDestinations(snap.destinations || []);
    renderSummary(snap.summary);
    if (snap.default_run) { state.demoJobsById[snap.default_run.job_id] = snap.default_run; if (globalScope.NetutilsResults) globalScope.NetutilsResults.renderOutcome(snap.default_run, true); }
    if (snap.lan_inventory) ingestLanData(snap.lan_inventory);
    applyDemoRange(state.historyRange);
  }

  async function init() {
    setGoalFilter("path", "recipe_diff_ping"); applyTheme(document.documentElement.dataset.theme || "white"); applyDensity(document.documentElement.dataset.density || "d2"); syncResponsiveNav();
    if (globalScope.matchMedia) globalScope.matchMedia("(max-width: 699px)").addEventListener("change", syncResponsiveNav);
    globalScope.addEventListener("resize", syncResponsiveNav);
    if (globalScope.NetutilsResults) globalScope.NetutilsResults.init({
      getCheckLabel, renderTableRows, setStatusPill, badgeVariant, fmtTime, fmtMsText, bindDialogDismiss, ingestLanData, renderSnapshotDiff,
      onMainRunRendered: (run) => { state.lastRun = run; state.liveJobSeq += 1; },
      loadJobById: async (jobId) => {
        if (state.mode === "demo") { const list = (state.demoSnapshot && state.demoSnapshot.cron && state.demoSnapshot.cron.jobs) || []; return state.demoJobsById[jobId] || list.find((i) => i.job_id === jobId) || state.demoSnapshot.default_run; }
        const r = await apiFetch("./api/jobs/" + encodeURIComponent(jobId) + "?style=json"); return r.res.ok ? r.data : null;
      },
      runAgainForCompare: async (past) => {
        if (state.mode === "demo") { const f = buildDemoOutcome(past.tool, past.target); f.duration_ms = Math.max(1, Math.round(Number(past.duration_ms || 14) * 0.85)); if (Array.isArray(f.whiskers)) f.whiskers = f.whiskers.map((w) => Object.assign({}, w, { avgMs: Number((Number(w.avgMs || 0) * 0.88).toFixed(2)) })); return f; }
        const r = await apiFetch("./api/run", { method: "POST", bodyObj: { tool: past.tool, target: past.target, style: "json" } });
        if (r.res.ok) { loadLiveWorkspace(); return r.data; } return null;
      }
    });
    if (globalScope.NetutilsDestinations) globalScope.NetutilsDestinations.init({
      apiFetch, announce, getCheckLabel, renderTableRows, wireRequired, syncValidity, bindDialogDismiss, runDemoTool: buildDemoOutcome,
      getCheckCatalog: () => Object.keys(CHECKS).map((id) => Object.assign({ id }, CHECKS[id])),
      onBeforeRun: (tool, target, isAsync) => { if (globalScope.NetutilsResults) globalScope.NetutilsResults.beginRunFocus(tool, target, isAsync); },
      onFocusSection: (sec) => { setActiveTab("checks"); globalScope.requestAnimationFrame(() => { if (globalScope.NetutilsResults) globalScope.NetutilsResults.focusTargetSection(sec); }); },
      onLiveWorkspaceRefresh: () => { if (state.mode === "live") loadLiveWorkspace(); },
      onSelectPinned: (d) => {
        const m = getCheckMeta(d.default_check);
        if (m.goal === "path" || m.goal === "web" || m.goal === "ports" || m.goal === "wake") {
          setGoalFilter(m.goal, d.default_check); $("targetInput").value = d.target || ""; $("wakeMacInput").value = d.mac || ""; syncCheckContext();
          executeRun(buildCheckPayload(), null, { focusResult: true });
        } else executeRun({ tool: d.default_check || "recipe_diff_ping", target: d.target || "" }, null, { focusResult: true });
      },
      onSelectWakeMac: (d) => { $("wakeMacInput").value = d.mac || ""; if (!$("targetInput").value.trim()) $("targetInput").value = d.target || ""; syncCheckContext(); announce("Selected MAC for " + d.name + "."); },
      onShowOutcome: (out) => { if (globalScope.NetutilsResults) globalScope.NetutilsResults.renderOutcome(out, true); },
      onDestinationsChanged: () => { state.destinationsLoaded = true; renderSummary(state.lastSummary); }
    });
    bindCheckAndLanEvents(); bindGlobalEvents(); syncCheckContext();
    if (new URLSearchParams(globalScope.location.search).get("demo") === "1" || globalScope.NETUTILS_STATIC_DEMO === true) {
      if (globalScope.NETUTILS_DEMO_SNAPSHOT) return hydrateDemoSnapshot(globalScope.NETUTILS_DEMO_SNAPSHOT);
      try { let res = await globalScope.fetch("./api/demo_snapshot", { headers: { Accept: "application/json" } }); if (!res.ok) res = await globalScope.fetch("./demo_snapshots/demo_snapshot.json", { headers: { Accept: "application/json" } }); hydrateDemoSnapshot(await res.json()); } catch (_) { announce("Unable to load sample workspace data."); }
      return;
    }
    try { const r = await apiFetch("./api/status", { skipAuthRedirect: true }); if (!r.res.ok || r.data.locked === true) return enterLockedMode(""); setStudioModeUI("live", r.data.enabled !== false && r.data.deadbolt_enabled !== false); loadLiveWorkspace(); } catch (_) { enterLockedMode(""); }
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})(typeof window !== "undefined" ? window : globalThis);
