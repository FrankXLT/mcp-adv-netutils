(function (globalScope) {
  "use strict";

  const SURFACES = {
    main: {
      cardId: "runProgressCard",
      labelId: "runProgressLabel",
      hintId: "runProgressHint",
      timerId: "runProgressTimer",
      cancelId: "runCancelBtn"
    },
    drawer: {
      cardId: "drawerProgressCard",
      labelId: "drawerProgressLabel",
      hintId: "drawerProgressHint",
      timerId: "drawerProgressTimer",
      cancelId: "drawerCancelBtn"
    }
  };

  const TOOL_HINTS = {
    mtr_path_quality: "Probing hops in parallel waves (typically 2-5s)...",
    recipe_path_autopsy: "Probing hops in parallel waves (typically 2-5s)...",
    traceroute: "Tracing route with ICMP/TCP/UDP fallback...",
    recipe_diff_ping: "Measuring round-trip latency and jitter...",
    ping: "Measuring round-trip latency and jitter...",
    arp_neighbor_sweep: "Scanning LAN neighbors and ports...",
    recipe_lan_radar: "Scanning LAN neighbors and ports...",
    recipe_diff_snapshot: "Comparing discovered hosts and ports against baseline...",
    mdns_ssdp_discover: "Discovering local mDNS and SSDP services...",
    mtu_path_probe: "Probing path packet size limits without fragmentation...",
    recipe_diff_http: "Timing DNS, TCP connect, TLS handshake, and first byte...",
    http_ping: "Timing DNS, TCP connect, TLS handshake, and first byte...",
    tls_certificate_check: "Inspecting TLS certificate chain and expiry...",
    recipe_diff_dns: "Querying DNS resolvers and comparing answers...",
    split_dns_audit: "Querying DNS resolvers and comparing answers...",
    resolve_hostname: "Resolving hostname with system DNS...",
    local_dns_query: "Querying local router DNS...",
    remote_dns_query: "Querying public encrypted DNS...",
    dns_reverse_batch: "Looking up reverse PTR records...",
    tcp_port_scan: "Probing target TCP ports...",
    recipe_host_card: "Gathering ping, DNS, TLS, and port status...",
    snmp_switch_port: "Reading switch port counters...",
    mac_vendor_lookup: "Looking up hardware vendor...",
    whois_query: "Querying domain registration records...",
    recipe_wake_verify: "Sending Wake packet and verifying online status...",
    wol_wake: "Sending Wake-on-LAN magic packet...",
    pinned_sweep: "Scanning pinned destinations in parallel..."
  };

  const activeRuns = { main: null, drawer: null };
  let runCounter = 0;

  const $ = (id) => document.getElementById(id);
  const nowMs = () => (globalScope.performance && typeof globalScope.performance.now === "function" ? globalScope.performance.now() : Date.now());

  function announce(msg) {
    const live = $("a11yAnnouncer");
    if (!live || !msg) return;
    live.textContent = "";
    globalScope.setTimeout(() => { live.textContent = String(msg); }, 20);
  }

  function describeCheckHint(toolName, target) {
    const key = String(toolName || "").trim();
    if (TOOL_HINTS[key]) return TOOL_HINTS[key];
    return target ? "Running diagnostic check..." : "Running diagnostic check...";
  }

  function isAbortError(err, token) {
    if (err && err.name === "AbortError") return true;
    return Boolean(token && token.signal && token.signal.aborted);
  }

  function setTriggerBusy(btn, runningLabel) {
    if (!btn) return;
    btn.setAttribute("aria-busy", "true");
    btn.disabled = true;
    if (runningLabel && btn.dataset) {
      if (btn.dataset.origLabel === undefined) btn.dataset.origLabel = btn.textContent || "";
      btn.textContent = String(runningLabel);
    }
  }

  function restoreTrigger(btn) {
    if (!btn) return;
    btn.setAttribute("aria-busy", "false");
    btn.disabled = false;
    if (btn.dataset && btn.dataset.origLabel !== undefined) {
      btn.textContent = btn.dataset.origLabel;
      delete btn.dataset.origLabel;
    }
  }

  function applyCalmCancelStatus(surface, msg) {
    const text = msg || "Run cancelled by operator.";
    if (surface === "drawer") {
      const sum = $("jobDrawerSummary");
      if (sum) sum.textContent = text;
    } else {
      const badge = $("runStatusBadge");
      if (badge) {
        badge.textContent = "[CANCELLED]";
        badge.setAttribute("data-variant", "status");
        badge.setAttribute("data-state", "muted");
      }
      const dur = $("runResultDuration");
      if (dur) dur.textContent = "Cancelled";
      const sum = $("runResultSummary");
      if (sum) sum.textContent = text;
    }
    announce(text);
  }

  function bindCancelOnce(surface, cancelBtn) {
    if (!cancelBtn || (cancelBtn.dataset && cancelBtn.dataset.progressWired === "1")) return;
    if (cancelBtn.dataset) cancelBtn.dataset.progressWired = "1";
    cancelBtn.addEventListener("click", () => {
      const cur = activeRuns[surface];
      if (cur) cur.cancel();
    });
  }

  function cleanupSurface(surface, runObj) {
    if (runObj.intervalId) {
      globalScope.clearInterval(runObj.intervalId);
      runObj.intervalId = 0;
    }
    restoreTrigger(runObj.triggerBtn);
    if (activeRuns[surface] !== runObj) return;
    activeRuns[surface] = null;
    const cfg = SURFACES[surface];
    const card = cfg && $(cfg.cardId);
    if (card) card.hidden = true;
  }

  function beginRun(opts) {
    const cfgOpts = opts || {};
    const surface = cfgOpts.surface === "drawer" ? "drawer" : "main";
    const cfg = SURFACES[surface];
    const prev = activeRuns[surface];
    if (prev && !prev.settled) {
      prev.settled = true;
      cleanupSurface(surface, prev);
      try { prev.controller.abort(); } catch (_) {}
    }

    const controller = typeof globalScope.AbortController === "function"
      ? new globalScope.AbortController()
      : { signal: undefined, abort() {} };
    const id = ++runCounter;
    const start = nowMs();
    const card = $(cfg.cardId);
    const labelEl = $(cfg.labelId);
    const hintEl = $(cfg.hintId);
    const timerEl = $(cfg.timerId);
    const cancelBtn = $(cfg.cancelId);

    bindCancelOnce(surface, cancelBtn);
    if (cancelBtn) cancelBtn.disabled = false;
    setTriggerBusy(cfgOpts.triggerBtn, cfgOpts.runningLabel);

    if (labelEl) labelEl.textContent = cfgOpts.label || "Running check…";
    if (hintEl) hintEl.textContent = cfgOpts.hint || describeCheckHint(cfgOpts.tool, cfgOpts.target);
    if (timerEl) timerEl.textContent = "0.0s";
    if (card) card.hidden = false;

    const runObj = {
      id,
      surface,
      controller,
      signal: controller.signal,
      triggerBtn: cfgOpts.triggerBtn || null,
      settled: false,
      intervalId: 0,
      isAborted: () => Boolean(controller.signal && controller.signal.aborted),
      finish: () => {
        if (runObj.settled) return;
        runObj.settled = true;
        cleanupSurface(surface, runObj);
      },
      cancel: (silent) => {
        if (runObj.settled) return;
        runObj.settled = true;
        try { controller.abort(); } catch (_) {}
        cleanupSurface(surface, runObj);
        if (silent) return;
        const msg = "Run cancelled by operator.";
        if (typeof cfgOpts.onCancel === "function") cfgOpts.onCancel({ surface, id, message: msg });
        if (!cfgOpts.skipDefaultCancelStatus) applyCalmCancelStatus(surface, msg);
      }
    };

    activeRuns[surface] = runObj;
    if (timerEl) {
      runObj.intervalId = globalScope.setInterval(() => {
        if (runObj.settled || activeRuns[surface] !== runObj) return;
        const elapsed = Math.max(0, (nowMs() - start) / 1000);
        timerEl.textContent = elapsed.toFixed(1) + "s";
      }, 100);
    }
    return runObj;
  }

  function cancelSurface(surface, silent) {
    const key = surface === "drawer" ? "drawer" : "main";
    const cur = activeRuns[key];
    if (cur) cur.cancel(Boolean(silent));
  }

  function getActiveRun(surface) {
    return activeRuns[surface === "drawer" ? "drawer" : "main"] || null;
  }

  globalScope.NetUtilsStudioProgress = {
    beginRun,
    cancelSurface,
    describeCheckHint,
    isAbortError,
    getActiveRun
  };
})(typeof window !== "undefined" ? window : globalThis);
