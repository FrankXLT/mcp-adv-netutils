(function (globalScope) {
  "use strict";

  const state = { deps: null, drawerJob: null, drawerReqSeq: 0, scrollOpSeq: 0 };
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  };

  function scrollIntoViewAsync(targetEl, blockMode) {
    if (!targetEl || typeof targetEl.scrollIntoView !== "function") return Promise.resolve();
    const reduced = globalScope.matchMedia && globalScope.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const res = targetEl.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: blockMode || "nearest" });
    if (res && typeof res.then === "function") return res;
    return new Promise((resolve) => {
      let timer;
      const finish = () => {
        clearTimeout(timer);
        globalScope.removeEventListener("scrollend", finish);
        globalScope.removeEventListener("scroll", onScroll);
        resolve();
      };
      const onScroll = () => { clearTimeout(timer); timer = globalScope.setTimeout(finish, 110); };
      globalScope.addEventListener("scrollend", finish, { once: true });
      globalScope.addEventListener("scroll", onScroll, { passive: true });
      timer = globalScope.setTimeout(finish, 110);
    });
  }

  async function focusTargetSection(targetEl, highlightEl) {
    if (!targetEl) return;
    const seq = ++state.scrollOpSeq;
    const rect = targetEl.getBoundingClientRect();
    const outOfView = rect.top < 64 || rect.bottom > (globalScope.innerHeight || 900);
    await scrollIntoViewAsync(targetEl, outOfView ? "start" : "nearest");
    if (seq !== state.scrollOpSeq) return;
    if (typeof targetEl.focus === "function") targetEl.focus({ preventScroll: true });
    const hl = highlightEl || targetEl;
    hl.classList.add("is-focus-highlight");
    globalScope.setTimeout(() => { if (seq === state.scrollOpSeq) hl.classList.remove("is-focus-highlight"); }, 1200);
  }

  function beginRunFocus(tool, targetLabel, isAsync) {
    const card = $("checkResultCard");
    if (isAsync && state.deps) {
      state.deps.setStatusPill($("runStatusBadge"), "[RUNNING]", "warn");
      $("runResultCheckName").textContent = state.deps.getCheckLabel(tool);
      $("runResultTarget").textContent = targetLabel || "Local";
      $("runResultDuration").textContent = "Running…";
      $("runResultSummary").textContent = "Running " + state.deps.getCheckLabel(tool) + (targetLabel ? " for " + targetLabel : "") + "…";
    }
    focusTargetSection(card, card);
  }

  function renderDnsTable(wrapEl, rows) {
    if (!wrapEl) return;
    if (!Array.isArray(rows) || !rows.length) { wrapEl.replaceChildren(); return; }
    const tbl = el("table", "va-data-table"), thead = document.createElement("thead"), hr = document.createElement("tr"), tbody = document.createElement("tbody");
    ["Resolver", "Latency", "Answers", "Consensus"].forEach((h) => hr.appendChild(el("th", "", h)));
    thead.appendChild(hr);
    state.deps.renderTableRows(tbody, rows, (r) => {
      const st = String(r.status || "OK").toUpperCase(), pill = el("span", "va-pill", st);
      state.deps.setStatusPill(pill, st, state.deps.badgeVariant(st));
      const ans = Array.isArray(r.answers) && r.answers.length ? r.answers.join(", ") : "none";
      return {
        cells: [
          ["Resolver", r.resolver],
          ["Latency", r.latency_ms > 0 ? state.deps.fmtMsText(r.latency_ms) : "—", "tabular-nums"],
          ["Answers", ans, "tabular-nums"],
          ["Consensus", pill]
        ]
      };
    });
    tbl.append(thead, tbody);
    wrapEl.replaceChildren(tbl);
  }

  function buildExportData(run) {
    const checkName = state.deps.getCheckLabel(run.tool);
    let headers = ["Metric", "Value"], rows = [];
    if (Array.isArray(run.whiskers) && run.whiskers.length) {
      headers = ["Segment / Hop", "Min (ms)", "Avg (ms)", "Max (ms)", "Loss (%)"];
      rows = run.whiskers.map((w) => [
        w.label, Number(w.minMs ?? w.min ?? 0).toFixed(2), Number(w.avgMs ?? w.avg ?? 0).toFixed(2),
        Number(w.maxMs ?? w.max ?? 0).toFixed(2), Number(w.lossPct ?? w.loss ?? 0).toFixed(1)
      ]);
    } else if (Array.isArray(run.waterfall) && run.waterfall.length) {
      headers = ["Phase", "Start (ms)", "Duration (ms)", "End (ms)"];
      rows = run.waterfall.map((p) => {
        const s = Number(p.startMs ?? 0), d = Number(p.durationMs ?? 0);
        return [p.label, s.toFixed(2), d.toFixed(2), (s + d).toFixed(2)];
      });
    } else if (Array.isArray(run.dns_comparisons) && run.dns_comparisons.length) {
      headers = ["Resolver", "Latency (ms)", "Answers", "Status"];
      rows = run.dns_comparisons.map((d) => [d.resolver, d.latency_ms > 0 ? Number(d.latency_ms).toFixed(2) : "—", (d.answers || []).join(", ") || "none", d.status || "OK"]);
    } else if (run.tls_health) {
      const t = run.tls_health;
      rows = [["Subject", t.subject || "—"], ["Issuer", t.issuer || "—"], ["Days Remaining", String(t.days_remaining ?? "—")], ["Protocol", t.protocol || "—"], ["Cipher", t.cipher || "—"], ["Hostname Match", String(Boolean(t.hostname_match))]];
    } else if (run.data && typeof run.data === "object") {
      Object.keys(run.data).slice(0, 16).forEach((k) => {
        const v = run.data[k];
        rows.push([k.replace(/_/g, " "), Array.isArray(v) ? v.map((x) => typeof x === "object" ? JSON.stringify(x) : x).join(", ") : (typeof v === "object" ? JSON.stringify(v) : String(v))]);
      });
    }
    if (!rows.length) rows = [["Check", checkName], ["Target", run.target || "—"], ["Status", run.status || "OK"], ["Summary", run.summary || "—"]];
    const tsv = [headers.join("\t")].concat(rows.map((r) => r.join("\t"))).join("\n");
    const md = [
      "### " + checkName + " — " + (run.target || "Local"),
      "**Status:** " + (run.status || "OK") + " | **Duration:** " + state.deps.fmtMsText(run.duration_ms),
      "", run.summary || "", "", "| " + headers.join(" | ") + " |", "| " + headers.map(() => "---").join(" | ") + " |"
    ].concat(rows.map((r) => "| " + r.join(" | ") + " |")).join("\n");
    return { headers, rows, markdown: md, tsv };
  }

  function renderFactsList(dlEl, run) {
    if (!dlEl) return;
    const facts = [];
    if (run.data && typeof run.data === "object") {
      Object.keys(run.data).slice(0, 8).forEach((k) => {
        const v = run.data[k];
        const txt = Array.isArray(v) ? v.map((x) => typeof x === "object" ? (x.port ? x.port + "/" + (x.service || "tcp") : JSON.stringify(x)) : x).join(", ") : (typeof v === "object" ? JSON.stringify(v) : String(v));
        facts.push([k.replace(/_/g, " "), txt]);
      });
    }
    if (!facts.length) facts.push(["Status", run.status || "OK"], ["Target", run.target || "—"], ["Duration", state.deps.fmtMsText(run.duration_ms)]);
    const frag = document.createDocumentFragment();
    facts.forEach(([k, v]) => { const box = el("div", "fact-item"); box.append(el("dt", "", k), el("dd", "", v)); frag.appendChild(box); });
    dlEl.replaceChildren(frag);
    dlEl.hidden = false;
  }

  function renderDrawerCharts(run, charts, hasW, hasF, hasD) {
    const host = $("jobDrawerChartsHost");
    const ch = charts || globalScope.NetutilsCharts;
    if (ch && typeof ch.disposeHost === "function") {
      host.querySelectorAll(".echart-host").forEach((elHost) => ch.disposeHost(elHost));
    }
    host.replaceChildren();
    if (hasW) { const b = el("div", "chart-panel"), h = el("div", "echart-host"); b.append(el("h3", "chart-title", "Path Latency & Packet Loss"), h); host.appendChild(b); if (charts) charts.renderWhiskers(h, run.whiskers); }
    if (hasF) { const b = el("div", "chart-panel"), h = el("div", "echart-host"); b.append(el("h3", "chart-title", "Response Timing Breakdown"), h); host.appendChild(b); if (charts) charts.renderWaterfall(h, run.waterfall); }
    if (hasD) { const b = el("div", "chart-panel"), h = el("div", "echart-host echart-host-sm"), dt = el("div", "va-table-scroll"); b.append(el("h3", "chart-title", "DNS Resolver Comparison"), h, dt); host.appendChild(b); if (charts) charts.renderDnsComparison(h, run.dns_comparisons); renderDnsTable(dt, run.dns_comparisons); }
    if (!hasW && !hasF && !hasD && !run.tls_health) { const b = el("div", "chart-panel"), dl = el("dl", "facts-grid"); renderFactsList(dl, run); b.appendChild(dl); host.appendChild(b); }
  }

  function renderOutcome(runData, isMainCard) {
    const run = runData || {}, charts = globalScope.NetutilsCharts;
    if (isMainCard) {
      state.deps.onMainRunRendered(run);
      const st = String(run.status || "OK").toUpperCase();
      state.deps.setStatusPill($("runStatusBadge"), "[" + st + "]", state.deps.badgeVariant(st));
      $("runResultCheckName").textContent = state.deps.getCheckLabel(run.tool);
      $("runResultTarget").textContent = run.target || "Local";
      $("runResultDuration").textContent = state.deps.fmtMsText(run.duration_ms);
      $("runResultSummary").textContent = run.summary || "Check completed.";
    }
    if (charts) charts.renderTlsStrip($(isMainCard ? "tlsHealthStrip" : "jobDrawerTlsStrip"), run.tls_health);
    const hasW = Array.isArray(run.whiskers) && run.whiskers.length > 0;
    const hasF = Array.isArray(run.waterfall) && run.waterfall.length > 0;
    const hasD = Array.isArray(run.dns_comparisons) && run.dns_comparisons.length > 0;

    if (isMainCard) {
      $("runWhiskersWrap").hidden = !hasW; $("runWaterfallWrap").hidden = !hasF; $("runDnsWrap").hidden = !hasD;
      if (charts) {
        if (hasW) charts.renderWhiskers($("runWhiskersHost"), run.whiskers); else charts.disposeHost($("runWhiskersHost"));
        if (hasF) charts.renderWaterfall($("runWaterfallHost"), run.waterfall); else charts.disposeHost($("runWaterfallHost"));
        if (hasD) { charts.renderDnsComparison($("runDnsHost"), run.dns_comparisons); renderDnsTable($("runDnsTableWrap"), run.dns_comparisons); }
        else { charts.disposeHost($("runDnsHost")); $("runDnsTableWrap").replaceChildren(); }
      }
      const noChart = !hasW && !hasF && !hasD && !run.tls_health;
      $("runSummaryVisual").hidden = !noChart;
      if (noChart) { $("runVisualEmptyText").hidden = true; renderFactsList($("runFactsGrid"), run); }
    } else {
      renderDrawerCharts(run, charts, hasW, hasF, hasD);
    }

    const exp = buildExportData(run);
    const thead = $(isMainCard ? "runResultTableHead" : "jobDrawerTableHead");
    const tbody = $(isMainCard ? "runResultTableBody" : "jobDrawerTableBody");
    const hr = document.createElement("tr");
    exp.headers.forEach((h) => hr.appendChild(el("th", "", h)));
    thead.replaceChildren(hr);
    state.deps.renderTableRows(tbody, exp.rows, (r) => ({ cells: exp.headers.map((h, i) => [h, r[i], i > 0 ? "tabular-nums" : ""]) }));
    const ps = $(isMainCard ? "runExportPayload" : "jobDrawerExportPayload");
    if (ps) ps.textContent = JSON.stringify({ markdown: exp.markdown, tsv: exp.tsv });
    if (isMainCard && (run.lan_inventory || run.physical || run.virtual)) state.deps.ingestLanData(run.lan_inventory || run);
    if (isMainCard && (run.snapshot_diff || run.added || run.removed || run.changed)) state.deps.renderSnapshotDiff(run.snapshot_diff || run);
  }

  function renderCompareDiff(pastJob, freshJob) {
    const pAvg = Number(pastJob.duration_ms || 0), fAvg = Number(freshJob.duration_ms || 0), delta = fAvg - pAvg, badge = $("jobDrawerCompareDelta");
    badge.textContent = (delta <= 0 ? "" : "+") + delta.toFixed(1) + " ms (" + (freshJob.status || "OK") + ")";
    badge.setAttribute("data-state", delta <= 0 ? "nominal" : "warn");
    const rows = [
      ["Status", pastJob.status || "OK", freshJob.status || "OK", pastJob.status === freshJob.status ? "Unchanged" : pastJob.status + " -> " + freshJob.status],
      ["Duration", state.deps.fmtMsText(pAvg), state.deps.fmtMsText(fAvg), (delta <= 0 ? "" : "+") + delta.toFixed(1) + " ms"]
    ];
    if (Array.isArray(pastJob.whiskers) && Array.isArray(freshJob.whiskers)) {
      pastJob.whiskers.forEach((pw, idx) => {
        const fw = freshJob.whiskers[idx];
        if (!fw) return;
        const d = Number(fw.avgMs || 0) - Number(pw.avgMs || 0);
        rows.push([pw.label, Number(pw.avgMs || 0).toFixed(2) + " ms", Number(fw.avgMs || 0).toFixed(2) + " ms", (d <= 0 ? "" : "+") + d.toFixed(2) + " ms"]);
      });
    }
    state.deps.renderTableRows($("jobDrawerCompareBody"), rows, (r) => {
      const ch = el("span", String(r[3]).startsWith("-") ? "delta-better" : (String(r[3]).startsWith("+") ? "delta-worse" : ""), r[3]);
      return { cells: [["Item", r[0]], ["Past Run", r[1], "tabular-nums"], ["Fresh Run", r[2], "tabular-nums"], ["Change", ch, "tabular-nums"]] };
    });
    $("jobDrawerComparePanel").hidden = false;
  }

  async function openJobDrawer(jobId) {
    if (!jobId) return;
    const seq = ++state.drawerReqSeq;
    const j = await state.deps.loadJobById(jobId);
    if (seq !== state.drawerReqSeq || !j) return;
    state.drawerJob = j;
    $("jobDrawerTitle").textContent = state.deps.getCheckLabel(j.tool) + " — " + (j.target || "Local");
    $("jobDrawerMeta").textContent = [j.job_id || jobId, j.status || "OK", state.deps.fmtMsText(j.duration_ms), "Recorded " + state.deps.fmtTime(j.created_at), "Retained until " + state.deps.fmtTime(j.expires_at)].join(" · ");
    $("jobDrawerSummary").textContent = j.summary || "Archived check report.";
    $("jobDrawerComparePanel").hidden = true;
    $("jobDrawerRunAgainBtn").setAttribute("aria-busy", "false");
    const cb = $("jobDrawerResultCard").querySelector('[data-qe-view="chart"]');
    if (cb) cb.click();
    renderOutcome(j, false);
    const dlg = $("jobDrawer");
    dlg.returnValue = "";
    if (typeof dlg.showModal === "function") {
      if (!dlg.open) dlg.showModal();
    } else {
      dlg.setAttribute("open", "");
    }
    if (globalScope.NetutilsCharts) globalScope.NetutilsCharts.refreshInContainer(dlg);
  }

  async function handleRunAgain() {
    const past = state.drawerJob;
    const dlg = $("jobDrawer");
    if (!past || !dlg || !dlg.open) return;
    const seq = ++state.drawerReqSeq;
    const btn = $("jobDrawerRunAgainBtn");
    btn.setAttribute("aria-busy", "true");
    try {
      const fresh = await state.deps.runAgainForCompare(past);
      if (seq !== state.drawerReqSeq || !dlg.open || !state.drawerJob || state.drawerJob.job_id !== past.job_id) return;
      if (fresh) renderCompareDiff(past, fresh);
    } finally {
      if (seq === state.drawerReqSeq || !dlg.open) btn.setAttribute("aria-busy", "false");
    }
  }

  function renderTableRows(tbodyEl, items, rowSpec) {
    const frag = document.createDocumentFragment();
    for (let i = 0; i < items.length; i += 1) {
      const spec = rowSpec(items[i], i), tr = document.createElement("tr");
      if (spec.jobId) tr.setAttribute("data-job-id", spec.jobId);
      for (let c = 0; c < spec.cells.length; c += 1) {
        const [label, content, cls] = spec.cells[c], td = el("td", cls || "");
        td.setAttribute("data-label", label);
        if (content instanceof Node) td.appendChild(content); else td.textContent = String(content ?? "—");
        tr.appendChild(td);
      }
      frag.appendChild(tr);
    }
    tbodyEl.replaceChildren(frag);
  }

  function makeSvgBar(rttMs) {
    const NS = "http://www.w3.org/2000/svg", svg = document.createElementNS(NS, "svg"), bg = document.createElementNS(NS, "rect"), fill = document.createElementNS(NS, "rect");
    svg.setAttribute("class", "va-inline-bar-svg"); svg.setAttribute("viewBox", "0 0 100 8"); svg.setAttribute("preserveAspectRatio", "none"); svg.setAttribute("aria-hidden", "true");
    bg.setAttribute("class", "va-inline-bar-bg"); bg.setAttribute("width", "100"); bg.setAttribute("height", "8"); bg.setAttribute("rx", "4");
    fill.setAttribute("class", "va-inline-bar-fill"); fill.setAttribute("data-state", Number(rttMs || 0) > 4 ? "warn" : "ok");
    fill.setAttribute("width", String(Math.max(8, Math.min(100, Math.round((Number(rttMs || 0) / 5) * 100))))); fill.setAttribute("height", "8"); fill.setAttribute("rx", "4");
    svg.append(bg, fill);
    return svg;
  }

  function bindDialogDismiss(dlg) {
    if (!dlg) return;
    dlg.addEventListener("close", () => { dlg.returnValue = ""; });
    if ("closedBy" in HTMLDialogElement.prototype || dlg.dataset.quietClosedBy === "1") return;
    dlg.dataset.quietClosedBy = "1";
    let pressedOut = false;
    const outside = (ev) => { if (ev.target !== dlg || (ev.button != null && ev.button !== 0)) return false; const r = dlg.getBoundingClientRect(); return ev.clientX < r.left || ev.clientX > r.right || ev.clientY < r.top || ev.clientY > r.bottom; };
    dlg.addEventListener("pointerdown", (ev) => { pressedOut = outside(ev); });
    dlg.addEventListener("pointercancel", () => { pressedOut = false; });
    dlg.addEventListener("pointerup", (ev) => { if (pressedOut && outside(ev)) dlg.close(); pressedOut = false; });
  }

  function init(deps) {
    state.deps = deps;
    const dlg = $("jobDrawer");
    [$("jobDrawerCloseBtn"), $("jobDrawerDoneBtn")].forEach((b) => { if (b) b.addEventListener("click", () => dlg.close()); });
    $("jobDrawerRunAgainBtn").addEventListener("click", handleRunAgain);
    bindDialogDismiss(dlg);
    if (dlg) {
      dlg.addEventListener("close", () => {
        state.drawerReqSeq += 1;
        state.drawerJob = null;
        const ch = globalScope.NetutilsCharts;
        const host = $("jobDrawerChartsHost");
        if (ch && host && typeof ch.disposeHost === "function") {
          host.querySelectorAll(".echart-host").forEach((elHost) => ch.disposeHost(elHost));
        }
        $("jobDrawerRunAgainBtn").setAttribute("aria-busy", "false");
      });
    }
  }

  globalScope.NetutilsResults = {
    init: init, renderOutcome: renderOutcome, openJobDrawer: openJobDrawer,
    focusTargetSection: focusTargetSection, beginRunFocus: beginRunFocus,
    renderTableRows: renderTableRows, makeSvgBar: makeSvgBar, bindDialogDismiss: bindDialogDismiss
  };
})(typeof window !== "undefined" ? window : globalThis);
