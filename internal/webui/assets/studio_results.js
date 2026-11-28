(function (globalScope) {
  "use strict";

  const state = { deps: null, drawerJob: null, drawerReqSeq: 0, scrollOpSeq: 0, focusHighlightEl: null };
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
    if (state.focusHighlightEl && state.focusHighlightEl !== hl) {
      state.focusHighlightEl.classList.remove("is-focus-highlight");
    }
    state.focusHighlightEl = hl;
    hl.classList.add("is-focus-highlight");
    globalScope.setTimeout(() => {
      if (seq === state.scrollOpSeq || state.focusHighlightEl !== hl) {
        hl.classList.remove("is-focus-highlight");
        if (state.focusHighlightEl === hl) state.focusHighlightEl = null;
      }
    }, 1200);
  }

  function beginRunFocus(tool, targetLabel, isAsync) {
    const switchTab = (state.deps && typeof state.deps.setActiveTab === "function" && state.deps.setActiveTab) ||
      (globalScope.NetUtilsStudio && typeof globalScope.NetUtilsStudio.setActiveTab === "function" && globalScope.NetUtilsStudio.setActiveTab);
    if (switchTab) switchTab("checks");
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

  function renderTlsStrip(stripEl, tls) {
    if (!stripEl) return;
    if (!tls || typeof tls !== "object") { stripEl.hidden = true; stripEl.replaceChildren(); return; }
    const days = Number(tls.days_remaining ?? 0), valid = Boolean(tls.valid) && Boolean(tls.hostname_match);
    const tone = !valid || days <= 7 ? "fault" : days < 30 ? "warn" : "nominal";
    const pill = el("span", "va-pill", (valid ? "TLS Valid" : "TLS Attention") + " · " + days + "d left");
    pill.setAttribute("data-variant", "status"); pill.setAttribute("data-state", tone);
    const addMeta = (k, v) => {
      const wrap = el("span", "tls-meta-item"), strong = el("strong", "", k + ": ");
      wrap.append(strong, document.createTextNode(String(v || "—")));
      return wrap;
    };
    const kids = [pill, addMeta("Host", tls.subject), addMeta("Issuer", tls.issuer)];
    if (tls.protocol || tls.cipher) kids.push(addMeta("Protocol", [tls.protocol, tls.cipher].filter(Boolean).join(" ")));
    if (tls.not_after) kids.push(addMeta("Expires", String(tls.not_after).replace("T", " ").slice(0, 16) + "Z"));
    kids.push(addMeta("Name Match", tls.hostname_match ? "Verified" : "Mismatch"));
    stripEl.replaceChildren.apply(stripEl, kids);
    stripEl.hidden = false;
  }

  const progressApi = () => globalScope.NetUtilsStudioProgress || null;
  const isAborted = (err, token) => Boolean((state.deps && state.deps.isAbortError && state.deps.isAbortError(err, token)) || (progressApi() && progressApi().isAbortError(err, token)) || (err && err.name === "AbortError") || (token && token.signal && token.signal.aborted));
  const cellText = (c) => (c && typeof c === "object" && "pill" in c ? String(c.pill) : (c instanceof Node ? (c.textContent || "") : String(c ?? "—")));
  const renderCellNode = (c) => { if (!c || typeof c !== "object" || !("pill" in c)) return c; const sp = el("span", "va-pill", c.pill); sp.setAttribute("data-variant", "status"); sp.setAttribute("data-state", c.state || "nominal"); return sp; };
  const rowIsSilent = (r) => Array.isArray(r) && r.some((c) => c && typeof c === "object" && c.state === "muted" && String(c.pill || "").includes("Silent"));

  function renderStructuredTable(wrapEl, tblSpec) {
    if (!wrapEl) return;
    if (!tblSpec || !Array.isArray(tblSpec.headers) || !tblSpec.headers.length || !Array.isArray(tblSpec.rows) || !tblSpec.rows.length) {
      wrapEl.replaceChildren(); wrapEl.hidden = true; return;
    }
    const tbl = el("table", "va-data-table"), thead = document.createElement("thead"), hr = document.createElement("tr"), tbody = document.createElement("tbody");
    tblSpec.headers.forEach((h) => hr.appendChild(el("th", "", h)));
    thead.appendChild(hr);
    const rowFn = state.deps && typeof state.deps.renderTableRows === "function" ? state.deps.renderTableRows : renderTableRows;
    rowFn(tbody, tblSpec.rows, (r) => ({ rowClass: rowIsSilent(r) ? "hop-silent-row" : "", cells: tblSpec.headers.map((h, i) => [h, renderCellNode(r[i] ?? "—"), i > 0 ? "tabular-nums" : ""]) }));
    tbl.append(thead, tbody);
    wrapEl.replaceChildren(tbl);
    wrapEl.hidden = false;
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
      const ans = Array.isArray(r.answers) && r.answers.length ? r.answers.join(", ") : "None";
      return { cells: [["Resolver", r.resolver], ["Latency", r.latency_ms > 0 ? state.deps.fmtMsText(r.latency_ms) : "—", "tabular-nums"], ["Answers", ans, "tabular-nums"], ["Consensus", pill]] };
    });
    tbl.append(thead, tbody);
    wrapEl.replaceChildren(tbl);
  }

  function outcomeDurationMs(run) {
    const r = run || {};
    return Number(r.elapsed_ms) > 0 ? Number(r.elapsed_ms) : Number(r.duration_ms || 0);
  }

  function buildFallbackFacts(run) {
    const tv = globalScope.NetutilsToolViews, facts = [];
    if (run && run.data && typeof run.data === "object" && !Array.isArray(run.data)) {
      Object.keys(run.data).slice(0, 8).forEach((k) => {
        facts.push([tv ? tv.humanizeKey(k) : k.replace(/_/g, " "), tv ? tv.formatValueHuman(run.data[k]) : String(run.data[k] ?? "—")]);
      });
    }
    if (!facts.length) facts.push(["Status", run.status || "OK"], ["Target", run.target || "—"], ["Duration", state.deps.fmtMsText(outcomeDurationMs(run))]);
    return facts;
  }

  function buildExportData(run, toolView) {
    const checkName = state.deps.getCheckLabel(run.tool), tv = globalScope.NetutilsToolViews;
    let headers = ["Metric", "Value"], rows = [], displayRows = null;
    if (toolView && toolView.table && Array.isArray(toolView.table.headers) && toolView.table.headers.length && Array.isArray(toolView.table.rows) && toolView.table.rows.length) {
      headers = toolView.table.headers.slice();
      displayRows = toolView.table.rows;
      rows = toolView.table.rows.map((r) => r.map(cellText));
    } else if (Array.isArray(run.whiskers) && run.whiskers.length) {
      headers = ["Segment / Hop", "Min (ms)", "Avg (ms)", "Max (ms)", "Loss / State"];
      rows = run.whiskers.map((w) => {
        const lp = Number(w.lossPct ?? w.loss ?? 0), silent = Boolean(w.silent);
        const fmt = (val) => (silent || lp >= 100 || !(Number(val) > 0) ? "—" : Number(val).toFixed(2));
        return [w.label, fmt(w.minMs ?? w.min), fmt(w.avgMs ?? w.avg), fmt(w.maxMs ?? w.max), silent ? "Silent transit (*)" : lp.toFixed(1) + "%"];
      });
    } else if (run.tool !== "recipe_diff_ping" && Array.isArray(run.waterfall) && run.waterfall.length) {
      headers = ["Phase", "Start (ms)", "Duration (ms)", "End (ms)"];
      rows = run.waterfall.map((p) => { const s = Number(p.startMs ?? 0), d = Number(p.durationMs ?? 0); return [p.label, s.toFixed(2), d.toFixed(2), (s + d).toFixed(2)]; });
    } else if (Array.isArray(run.dns_comparisons) && run.dns_comparisons.length) {
      headers = ["Resolver", "Latency (ms)", "Answers", "Status"];
      rows = run.dns_comparisons.map((d) => [d.resolver, d.latency_ms > 0 ? Number(d.latency_ms).toFixed(2) : "—", (d.answers || []).join(", ") || "None", d.status || "OK"]);
    } else if (run.tls_health) {
      const t = run.tls_health;
      rows = [["Subject", t.subject || "—"], ["Issuer", t.issuer || "—"], ["Days Remaining", String(t.days_remaining ?? "—")], ["Protocol", t.protocol || "—"], ["Cipher", t.cipher || "—"], ["Hostname Match", t.hostname_match ? "Yes" : "No"]];
    } else if (toolView && Array.isArray(toolView.summaryFacts) && toolView.summaryFacts.length) {
      rows = toolView.summaryFacts.map(([k, v]) => [String(k), cellText(v)]);
    } else if (run.data && typeof run.data === "object") {
      Object.keys(run.data).slice(0, 16).forEach((k) => {
        rows.push([tv ? tv.humanizeKey(k) : k.replace(/_/g, " "), tv ? tv.formatValueHuman(run.data[k]) : String(run.data[k] ?? "—")]);
      });
    }
    if (!rows.length) rows = [["Check", checkName], ["Target", run.target || "—"], ["Status", run.status || "OK"], ["Summary", run.summary || "—"]];
    const clean = (c) => String(c ?? "—").replace(/[\r\n\t]+/g, " ");
    const tsv = [headers.join("\t")].concat(rows.map((r) => r.map(clean).join("\t"))).join("\n");
    const md = [
      "### " + checkName + " — " + (run.target || "Local"),
      "**Status:** " + (run.status || "OK") + " | **Duration:** " + state.deps.fmtMsText(outcomeDurationMs(run)),
      "", run.summary || "", "", "| " + headers.join(" | ") + " |", "| " + headers.map(() => "---").join(" | ") + " |"
    ].concat(rows.map((r) => "| " + r.map(clean).join(" | ") + " |")).join("\n");
    return { headers, rows, displayRows: displayRows || rows, markdown: md, tsv };
  }

  function renderFactsList(dlEl, facts) {
    if (!dlEl) return;
    if (!Array.isArray(facts) || !facts.length) { dlEl.replaceChildren(); dlEl.hidden = true; return; }
    const frag = document.createDocumentFragment();
    facts.forEach(([k, v]) => {
      const box = el("div", "fact-item"), dd = el("dd", ""), valNode = renderCellNode(v);
      if (valNode instanceof Node) dd.appendChild(valNode); else dd.textContent = String(valNode ?? "—");
      box.append(el("dt", "", k), dd); frag.appendChild(box);
    });
    dlEl.replaceChildren(frag);
    dlEl.hidden = false;
  }

  function ensureToolChartWrap() {
    let wrap = $("runToolChartWrap");
    if (wrap) return wrap;
    const grid = $("runChartsGrid");
    if (!grid) return null;
    wrap = el("div", "chart-panel"); wrap.id = "runToolChartWrap"; wrap.hidden = true;
    const title = el("h3", "chart-title"); title.id = "runToolChartTitle";
    const chartHost = el("div", "echart-host"); chartHost.id = "runToolChartHost"; chartHost.setAttribute("role", "img");
    const tblWrap = el("div", "va-table-scroll va-table-wrap"); tblWrap.id = "runToolTableWrap"; tblWrap.setAttribute("role", "region"); tblWrap.setAttribute("tabindex", "0");
    wrap.append(title, chartHost, tblWrap);
    grid.insertBefore(wrap, $("runSummaryVisual") || null);
    return wrap;
  }

  function inspectToolVisual(run, toolView, hasW, hasF, hasD) {
    const hasRich = hasW || hasF || hasD, t = run && run.tool;
    const hasChart = Boolean(toolView && toolView.chart && Array.isArray(toolView.chart.rows) && toolView.chart.rows.length);
    const hasTable = Boolean(toolView && toolView.table && Array.isArray(toolView.table.rows) && toolView.table.rows.length);
    const isTraceTool = t === "recipe_path_autopsy" || t === "mtr_path_quality" || t === "traceroute";
    const allowTableWithRich = Boolean(hasTable && ((t === "recipe_diff_http" && toolView.table.rows.length >= 2) || isTraceTool));
    const showChart = !hasRich && hasChart, showTable = hasTable && (!hasRich || allowTableWithRich), hasToolVisual = showChart || showTable;
    const title = showChart ? toolView.chart.title : (t === "recipe_diff_http" ? "Endpoint Comparison" : (state.deps.getCheckLabel(t) + " Details"));
    return { showChart, showTable, hasToolVisual, title };
  }

  function renderDrawerCharts(run, charts, hasW, hasF, hasD, toolView) {
    const host = $("jobDrawerChartsHost"), ch = charts || globalScope.NetutilsCharts;
    if (ch && typeof ch.disposeHost === "function") host.querySelectorAll(".echart-host").forEach((elHost) => ch.disposeHost(elHost));
    host.replaceChildren();
    if (hasW) { const b = el("div", "chart-panel"), h = el("div", "echart-host"); b.append(el("h3", "chart-title", "Path Latency & Packet Loss"), h); host.appendChild(b); if (ch) ch.renderWhiskers(h, run.whiskers); }
    if (hasF) { const b = el("div", "chart-panel"), h = el("div", "echart-host"); b.append(el("h3", "chart-title", "Response Timing Breakdown"), h); host.appendChild(b); if (ch) ch.renderWaterfall(h, run.waterfall); }
    if (hasD) { const b = el("div", "chart-panel"), h = el("div", "echart-host echart-host-sm"), dt = el("div", "va-table-scroll"); b.append(el("h3", "chart-title", "DNS Resolver Comparison"), h, dt); host.appendChild(b); if (ch) ch.renderDnsComparison(h, run.dns_comparisons); renderDnsTable(dt, run.dns_comparisons); }
    const tv = inspectToolVisual(run, toolView, hasW, hasF, hasD);
    if (tv.hasToolVisual) {
      const b = el("div", "chart-panel"); b.appendChild(el("h3", "chart-title", tv.title));
      if (tv.showChart && ch && typeof ch.renderHorizontalBars === "function") { const h = el("div", "echart-host"); b.appendChild(h); ch.renderHorizontalBars(h, toolView.chart); }
      if (tv.showTable) { const tw = el("div", "va-table-scroll va-table-wrap"); b.appendChild(tw); renderStructuredTable(tw, toolView.table); }
      host.appendChild(b);
    }
    const facts = toolView && toolView.summaryFacts && toolView.summaryFacts.length ? toolView.summaryFacts :
      (!hasW && !hasF && !hasD && !run.tls_health && !tv.hasToolVisual ? buildFallbackFacts(run) : []);
    if (facts.length) { const b = el("div", "chart-panel"), dl = el("dl", "facts-grid"); renderFactsList(dl, facts); b.appendChild(dl); host.appendChild(b); }
  }

  function renderMainToolSection(run, charts, hasW, hasF, hasD, toolView) {
    const toolWrap = ensureToolChartWrap(), tv = inspectToolVisual(run, toolView, hasW, hasF, hasD);
    if (toolWrap) {
      const titleEl = $("runToolChartTitle"), chartHost = $("runToolChartHost"), tblWrap = $("runToolTableWrap");
      toolWrap.hidden = !tv.hasToolVisual;
      if (tv.hasToolVisual) {
        if (titleEl) titleEl.textContent = tv.title;
        if (chartHost) {
          if (tv.showChart && charts && typeof charts.renderHorizontalBars === "function") { chartHost.hidden = false; charts.renderHorizontalBars(chartHost, toolView.chart); }
          else { if (charts && typeof charts.disposeHost === "function") charts.disposeHost(chartHost); chartHost.replaceChildren(); chartHost.hidden = true; }
        }
        if (tblWrap) { if (tv.showTable) renderStructuredTable(tblWrap, toolView.table); else { tblWrap.replaceChildren(); tblWrap.hidden = true; } }
      } else {
        if (chartHost) { if (charts && typeof charts.disposeHost === "function") charts.disposeHost(chartHost); chartHost.replaceChildren(); chartHost.hidden = true; }
        if (tblWrap) { tblWrap.replaceChildren(); tblWrap.hidden = true; }
      }
    }
    const facts = toolView && toolView.summaryFacts && toolView.summaryFacts.length ? toolView.summaryFacts :
      (!hasW && !hasF && !hasD && !run.tls_health && !tv.hasToolVisual ? buildFallbackFacts(run) : []);
    $("runSummaryVisual").hidden = facts.length === 0;
    if (facts.length) { $("runVisualEmptyText").hidden = true; renderFactsList($("runFactsGrid"), facts); }
    else renderFactsList($("runFactsGrid"), []);
  }

  function renderOutcome(runData, isMainCard) {
    const run = runData || {}, charts = globalScope.NetutilsCharts, tvMod = globalScope.NetutilsToolViews;
    const toolView = tvMod && typeof tvMod.buildToolView === "function" ? tvMod.buildToolView(run, state.deps) : null;
    if (isMainCard) {
      state.deps.onMainRunRendered(run);
      const st = String(run.status || "OK").toUpperCase();
      state.deps.setStatusPill($("runStatusBadge"), "[" + st + "]", state.deps.badgeVariant(st));
      $("runResultCheckName").textContent = state.deps.getCheckLabel(run.tool);
      $("runResultTarget").textContent = run.target || "Local";
      $("runResultDuration").textContent = state.deps.fmtMsText(outcomeDurationMs(run));
      $("runResultSummary").textContent = run.summary || "Check completed.";
    }
    renderTlsStrip($(isMainCard ? "tlsHealthStrip" : "jobDrawerTlsStrip"), run.tls_health);
    const hasW = Array.isArray(run.whiskers) && run.whiskers.length > 0;
    const hasF = run.tool !== "recipe_diff_ping" && Array.isArray(run.waterfall) && run.waterfall.length > 0;
    const hasD = Array.isArray(run.dns_comparisons) && run.dns_comparisons.length > 0;

    if (isMainCard) {
      $("runWhiskersWrap").hidden = !hasW; $("runWaterfallWrap").hidden = !hasF; $("runDnsWrap").hidden = !hasD;
      if (charts) {
        if (hasW) charts.renderWhiskers($("runWhiskersHost"), run.whiskers); else charts.disposeHost($("runWhiskersHost"));
        if (hasF) charts.renderWaterfall($("runWaterfallHost"), run.waterfall); else charts.disposeHost($("runWaterfallHost"));
        if (hasD) { charts.renderDnsComparison($("runDnsHost"), run.dns_comparisons); renderDnsTable($("runDnsTableWrap"), run.dns_comparisons); }
        else { charts.disposeHost($("runDnsHost")); $("runDnsTableWrap").replaceChildren(); }
      }
      renderMainToolSection(run, charts, hasW, hasF, hasD, toolView);
    } else renderDrawerCharts(run, charts, hasW, hasF, hasD, toolView);

    const exp = buildExportData(run, toolView), thead = $(isMainCard ? "runResultTableHead" : "jobDrawerTableHead"), tbody = $(isMainCard ? "runResultTableBody" : "jobDrawerTableBody");
    const hr = document.createElement("tr"); exp.headers.forEach((h) => hr.appendChild(el("th", "", h))); thead.replaceChildren(hr);
    state.deps.renderTableRows(tbody, exp.displayRows || exp.rows, (r) => ({ rowClass: rowIsSilent(r) ? "hop-silent-row" : "", cells: exp.headers.map((h, i) => [h, renderCellNode(r[i]), i > 0 ? "tabular-nums" : ""]) }));
    const ps = $(isMainCard ? "runExportPayload" : "jobDrawerExportPayload");
    if (ps) ps.textContent = JSON.stringify({ markdown: exp.markdown, tsv: exp.tsv });
    if (isMainCard && (run.lan_inventory || run.physical || run.virtual)) state.deps.ingestLanData(run.lan_inventory || run);
    if (isMainCard && (run.snapshot_diff || run.added || run.removed || run.changed)) state.deps.renderSnapshotDiff(run.snapshot_diff || run);
  }

  function renderCompareDiff(pastJob, freshJob) {
    const pAvg = outcomeDurationMs(pastJob), fAvg = outcomeDurationMs(freshJob), delta = fAvg - pAvg, badge = $("jobDrawerCompareDelta");
    badge.textContent = (delta <= 0 ? "" : "+") + delta.toFixed(1) + " ms (" + (freshJob.status || "OK") + ")";
    badge.setAttribute("data-state", delta <= 0 ? "nominal" : "warn");
    const rows = [
      ["Status", pastJob.status || "OK", freshJob.status || "OK", pastJob.status === freshJob.status ? "Unchanged" : pastJob.status + " → " + freshJob.status],
      ["Duration", state.deps.fmtMsText(pAvg), state.deps.fmtMsText(fAvg), (delta <= 0 ? "" : "+") + delta.toFixed(1) + " ms"]
    ];
    if (Array.isArray(pastJob.whiskers) && Array.isArray(freshJob.whiskers)) {
      pastJob.whiskers.forEach((pw, idx) => {
        const fw = freshJob.whiskers[idx]; if (!fw) return;
        const pLoss = Number(pw.lossPct ?? pw.loss ?? 0), fLoss = Number(fw.lossPct ?? fw.loss ?? 0);
        const pVal = Number(pw.avgMs ?? pw.avg ?? 0), fVal = Number(fw.avgMs ?? fw.avg ?? 0);
        const pMiss = pw.silent || pLoss >= 100 || !(pVal > 0), fMiss = fw.silent || fLoss >= 100 || !(fVal > 0);
        const pTxt = pw.silent ? "Silent" : (pMiss ? "—" : pVal.toFixed(2) + " ms"), fTxt = fw.silent ? "Silent" : (fMiss ? "—" : fVal.toFixed(2) + " ms");
        rows.push([pw.label, pTxt, fTxt, (pMiss || fMiss) ? "—" : ((fVal - pVal <= 0 ? "" : "+") + (fVal - pVal).toFixed(2) + " ms")]);
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
    const api = progressApi(); if (api && typeof api.cancelSurface === "function") api.cancelSurface("drawer", true);
    const seq = ++state.drawerReqSeq, j = await state.deps.loadJobById(jobId);
    if (seq !== state.drawerReqSeq || !j) return;
    state.drawerJob = j;
    $("jobDrawerTitle").textContent = state.deps.getCheckLabel(j.tool) + " — " + (j.target || "Local");
    $("jobDrawerMeta").textContent = [j.job_id || jobId, j.status || "OK", state.deps.fmtMsText(outcomeDurationMs(j)), "Recorded " + state.deps.fmtTime(j.created_at), "Retained until " + state.deps.fmtTime(j.expires_at)].join(" · ");
    $("jobDrawerSummary").textContent = j.summary || "Archived check report.";
    $("jobDrawerComparePanel").hidden = true;
    $("jobDrawerRunAgainBtn").setAttribute("aria-busy", "false");
    const cb = $("jobDrawerResultCard").querySelector('[data-qe-view="chart"]'); if (cb) cb.click();
    const dlg = $("jobDrawer");
    if (dlg) { dlg.returnValue = ""; if (typeof dlg.showModal === "function") { if (!dlg.open) dlg.showModal(); } else dlg.setAttribute("open", ""); }
    renderOutcome(j, false);
    if (dlg && globalScope.NetutilsCharts) globalScope.NetutilsCharts.refreshInContainer(dlg);
  }

  async function handleRunAgain() {
    const past = state.drawerJob, dlg = $("jobDrawer");
    if (!past || !dlg || !dlg.open) return;
    const seq = ++state.drawerReqSeq, btn = $("jobDrawerRunAgainBtn"), api = progressApi();
    const prog = api && typeof api.beginRun === "function" ? api.beginRun({
      surface: "drawer", tool: past.tool, target: past.target, label: "Re-running " + state.deps.getCheckLabel(past.tool),
      hint: api.describeCheckHint(past.tool, past.target), triggerBtn: btn, runningLabel: "Running…",
      onCancel: () => { if (seq === state.drawerReqSeq) state.drawerReqSeq += 1; }
    }) : null;
    if (!prog) btn.setAttribute("aria-busy", "true");
    try {
      const fresh = await state.deps.runAgainForCompare(past, { signal: prog ? prog.signal : undefined });
      if (isAborted(null, prog) || seq !== state.drawerReqSeq || !dlg.open || !state.drawerJob || state.drawerJob.job_id !== past.job_id) return;
      if (fresh) renderCompareDiff(past, fresh);
    } catch (err) {
      if (isAborted(err, prog)) return;
      if ($("jobDrawerSummary")) $("jobDrawerSummary").textContent = "Unable to complete fresh comparison check.";
    } finally {
      if (prog) prog.finish(); else if (seq === state.drawerReqSeq || !dlg.open) btn.setAttribute("aria-busy", "false");
    }
  }

  function renderTableRows(tbodyEl, items, rowSpec) {
    const frag = document.createDocumentFragment();
    for (let i = 0; i < items.length; i += 1) {
      const spec = rowSpec(items[i], i), tr = document.createElement("tr");
      if (spec.rowClass) tr.className = spec.rowClass;
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
        const api = progressApi(); if (api && typeof api.cancelSurface === "function") api.cancelSurface("drawer", true);
        state.drawerReqSeq += 1; state.drawerJob = null;
        const ch = globalScope.NetutilsCharts, host = $("jobDrawerChartsHost");
        if (ch && host && typeof ch.disposeHost === "function") host.querySelectorAll(".echart-host").forEach((elHost) => ch.disposeHost(elHost));
        $("jobDrawerRunAgainBtn").setAttribute("aria-busy", "false");
      });
    }
  }

  globalScope.NetutilsResults = {
    init: init, renderOutcome: renderOutcome, openJobDrawer: openJobDrawer,
    focusTargetSection: focusTargetSection, beginRunFocus: beginRunFocus,
    renderTableRows: renderTableRows, makeSvgBar: makeSvgBar, bindDialogDismiss: bindDialogDismiss,
    outcomeDurationMs: outcomeDurationMs
  };
})(typeof window !== "undefined" ? window : globalThis);
