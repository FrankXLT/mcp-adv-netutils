(function (globalScope) {
  "use strict";

  const THEME_KEY = "netutils_theme";
  const DENSITY_KEY = "netutils_density";
  const ALLOWED_THEMES = { white: 1, paper: 1, "dark-paper": 1, dark: 1 };

  (function restoreEarlyThemeAndDensity() {
    let theme = "white";
    let density = "d2";
    try {
      const params = new URLSearchParams(globalScope.location.search || "");
      const qTheme = params.get("theme");
      const savedTheme = globalScope.localStorage.getItem(THEME_KEY);
      const savedDensity = globalScope.localStorage.getItem(DENSITY_KEY);
      if (qTheme && ALLOWED_THEMES[qTheme]) theme = qTheme;
      else if (savedTheme && ALLOWED_THEMES[savedTheme]) theme = savedTheme;
      if (savedDensity === "d2" || savedDensity === "d3") density = savedDensity;
    } catch (_) {}
    const root = document.documentElement;
    root.dataset.theme = theme;
    root.dataset.density = density;
    const meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) meta.setAttribute("content", theme === "dark" || theme === "dark-paper" ? "dark" : "light");
  })();

  const REGISTRY = new Map();
  let themeObserver = null;

  function toNum(val, fallback) {
    const n = Number(val);
    return Number.isFinite(n) ? n : fallback;
  }

  function fmtMs(val) {
    const n = toNum(val, 0);
    if (Math.abs(n) >= 100) return String(Math.round(n));
    if (Math.abs(n) >= 10) return String(Number(n.toFixed(1)));
    return String(Number(n.toFixed(2)));
  }

  function trimLabel(str, maxLen) {
    const s = String(str || "");
    if (s.length <= maxLen) return s;
    const noParen = s.replace(/\s*\([^)]*\)\s*$/, "");
    if (noParen.length >= 6 && noParen.length <= maxLen) return noParen;
    let cut = s.slice(0, Math.max(1, maxLen - 1)).replace(/\s+$/, "");
    if ((cut.match(/\(/g) || []).length > (cut.match(/\)/g) || []).length) cut = cut.replace(/\s*\([^()]*$/, "");
    if ((cut.match(/\[/g) || []).length > (cut.match(/\]/g) || []).length) cut = cut.replace(/\s*\[[^\[\]]*$/, "");
    return cut.length >= s.length ? s : cut + "…";
  }

  const ESC_MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" };
  const escHtml = (str) => String(str == null ? "" : str).replace(/[&<>"']/g, (c) => ESC_MAP[c]);

  function readThemeTokens() {
    const cs = getComputedStyle(document.documentElement);
    const pick = (name, fb) => {
      const val = cs.getPropertyValue(name).trim();
      return val || fb || "currentColor";
    };
    return {
      textPrimary: pick("--text-primary"),
      textSecondary: pick("--text-secondary"),
      textMuted: pick("--text-muted"),
      bgSurface: pick("--bg-surface"),
      bgElevated: pick("--bg-elevated"),
      bgSubtle: pick("--bg-subtle"),
      borderHairline: pick("--border-hairline"),
      borderStrong: pick("--border-strong"),
      accentPrimary: pick("--accent-primary"),
      statusOk: pick("--status-ok"),
      statusWarn: pick("--status-warn"),
      statusDanger: pick("--status-danger"),
      chart1: pick("--chart-1"),
      chart2: pick("--chart-2"),
      chart3: pick("--chart-3"),
      chart4: pick("--chart-4"),
      chart5: pick("--chart-5"),
      fontSans: pick("--font-sans", "sans-serif"),
      fontMono: pick("--font-mono", "monospace")
    };
  }

  function computeNiceMax(maxVal) {
    const raw = Math.max(1, toNum(maxVal, 10));
    if (globalScope.QuietSvgLayout && typeof globalScope.QuietSvgLayout.niceScale125 === "function") {
      return globalScope.QuietSvgLayout.niceScale125(0, raw * 1.12, { targetTicks: 5, includeZero: true });
    }
    const step = Math.pow(10, Math.floor(Math.log10(raw / 4)));
    return { min: 0, max: Math.ceil((raw * 1.15) / step) * step, step: step };
  }

  function computeGutterPx(labels, tok, maxPx) {
    const cap = maxPx || 168;
    if (globalScope.QuietSvgLayout && typeof globalScope.QuietSvgLayout.measureCategoryGutter === "function") {
      const m = globalScope.QuietSvgLayout.measureCategoryGutter(labels, {
        minPx: 76, maxPx: cap, maxChars: 24, maxLines: 1, fontFamily: tok.fontSans, fontSize: 11
      });
      return m.gutterPx;
    }
    let maxLen = 0;
    for (let i = 0; i < labels.length; i += 1) maxLen = Math.max(maxLen, String(labels[i] || "").length);
    return Math.max(80, Math.min(cap, maxLen * 7 + 18));
  }

  function disposeHost(hostEl) {
    if (!hostEl) return;
    const entry = REGISTRY.get(hostEl);
    if (entry) {
      if (typeof entry.stopResize === "function") entry.stopResize();
      if (entry.chart && (!entry.chart.isDisposed || !entry.chart.isDisposed())) entry.chart.dispose();
      REGISTRY.delete(hostEl);
    }
    if (globalScope.echarts && typeof globalScope.echarts.getInstanceByDom === "function") {
      const existing = globalScope.echarts.getInstanceByDom(hostEl);
      if (existing && (!existing.isDisposed || !existing.isDisposed())) existing.dispose();
    }
  }

  function attachResize(hostEl, chart) {
    if (globalScope.QuietEChartsDefaults && typeof globalScope.QuietEChartsDefaults.observeChartResize === "function") {
      return globalScope.QuietEChartsDefaults.observeChartResize(hostEl, chart);
    }
    let raf = 0;
    const resizeNow = () => {
      if (raf) return;
      raf = globalScope.requestAnimationFrame(() => {
        raf = 0;
        if (hostEl.clientWidth > 0 && (!chart.isDisposed || !chart.isDisposed())) chart.resize();
      });
    };
    let ro = null;
    if (typeof globalScope.ResizeObserver === "function") {
      ro = new globalScope.ResizeObserver(resizeNow);
      ro.observe(hostEl);
    } else {
      globalScope.addEventListener("resize", resizeNow);
    }
    return () => {
      if (raf) globalScope.cancelAnimationFrame(raf);
      if (ro) ro.disconnect();
      else globalScope.removeEventListener("resize", resizeNow);
    };
  }

  function mountChart(hostEl, buildOptionFn, emptyMsg) {
    if (!hostEl) return null;
    disposeHost(hostEl);
    const tok = readThemeTokens();
    const opt = buildOptionFn(tok, hostEl);
    if (!opt) {
      hostEl.removeAttribute("data-rows");
      const p = document.createElement("p");
      p.className = "chart-empty";
      p.textContent = emptyMsg || "No chart data available.";
      hostEl.replaceChildren(p);
      return null;
    }
    if (!globalScope.echarts || typeof globalScope.echarts.init !== "function") {
      const p = document.createElement("p");
      p.className = "chart-empty";
      p.textContent = "Chart engine unavailable.";
      hostEl.replaceChildren(p);
      return null;
    }
    hostEl.replaceChildren();
    const chart = globalScope.echarts.init(hostEl, null, { renderer: "svg" });
    chart.setOption(opt, true);
    const stopResize = attachResize(hostEl, chart);
    REGISTRY.set(hostEl, { chart, buildOption: buildOptionFn, stopResize });
    return chart;
  }

  function tooltipStyle(tok) {
    return {
      backgroundColor: tok.bgElevated,
      borderColor: tok.borderStrong,
      borderWidth: 1,
      textStyle: { color: tok.textPrimary, fontFamily: tok.fontSans, fontSize: 12 },
      confine: true
    };
  }

  function normalizeWhiskers(rawSeries) {
    const list = Array.isArray(rawSeries) ? rawSeries : (rawSeries && (rawSeries.series || rawSeries.hops || rawSeries.stages)) || [];
    const rows = [];
    for (let i = 0; i < list.length; i += 1) {
      const item = list[i];
      if (!item || typeof item !== "object") continue;
      const min = toNum(item.minMs !== undefined ? item.minMs : item.min, 0);
      const avg = toNum(item.avgMs !== undefined ? item.avgMs : (item.avg !== undefined ? item.avg : item.rttMs), min);
      const max = toNum(item.maxMs !== undefined ? item.maxMs : item.max, avg);
      const lo = Math.max(0, Math.min(min, avg, max));
      const hi = Math.max(lo, min, avg, max);
      rows.push({
        label: String(item.label || item.name || item.hop || ("Hop " + (i + 1))),
        min: lo,
        avg: Math.min(hi, Math.max(lo, avg)),
        max: hi,
        lossPct: Math.min(100, Math.max(0, toNum(item.lossPct !== undefined ? item.lossPct : item.loss, 0)))
      });
    }
    return rows;
  }

  function horizontalChartBase(tok, hostEl, cats, maxVal, xName, rightPad, bottomPad, tipFmt, series) {
    const narrow = ((hostEl && hostEl.clientWidth) || 640) < 460;
    const scale = computeNiceMax(maxVal);
    return {
      animation: false, backgroundColor: "transparent",
      textStyle: { fontFamily: tok.fontSans, color: tok.textPrimary },
      tooltip: Object.assign(tooltipStyle(tok), { trigger: "axis", axisPointer: { type: "shadow" }, formatter: tipFmt }),
      grid: { left: computeGutterPx(cats, tok, narrow ? 112 : 168), right: narrow ? Math.min(rightPad, 72) : rightPad, top: 14, bottom: bottomPad, containLabel: false },
      xAxis: {
        type: "value", name: xName || "ms", nameLocation: "end", nameGap: 6, min: 0, max: scale.max,
        splitNumber: narrow ? 3 : 5,
        nameTextStyle: { color: tok.textMuted, fontSize: 11, fontFamily: tok.fontMono, align: "left", verticalAlign: "top", padding: [5, 0, 0, 2] },
        axisLine: { lineStyle: { color: tok.borderStrong } },
        axisLabel: { color: tok.textSecondary, fontSize: 11, fontFamily: tok.fontMono, hideOverlap: true },
        splitLine: { lineStyle: { color: tok.borderHairline, type: "dashed" } }
      },
      yAxis: {
        type: "category", inverse: true, data: cats,
        axisLine: { lineStyle: { color: tok.borderStrong } },
        axisTick: { show: false },
        axisLabel: { color: tok.textPrimary, fontSize: 11 }
      },
      series: series
    };
  }

  function renderWhiskers(hostEl, rawSeries) {
    const rows = normalizeWhiskers(rawSeries);
    const isLossOnly = (r) => r.lossPct >= 100 || (r.max === 0 && r.lossPct > 0);
    if (hostEl) hostEl.dataset.rows = rows.length > 6 ? "many" : "few";
    return mountChart(hostEl, (tok, el) => {
      if (!rows.length) return null;
      const cats = rows.map((r) => trimLabel(r.label, (el.clientWidth || 640) < 460 ? 18 : 26));
      const maxVal = Math.max.apply(null, rows.map((r) => r.max).concat([1]));
      const customData = rows.map((r, idx) => [idx, r.min, r.max, r.avg, r.lossPct]);
      const avgData = rows.map((r, idx) => (isLossOnly(r) ? null : {
        value: [r.avg, idx],
        itemStyle: { color: r.lossPct >= 20 ? tok.statusDanger : (r.lossPct > 0 ? tok.statusWarn : tok.chart2), borderColor: tok.bgSurface, borderWidth: 1.5 }
      }));
      const labelData = rows.map((r, idx) => {
        const lossOnly = isLossOnly(r);
        return {
          value: [lossOnly ? 0 : r.max, idx], symbol: lossOnly ? "diamond" : "circle", symbolSize: lossOnly ? 8 : 1,
          itemStyle: lossOnly ? { color: tok.statusDanger, borderColor: tok.bgSurface, borderWidth: 1.5, opacity: 1 } : { color: "transparent", borderWidth: 0, opacity: 1 },
          label: lossOnly ? { color: tok.statusDanger } : undefined
        };
      });
      const opt = horizontalChartBase(tok, el, cats, maxVal, "ms", 92, 52, (params) => {
        const first = Array.isArray(params) ? params[0] : params;
        const r = rows[first ? first.dataIndex : 0];
        if (!r) return "";
        const lbl = "<strong>" + escHtml(r.label) + "</strong>";
        if (isLossOnly(r)) return lbl + "<br/>Packet Loss: " + escHtml(fmtMs(r.lossPct)) + "%";
        return [lbl, "Min: " + escHtml(fmtMs(r.min)) + " ms", "Avg: " + escHtml(fmtMs(r.avg)) + " ms", "Max: " + escHtml(fmtMs(r.max)) + " ms", "Loss: " + escHtml(fmtMs(r.lossPct)) + "%"].join("<br/>");
      }, [
        {
          name: "Min–Max Range", type: "custom", z: 2, itemStyle: { color: tok.accentPrimary }, data: customData,
          renderItem: (params, api) => {
            const idx = api.value(0), lo = api.value(1), hi = api.value(2), loss = api.value(4);
            if (loss >= 100 || (hi === 0 && loss > 0)) return null;
            const pLo = api.coord([lo, idx]), pHi = api.coord([hi, idx]);
            const stroke = loss >= 20 ? tok.statusDanger : (loss > 0 ? tok.statusWarn : tok.accentPrimary);
            return { type: "group", children: [
              { type: "line", shape: { x1: pLo[0], y1: pLo[1], x2: pHi[0], y2: pHi[1] }, style: { stroke, lineWidth: 2.2 } },
              { type: "line", shape: { x1: pLo[0], y1: pLo[1] - 6, x2: pLo[0], y2: pLo[1] + 6 }, style: { stroke, lineWidth: 2 } },
              { type: "line", shape: { x1: pHi[0], y1: pHi[1] - 6, x2: pHi[0], y2: pHi[1] + 6 }, style: { stroke, lineWidth: 2 } }
            ] };
          }
        },
        { name: "Average RTT", type: "scatter", z: 4, symbolSize: 9, itemStyle: { color: tok.chart2, borderColor: tok.bgSurface, borderWidth: 1.5 }, data: avgData },
        {
          name: "Value Labels", type: "scatter", z: 5, silent: true, legendHoverLink: false, tooltip: { show: false }, data: labelData,
          label: {
            show: true, position: "right", distance: 10, fontFamily: tok.fontMono, fontSize: 11, color: tok.textSecondary,
            textBorderColor: tok.bgElevated, textBorderWidth: 4,
            formatter: (p) => {
              const r = rows[p.dataIndex];
              if (!r) return "";
              if (r.lossPct >= 100) return "100% loss";
              if (r.max === 0 && r.lossPct > 0) return fmtMs(r.lossPct) + "% loss";
              return r.lossPct > 0 ? fmtMs(r.avg) + " ms (" + fmtMs(r.lossPct) + "%)" : fmtMs(r.avg) + " ms";
            }
          }
        }
      ]);
      opt.legend = { bottom: 0, left: "center", itemWidth: 14, itemHeight: 8, textStyle: { color: tok.textSecondary, fontSize: 11 }, data: [{ name: "Min–Max Range", icon: "rect", itemStyle: { color: tok.accentPrimary } }, { name: "Average RTT", icon: "circle", itemStyle: { color: tok.chart2, borderColor: tok.bgSurface, borderWidth: 1.5 } }] };
      return opt;
    }, "No latency whisker data available.");
  }

  function renderWaterfall(hostEl, rawPhases) {
    const list = Array.isArray(rawPhases) ? rawPhases : (rawPhases && rawPhases.phases) || [];
    const rows = [];
    let cursor = 0;
    for (let i = 0; i < list.length; i += 1) {
      const item = list[i];
      if (!item || typeof item !== "object") continue;
      const label = String(item.label || item.name || item.phase || ("Phase " + (i + 1)));
      const dur = Math.max(0, toNum(item.durationMs !== undefined ? item.durationMs : (item.duration !== undefined ? item.duration : item.ms), 0));
      const isTotal = Boolean(item.isTotal || label.toLowerCase() === "total");
      const start = item.startMs !== undefined ? Math.max(0, toNum(item.startMs, 0)) : (isTotal ? 0 : cursor);
      if (!isTotal && item.startMs === undefined) cursor = start + dur;
      rows.push({ label, start, duration: dur, end: start + dur, isTotal });
    }
    if (hostEl) hostEl.dataset.rows = rows.length > 6 ? "many" : "few";
    return mountChart(hostEl, (tok, el) => {
      if (!rows.length) return null;
      const palette = [tok.chart1, tok.chart2, tok.chart3, tok.chart4, tok.textSecondary];
      const cats = rows.map((r) => trimLabel(r.label, (el.clientWidth || 640) < 460 ? 18 : 24));
      const maxVal = Math.max.apply(null, rows.map((r) => r.end).concat([1]));
      return horizontalChartBase(tok, el, cats, maxVal, "ms", 82, 42, (params) => {
        const first = Array.isArray(params) ? params[0] : params;
        const r = rows[first ? first.dataIndex : 0];
        return r ? ["<strong>" + escHtml(r.label) + "</strong>", "Duration: " + escHtml(fmtMs(r.duration)) + " ms", "Window: " + escHtml(fmtMs(r.start)) + " – " + escHtml(fmtMs(r.end)) + " ms"].join("<br/>") : "";
      }, [
        { name: "Offset", type: "bar", stack: "wf", silent: true, barMaxWidth: 18, itemStyle: { color: "transparent" }, tooltip: { show: false }, data: rows.map((r) => r.start) },
        {
          name: "Duration", type: "bar", stack: "wf", barMaxWidth: 18,
          label: { show: true, position: "right", fontFamily: tok.fontMono, fontSize: 11, color: tok.textSecondary, textBorderColor: tok.bgElevated, textBorderWidth: 4, formatter: (p) => fmtMs(p.value) + " ms" },
          data: rows.map((r, idx) => ({ value: r.duration, itemStyle: { color: r.isTotal ? tok.textSecondary : palette[idx % 4], borderRadius: [3, 3, 3, 3] } }))
        }
      ]);
    }, "No timing breakdown data available.");
  }

  function renderDnsComparison(hostEl, rawRows) {
    const rows = (Array.isArray(rawRows) ? rawRows : []).filter((x) => x && typeof x === "object").map((r, i) => ({
      resolver: String(r.resolver || ("Resolver " + (i + 1))), latency: Math.max(0, toNum(r.latency_ms, 0)),
      answers: Array.isArray(r.answers) ? r.answers : [], status: String(r.status || "OK").toUpperCase(), match: Boolean(r.match)
    }));
    return mountChart(hostEl, (tok, el) => {
      if (!rows.length) return null;
      const useLat = rows.some((r) => r.latency > 0);
      const maxVal = Math.max.apply(null, rows.map((r) => (useLat ? r.latency : r.answers.length)).concat([1]));
      const cats = rows.map((r) => trimLabel(r.resolver, (el.clientWidth || 640) < 460 ? 18 : 24));
      return horizontalChartBase(tok, el, cats, maxVal, useLat ? "ms" : "records", 86, 42, (params) => {
        const first = Array.isArray(params) ? params[0] : params;
        const r = rows[first ? first.dataIndex : 0];
        if (!r) return "";
        const lat = r.latency > 0 ? " (" + escHtml(fmtMs(r.latency)) + " ms)" : "";
        return ["<strong>" + escHtml(r.resolver) + "</strong>", "Status: " + escHtml(r.status) + lat, "Answers: " + (r.answers.length ? escHtml(r.answers.join(", ")) : "none")].join("<br/>");
      }, [{
        name: useLat ? "Latency" : "Records", type: "bar", barMaxWidth: 18,
        label: {
          show: true, position: "right", fontFamily: tok.fontMono, fontSize: 11, color: tok.textSecondary, textBorderColor: tok.bgElevated, textBorderWidth: 4,
          formatter: (p) => { const r = rows[p.dataIndex]; return useLat ? (fmtMs(r.latency) + " ms · " + r.status) : (r.answers.length + " ans · " + r.status); }
        },
        data: rows.map((r) => ({ value: useLat ? r.latency : r.answers.length, itemStyle: { color: r.status === "FAIL" || r.status === "MISMATCH" ? tok.statusDanger : (r.status === "WARN" || !r.match ? tok.statusWarn : tok.statusOk), borderRadius: [3, 3, 3, 3] } }))
      }]);
    }, "No resolver comparison data available.");
  }

  function renderHistoryTimeline(hostEl, rawBuckets) {
    const rows = (Array.isArray(rawBuckets) ? rawBuckets : []).filter((b) => b && typeof b === "object").map((b) => ({
      label: String(b.label || b.ts || ""),
      avg: Math.max(0, toNum(b.avg_ms, 0)),
      max: Math.max(0, toNum(b.max_ms, 0)),
      ok: toNum(b.ok_count, 0), warn: toNum(b.warn_count, 0), fail: toNum(b.fail_count, 0),
      uptime: toNum(b.uptime_pct, 100),
      status: String(b.status || "OK").toUpperCase()
    }));
    return mountChart(hostEl, (tok, el) => {
      if (!rows.length) return null;
      const scale = computeNiceMax(Math.max.apply(null, rows.map((r) => Math.max(r.avg, r.max)).concat([1])));
      const cw = el.clientWidth || 640;
      const step = rows.length > 10 ? Math.max(1, Math.ceil(rows.length / (cw < 560 ? 5 : 10))) : 0;
      const eventPoints = [];
      for (let i = 0; i < rows.length; i += 1) {
        const r = rows[i];
        if (r.fail > 0 || r.warn > 0 || r.status !== "OK") {
          eventPoints.push({
            value: [i, Math.max(r.avg, r.max)],
            itemStyle: { color: r.fail > 0 || r.status === "FAIL" ? tok.statusDanger : tok.statusWarn, borderColor: tok.bgSurface, borderWidth: 1.5 }
          });
        }
      }
      return {
        animation: false, backgroundColor: "transparent",
        textStyle: { fontFamily: tok.fontSans, color: tok.textPrimary },
        tooltip: Object.assign(tooltipStyle(tok), {
          trigger: "axis",
          formatter: (params) => {
            const first = Array.isArray(params) ? params[0] : params;
            const r = rows[first ? first.dataIndex : 0];
            return r ? [
              "<strong>" + escHtml(r.label) + "</strong> (" + escHtml(r.status) + ")",
              "Average: " + escHtml(fmtMs(r.avg)) + " ms · Peak: " + escHtml(fmtMs(r.max)) + " ms",
              "Uptime: " + escHtml(fmtMs(r.uptime)) + "% (" + escHtml(r.ok) + " OK / " + escHtml(r.warn) + " Warn / " + escHtml(r.fail) + " Fail)"
            ].join("<br/>") : "";
          }
        }),
        legend: { bottom: 0, left: "center", itemWidth: 14, itemHeight: 8, textStyle: { color: tok.textSecondary, fontSize: 11 }, data: ["Average (ms)", "Peak (ms)", "Warn / Fail"] },
        grid: { left: 52, right: 18, top: 28, bottom: 52, containLabel: false },
        xAxis: {
          type: "category", data: rows.map((r) => r.label), boundaryGap: false,
          axisLine: { lineStyle: { color: tok.borderStrong } },
          axisLabel: { color: tok.textSecondary, fontSize: 11, interval: step > 0 ? (idx) => idx % step === 0 || idx === rows.length - 1 : 0, hideOverlap: true }
        },
        yAxis: {
          type: "value", name: "ms", nameGap: 10, min: 0, max: scale.max,
          axisLine: { lineStyle: { color: tok.borderStrong } },
          axisLabel: { color: tok.textSecondary, fontSize: 11, fontFamily: tok.fontMono },
          splitLine: { lineStyle: { color: tok.borderHairline, type: "dashed" } }
        },
        series: [
          { name: "Peak (ms)", type: "line", symbol: "none", lineStyle: { color: tok.chart4, width: 1.5, type: "dashed" }, itemStyle: { color: tok.chart4 }, data: rows.map((r) => r.max) },
          { name: "Average (ms)", type: "line", symbol: "circle", symbolSize: 5, lineStyle: { color: tok.accentPrimary, width: 2.2 }, itemStyle: { color: tok.accentPrimary }, areaStyle: { color: tok.accentPrimary, opacity: 0.1 }, data: rows.map((r) => r.avg) },
          { name: "Warn / Fail", type: "scatter", symbol: "diamond", symbolSize: 11, z: 5, itemStyle: { color: tok.statusWarn, borderColor: tok.bgSurface, borderWidth: 1.5 }, data: eventPoints }
        ]
      };
    }, "No check history recorded in this window yet.");
  }

  function rethemeAll() {
    const entries = Array.from(REGISTRY.entries());
    for (let i = 0; i < entries.length; i += 1) {
      const hostEl = entries[i][0];
      const entry = entries[i][1];
      if (!document.contains(hostEl)) disposeHost(hostEl);
      else mountChart(hostEl, entry.buildOption);
    }
  }

  function refreshInContainer(rootEl) {
    const scope = rootEl || document;
    globalScope.requestAnimationFrame(() => {
      REGISTRY.forEach((entry, hostEl) => {
        if (!document.contains(hostEl)) return disposeHost(hostEl);
        if (scope.contains(hostEl) && hostEl.clientWidth > 0 && (!entry.chart.isDisposed || !entry.chart.isDisposed())) {
          entry.chart.resize();
        }
      });
    });
  }

  if (typeof MutationObserver === "function") {
    themeObserver = new MutationObserver((mutations) => {
      for (let i = 0; i < mutations.length; i += 1) {
        if (mutations[i].attributeName === "data-theme") {
          rethemeAll();
          break;
        }
      }
    });
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  }

  function renderTlsStrip(stripEl, tls) {
    if (!stripEl) return;
    if (!tls || typeof tls !== "object") { stripEl.hidden = true; stripEl.replaceChildren(); return; }
    const days = Number(tls.days_remaining ?? 0), valid = Boolean(tls.valid) && Boolean(tls.hostname_match);
    const tone = !valid || days <= 7 ? "fault" : days < 30 ? "warn" : "nominal";
    const pill = document.createElement("span");
    pill.className = "va-pill";
    pill.textContent = (valid ? "TLS Valid" : "TLS Attention") + " · " + days + "d left";
    pill.setAttribute("data-variant", "status");
    pill.setAttribute("data-state", tone);
    const addMeta = (k, v) => {
      const wrap = document.createElement("span"), strong = document.createElement("strong");
      wrap.className = "tls-meta-item";
      strong.textContent = k + ": ";
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

  globalScope.NetutilsCharts = {
    renderWhiskers, renderWaterfall, renderDnsComparison, renderHistoryTimeline,
    renderTlsStrip, disposeHost, rethemeAll, refreshInContainer, fmtMs
  };
})(typeof window !== "undefined" ? window : globalThis);
