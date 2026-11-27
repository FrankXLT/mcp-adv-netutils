/* SPDX-License-Identifier: Apache-2.0 */
/**
 * Quiet UI Pillar 2 — Progressive-Enhancement Evidence Runtime (<= 250L, zero deps).
 * Features:
 *   1. Synchronized multi-channel waveform cursor readout ([data-qe-scope="true"])
 *   2. Pedagogical Flow equation-to-visual term highlighting ([data-term])
 *   3. Spec drawer metadata & copy-JSON feedback
 */
(function (window, document) {
  'use strict';

  var termsBound = false;

  function findNearestSample(samples, targetT, maxGap) {
    if (!Array.isArray(samples) || samples.length === 0) return null;
    for (let i = 0; i < samples.length - 1; i++) {
      const a = samples[i];
      const b = samples[i + 1];
      if (!Array.isArray(a) || !Array.isArray(b) || a.length < 2 || b.length < 2) continue;
      const t0 = Number(a[0]);
      const t1 = Number(b[0]);
      if (targetT >= t0 && targetT <= t1) {
        if (Math.abs(targetT - t0) < 1e-6 && a[1] !== null && a[1] !== undefined) return a;
        if (Math.abs(targetT - t1) < 1e-6 && b[1] !== null && b[1] !== undefined) return b;
        if (a[1] === null || a[1] === undefined || b[1] === null || b[1] === undefined) {
          return null;
        }
        if (Number.isFinite(maxGap) && maxGap > 0 && (t1 - t0) > maxGap) {
          return null;
        }
      }
    }
    let best = null;
    let bestDt = Infinity;
    for (let i = 0; i < samples.length; i++) {
      const s = samples[i];
      if (!Array.isArray(s) || s.length < 2) continue;
      const dt = Math.abs(Number(s[0]) - targetT);
      if (dt < bestDt) {
        bestDt = dt;
        best = s;
      }
    }
    return best;
  }

  function renderScopeAtTime(svg, meta, targetT) {
    if (!Number.isFinite(meta.x0) || !Number.isFinite(meta.pw) || meta.pw <= 0) return;
    if (!Number.isFinite(meta.t_min) || !Number.isFinite(meta.t_span) || meta.t_span <= 0) return;
    const t = Math.max(meta.t_min, Math.min(meta.t_min + meta.t_span, targetT));
    const clampedX = meta.x0 + ((t - meta.t_min) / meta.t_span) * meta.pw;
    svg.dataset.qeCursorT = String(t);

    const cursorLine = svg.querySelector('.qe-live-cursor');
    if (cursorLine) {
      cursorLine.setAttribute('x1', clampedX.toFixed(1));
      cursorLine.setAttribute('x2', clampedX.toFixed(1));
      cursorLine.setAttribute('visibility', 'visible');
    }

    const wrap = svg.closest('.qe-waveform-wrap') || svg.closest('.qe-plot-wrap');
    const readout = wrap ? wrap.querySelector('.qe-scope-readout') : null;
    if (!readout) return;

    const gapLim = Number(meta.max_gap);
    const vals = (meta.channels || []).map(function (ch) {
      const cid = String((ch && ch.id) || 'CH').toUpperCase();
      const s = findNearestSample(ch && ch.samples, t, gapLim);
      if (!s || s[1] === null || s[1] === undefined) {
        return cid + ': DROPOUT';
      }
      const vStr = typeof s[1] === 'number' ? Number(s[1]).toFixed(2) : String(s[1]);
      return cid + ': ' + vStr + (ch.unit ? '\u00a0' + ch.unit : '');
    });
    readout.textContent = 't = ' + t.toFixed(2) + '\u00a0' + (meta.t_unit || '') + '  |  ' + vals.join('  |  ');
  }

  function updateScopeCursor(svg, meta, clientX) {
    const rect = svg.getBoundingClientRect();
    const vb = svg.viewBox && svg.viewBox.baseVal;
    if (!rect.width || !vb || !vb.width || !meta.pw || meta.pw <= 0) return;
    const svgX = ((clientX - rect.left) / rect.width) * vb.width;
    const clampedX = Math.max(meta.x0, Math.min(meta.x0 + meta.pw, svgX));
    const t = meta.t_min + ((clampedX - meta.x0) / meta.pw) * meta.t_span;
    renderScopeAtTime(svg, meta, t);
  }

  function clearScopeCursor(svg) {
    const cursorLine = svg.querySelector('.qe-live-cursor');
    if (cursorLine) cursorLine.setAttribute('visibility', 'hidden');
    const wrap = svg.closest('.qe-waveform-wrap') || svg.closest('.qe-plot-wrap');
    const readout = wrap ? wrap.querySelector('.qe-scope-readout') : null;
    if (readout) {
      if (readout._qeDefaultNodes && readout._qeDefaultNodes.length) {
        readout.replaceChildren.apply(readout, readout._qeDefaultNodes.map(function (n) { return n.cloneNode(true); }));
      } else if (readout.dataset.default) {
        readout.textContent = readout.dataset.default;
      }
    }
  }

  function initWaveforms() {
    document.querySelectorAll('svg[data-qe-scope="true"]').forEach(function (svg) {
      if (svg.dataset.qeScopeBound === '1') return;
      const wrap = svg.closest('.qe-waveform-wrap') || svg.closest('.qe-plot-wrap');
      const dataEl = wrap ? wrap.querySelector('.qe-scope-data') : null;
      const roEl = wrap ? wrap.querySelector('.qe-scope-readout') : null;
      if (roEl && !roEl._qeDefaultNodes) roEl._qeDefaultNodes = Array.from(roEl.childNodes, function (n) { return n.cloneNode(true); });
      if (!dataEl) return;
      let meta = null;
      try {
        meta = JSON.parse(dataEl.textContent || '{}');
      } catch (_err) {
        return;
      }
      svg.dataset.qeScopeBound = '1';
      svg.addEventListener('pointermove', function (ev) { updateScopeCursor(svg, meta, ev.clientX); });
      svg.addEventListener('pointerdown', function (ev) { updateScopeCursor(svg, meta, ev.clientX); });
      svg.addEventListener('pointerleave', function () { clearScopeCursor(svg); });
      svg.addEventListener('keydown', function (ev) {
        const curT = Number(svg.dataset.qeCursorT || meta.t_min);
        const dt = Number(meta.dt);
        const step = (Number.isFinite(dt) && dt > 0 && ((meta.t_span || 1) / dt) <= 200) ? dt : ((meta.t_span || 1) / 40);
        if (ev.key === 'ArrowRight') { ev.preventDefault(); renderScopeAtTime(svg, meta, curT + step); }
        else if (ev.key === 'ArrowLeft') { ev.preventDefault(); renderScopeAtTime(svg, meta, curT - step); }
        else if (ev.key === 'Home') { ev.preventDefault(); renderScopeAtTime(svg, meta, meta.t_min); }
        else if (ev.key === 'End') { ev.preventDefault(); renderScopeAtTime(svg, meta, meta.t_min + meta.t_span); }
        else if (ev.key === 'Escape') { clearScopeCursor(svg); }
      });
    });
  }

  function setActiveTerm(scopeRoot, termKey) {
    if (!scopeRoot) return;
    scopeRoot.querySelectorAll('[data-term]').forEach(function (el) {
      if (!termKey) {
        el.classList.remove('is-term-active', 'is-term-dimmed');
      } else if (el.getAttribute('data-term') === termKey) {
        el.classList.add('is-term-active');
        el.classList.remove('is-term-dimmed');
      } else {
        el.classList.remove('is-term-active');
        el.classList.add('is-term-dimmed');
      }
    });
  }

  function initPedagogicalTerms() {
    if (termsBound) return;
    termsBound = true;
    const resolveScope = function (ev) {
      const target = ev.target && ev.target.closest ? ev.target.closest('[data-term]') : null;
      if (!target) return null;
      return { target: target, scope: target.closest('.qe-pedagogy-scope') || target.closest('.qe-figure') || document };
    };
    document.addEventListener('pointerover', function (ev) { const r = resolveScope(ev); if (r) setActiveTerm(r.scope, r.target.getAttribute('data-term')); });
    document.addEventListener('pointerout', function (ev) { const r = resolveScope(ev); if (r) setActiveTerm(r.scope, r.scope.dataset.pinnedTerm || null); });
    document.addEventListener('click', function (ev) {
      const btn = ev.target && ev.target.closest ? ev.target.closest('button[data-term], .qe-eq-term[data-term]') : null;
      if (!btn) return;
      const scope = btn.closest('.qe-pedagogy-scope') || btn.closest('.qe-figure') || document;
      const term = btn.getAttribute('data-term');
      const next = (scope.dataset.pinnedTerm === term) ? '' : (term || '');
      if (next) scope.dataset.pinnedTerm = next;
      else delete scope.dataset.pinnedTerm;
      setActiveTerm(scope, next || null);
      scope.querySelectorAll('button[data-term], .qe-eq-term[data-term]').forEach(function (b) {
        b.setAttribute('aria-pressed', (next && b.getAttribute('data-term') === next) ? 'true' : 'false');
      });
    });
    document.addEventListener('focusin', function (ev) { const r = resolveScope(ev); if (r) setActiveTerm(r.scope, r.target.getAttribute('data-term')); });
    document.addEventListener('focusout', function (ev) { const r = resolveScope(ev); if (r) setActiveTerm(r.scope, r.scope.dataset.pinnedTerm || null); });
  }

  function copyWithFallback(txt, btn, defaultLabel, statusEl) {
    const label = defaultLabel || 'Copy JSON Spec';
    const markCopied = function (msg) {
      if (statusEl) {
        statusEl.textContent = msg;
        statusEl.classList.add('is-visible');
        window.setTimeout(function () { statusEl.classList.remove('is-visible'); statusEl.textContent = ''; }, 1800);
      } else {
        btn.textContent = msg;
        window.setTimeout(function () { btn.textContent = label; }, 1400);
      }
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(txt).then(function () { markCopied('Copied'); }).catch(function () {});
      return;
    }
    const ta = document.createElement('textarea');
    ta.value = txt;
    ta.setAttribute('readonly', '');
    ta.style.cssText = 'position:fixed;opacity:0;pointer-events:none;left:-9999px';
    document.body.appendChild(ta);
    ta.select();
    try { if (document.execCommand('copy')) markCopied('Copied'); } catch (_err) {}
    document.body.removeChild(ta);
  }

  function initSpecDrawers() {
    document.querySelectorAll('.qe-spec-drawer').forEach(function (dlg) {
      if (dlg.querySelector('.qe-copy-spec-btn')) return;
      const pre = dlg.querySelector('pre');
      if (!pre) return;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'va-pill-btn qe-copy-spec-btn';
      btn.textContent = 'Copy JSON Spec';
      btn.addEventListener('click', function () { copyWithFallback(pre.textContent || '', btn, 'Copy JSON Spec'); });
      pre.parentNode.insertBefore(btn, pre);
    });
  }

  function activateEcoTabFallback(tabBtn) {
    const wrap = tabBtn && tabBtn.closest('.qe-eco-drawer');
    if (!wrap) return;
    const targetId = tabBtn.getAttribute('aria-controls');
    wrap.querySelectorAll('.qe-eco-tab[role="tab"]').forEach(function (t) {
      const on = t === tabBtn;
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
    });
    wrap.querySelectorAll('.qe-eco-panel[role="tabpanel"]').forEach(function (p) {
      if (p.id === targetId) p.removeAttribute('hidden');
      else p.setAttribute('hidden', 'until-found');
    });
  }

  function initEcoAndModeFallback() {
    const hideUnusedModebars = function () {
      const hasEcharts = typeof window.echarts !== 'undefined' || (window.parent && window.parent !== window && typeof window.parent.echarts !== 'undefined');
      if (typeof window.QuietEChartsAdapter === 'undefined' && !hasEcharts) {
        document.querySelectorAll('.qe-plot-modebar').forEach(function (bar) { bar.hidden = true; });
      }
    };
    if (typeof queueMicrotask === 'function') queueMicrotask(hideUnusedModebars);
    else window.setTimeout(hideUnusedModebars, 0);
    if (typeof window.QuietEChartsAdapter !== 'undefined' || document.documentElement.dataset.qeEcoFallback === '1') return;
    document.documentElement.dataset.qeEcoFallback = '1';
    document.addEventListener('click', function (ev) {
      if (typeof window.QuietEChartsAdapter !== 'undefined') return;
      const tab = ev.target && ev.target.closest ? ev.target.closest('.qe-eco-tab[role="tab"]') : null;
      if (tab) { activateEcoTabFallback(tab); return; }
      const copyBtn = ev.target && ev.target.closest ? ev.target.closest('.qe-copy-btn') : null;
      if (copyBtn) {
        const drw = copyBtn.closest('.qe-eco-drawer');
        const pre = drw && drw.querySelector('.qe-eco-panel:not([hidden]) pre');
        if (pre) copyWithFallback(pre.textContent || '', copyBtn, copyBtn.textContent, drw.querySelector('.qe-copy-status'));
      }
    });
    document.addEventListener('keydown', function (ev) {
      if (typeof window.QuietEChartsAdapter !== 'undefined') return;
      const tab = ev.target && ev.target.closest ? ev.target.closest('.qe-eco-tab[role="tab"]') : null;
      if (!tab) return;
      const list = tab.closest('[role="tablist"]');
      const tabs = list ? Array.prototype.slice.call(list.querySelectorAll('.qe-eco-tab[role="tab"]')) : [];
      const idx = tabs.indexOf(tab);
      if (idx < 0) return;
      const nxt = ev.key === 'ArrowRight' ? (idx + 1) % tabs.length : (ev.key === 'ArrowLeft' ? (idx - 1 + tabs.length) % tabs.length : (ev.key === 'Home' ? 0 : (ev.key === 'End' ? tabs.length - 1 : -1)));
      if (nxt >= 0) { ev.preventDefault(); activateEcoTabFallback(tabs[nxt]); tabs[nxt].focus(); }
    });
    document.addEventListener('beforematch', function (ev) {
      if (typeof window.QuietEChartsAdapter !== 'undefined') return;
      const panel = ev.target && ev.target.closest ? ev.target.closest('.qe-eco-panel[role="tabpanel"]') : null;
      const tid = panel && panel.getAttribute('aria-labelledby');
      if (tid) activateEcoTabFallback(document.getElementById(tid));
    }, true);
  }

  function boot() {
    initWaveforms();
    initPedagogicalTerms();
    initSpecDrawers();
    initEcoAndModeFallback();
  }

  if (typeof document !== 'undefined' && document) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', boot);
    } else {
      boot();
    }
  }

  window.QuietEvidenceRuntime = {
    boot: boot,
    setActiveTerm: setActiveTerm,
    renderScopeAtTime: renderScopeAtTime,
    clearScopeCursor: clearScopeCursor
  };
})(window, typeof document !== 'undefined' ? document : null);


// SPDX-License-Identifier: Apache-2.0
(function (root) {
  'use strict';

  var _measureCtx = null;
  var _COMB_RE = /^[\u0300-\u036F\u1AB0-\u1AFF\u1DC0-\u1DFF\u200B-\u200F\u20D0-\u20FF\uFE20-\uFE2F\uFEFF]$/;
  var _WIDE_RE = /[\u1100-\u115F\u2E80-\u9FFF\uAC00-\uD7AF\uF900-\uFAFF\uFE30-\uFE6F\uFF01-\uFF60\u{20000}-\u{2FA1F}]/u;

  function charUnit(ch, cp) {
    return _COMB_RE.test(ch) ? 0 : (_WIDE_RE.test(ch) ? 1.75 : 1.0);
  }

  function visualUnits(text) {
    var s = String(text == null ? '' : text), u = 0;
    for (var i = 0; i < s.length; i += 1) {
      var cp = s.codePointAt(i), ch = String.fromCodePoint(cp);
      if (cp > 0xFFFF) i += 1;
      u += charUnit(ch, cp);
    }
    return u;
  }

  function getMeasureCtx() {
    if (_measureCtx) return _measureCtx;
    if (typeof document !== 'undefined' && document && document.createElement) {
      var canvas = document.createElement('canvas');
      if (canvas && canvas.getContext) _measureCtx = canvas.getContext('2d');
    }
    return _measureCtx;
  }

  function measureTextPx(text, fontSpec) {
    var s = String(text == null ? '' : text), fb = visualUnits(s) * 6.8;
    var ctx = getMeasureCtx();
    if (ctx) {
      ctx.font = fontSpec || '11px Inter, system-ui, sans-serif';
      var w = ctx.measureText(s).width;
      return (w > 0 || !s) ? w : fb;
    }
    return fb;
  }

  function roundClean(v) {
    return Math.abs(v) < 1e-12 ? 0 : Number(v.toFixed(10));
  }

  function niceStep125(rawStep) {
    if (!Number.isFinite(rawStep) || rawStep <= 0) return 1;
    var exp = Math.floor(Math.log10(rawStep));
    var pow = Math.pow(10, exp);
    var frac = rawStep / pow;
    var mant = 1;
    if (frac > 5) mant = 10;
    else if (frac > 2) mant = 5;
    else if (frac > 1) mant = 2;
    return mant * pow;
  }

  function niceScale125(minVal, maxVal, opts) {
    var cfg = opts || {};
    var targetTicks = Math.max(2, Number(cfg.targetTicks || 5));
    var lo = Number(minVal);
    var hi = Number(maxVal);
    if (!Number.isFinite(lo)) lo = 0;
    if (!Number.isFinite(hi)) hi = lo + 1;
    if (cfg.includeZero) {
      lo = Math.min(lo, 0);
      hi = Math.max(hi, 0);
    }
    if (lo > hi) { var tmp = lo; lo = hi; hi = tmp; }
    if (Math.abs(hi - lo) < 1e-9) {
      var pad = Math.abs(lo) > 1e-6 ? Math.abs(lo) * 0.2 : 1;
      lo = cfg.includeZero && lo >= 0 ? 0 : lo - pad;
      hi = hi + pad;
    }
    var step = niceStep125((hi - lo) / (targetTicks - 1));
    var sMin = roundClean(Math.floor(lo / step + 1e-9) * step);
    if (cfg.clampMin !== undefined && cfg.clampMin !== null && Number.isFinite(Number(cfg.clampMin))) {
      sMin = Math.max(Number(cfg.clampMin), sMin);
    }
    var sMax = roundClean(Math.ceil(hi / step - 1e-9) * step);
    if (sMax <= sMin) sMax = roundClean(sMin + step);
    var ticks = [];
    var guard = 0;
    for (var cur = sMin; cur <= sMax + step * 1e-4 && guard < 24; cur += step, guard += 1) {
      ticks.push(roundClean(cur));
    }
    return { min: sMin, max: sMax, step: roundClean(step), ticks: ticks };
  }

  function formatTick(v, step) {
    if (!Number.isFinite(v)) return '';
    if (Math.abs(v) < 1e-12) return '0';
    var st = Math.abs(Number(step || 1));
    var dec = st >= 1 ? 0 : Math.min(4, Math.max(1, Math.ceil(-Math.log10(st)) + 1));
    return roundClean(v).toLocaleString(undefined, { maximumFractionDigits: dec });
  }

  function firstUnclosedIdx(str) {
    var p = [], b = [];
    for (var i = 0; i < str.length; i += 1) {
      var c = str[i];
      if (c === '(') p.push(i);
      else if (c === ')' && p.length) p.pop();
      else if (c === '[') b.push(i);
      else if (c === ']' && b.length) b.pop();
    }
    var ip = p.length ? p[0] : Infinity;
    var ib = b.length ? b[0] : Infinity;
    var m = Math.min(ip, ib);
    return Number.isFinite(m) ? m : -1;
  }

  function balanceDelimiters(str) {
    var out = String(str || '').replace(/[\s,(\[:/-]+$/, '');
    var guard = 0;
    while (guard < 8) {
      var idx = firstUnclosedIdx(out);
      if (idx === -1) break;
      if (idx > 0) {
        out = out.slice(0, idx).replace(/[\s,(\[:/-]+$/, '');
      } else {
        out = out.slice(1).replace(/^[\s(\[]+/, '');
      }
      guard += 1;
    }
    return out;
  }

  function sliceUnits(str, cap) {
    var u = 0, cut = 0, s = String(str || '');
    for (var i = 0; i < s.length; i += 1) {
      var cp = s.codePointAt(i), ch = String.fromCodePoint(cp), step = cp > 0xFFFF ? 2 : 1, w = charUnit(ch, cp);
      if (cut > 0 && w > 0 && u + w > cap) break;
      u += w; cut = i + step;
      if (cp > 0xFFFF) i += 1;
    }
    return s.slice(0, Math.max(1, cut));
  }

  function truncateTokenSafe(str, limit) {
    var cap = Math.max(2, limit - 1), s = String(str || ''), sub = sliceUnits(s, cap);
    if (/\s/.test(sub)) sub = sub.replace(/\s+\S*$/, '') || sub;
    var head = balanceDelimiters(sub);
    return (head || sliceUnits(s.replace(/[(\[]/g, ''), cap)) + '\u2026';
  }

  function pushWideChunks(tok, limit, out) {
    if (!_WIDE_RE.test(tok) || visualUnits(tok) <= limit) { out.push(tok); return; }
    var cur = '', u = 0;
    for (var i = 0; i < tok.length; i += 1) {
      var cp = tok.codePointAt(i), ch = String.fromCodePoint(cp), w = charUnit(ch, cp);
      if (cp > 0xFFFF) i += 1;
      if (cur && w > 0 && u + w > limit) { out.push(cur); cur = ch; u = w; } else { cur += ch; u += w; }
    }
    if (cur) out.push(cur);
  }

  function wrapLabelLines(text, maxChars, maxLines) {
    var raw = String(text == null ? '' : text).trim().replace(/\s+/g, ' ');
    var limit = Math.max(6, Number(maxChars || 18)), capLines = Math.max(1, Number(maxLines || 2));
    if (!raw || visualUnits(raw) <= limit) return raw ? [balanceDelimiters(raw) || raw] : [''];
    var words = [], lines = [], cur = '', overflowed = false;
    raw.split(' ').forEach(function (w) { pushWideChunks(w, limit, words); });
    for (var i = 0; i < words.length; i += 1) {
      var w = words[i], next = cur ? (cur + (_WIDE_RE.test(Array.from(cur).pop()) && _WIDE_RE.test(Array.from(w)[0] || '') ? '' : ' ') + w) : w;
      if (!cur || visualUnits(next) <= limit) { cur = next; continue; }
      lines.push(cur);
      if (lines.length >= capLines) { cur = ''; overflowed = true; break; }
      cur = w;
    }
    if (cur && lines.length < capLines) lines.push(cur);
    if (lines.length && (overflowed || visualUnits(lines[lines.length - 1]) > limit)) {
      lines[lines.length - 1] = truncateTokenSafe(lines[lines.length - 1], limit);
    }
    for (var li = 0; li < lines.length - 1; li += 1) {
      if (firstUnclosedIdx(lines[li]) !== -1 && firstUnclosedIdx(lines.join(' ')) !== -1) {
        lines[li] = balanceDelimiters(lines[li]) || lines[li].replace(/[(\[]/g, '');
      }
    }
    return lines;
  }

  function isMonoLabelSet(list) {
    if (!list.length) return false;
    var hits = 0;
    for (var i = 0; i < list.length; i += 1) {
      var s = String(list[i] == null ? '' : list[i]).trim();
      if (/[_/\\:]|[a-z]+-[a-z0-9-]+|^0x[0-9a-f]+$|^\d{2,}h$/i.test(s)) hits += 1;
    }
    return hits * 2 >= list.length;
  }

  function measureCategoryGutter(labels, opts) {
    var cfg = opts || {};
    var list = Array.isArray(labels) ? labels : [];
    var numOr = function (v, d) { var n = Number(v); return v != null && v !== '' && Number.isFinite(n) ? n : d; };
    var minPx = Math.max(0, numOr(cfg.minPx, 64)), maxPx = Math.max(minPx, numOr(cfg.maxPx, 220));
    var axisMargin = Math.max(0, numOr(cfg.axisLabelMargin, 8));
    var padPx = Math.max(0, numOr(cfg.padPx, 12)) + axisMargin;
    var maxChars = Math.max(6, numOr(cfg.maxChars, 24));
    var ff = String(cfg.fontFamily || '').toLowerCase();
    var isMono = cfg.mono === true || ff === 'mono' || ff.indexOf('mono') >= 0 || (cfg.mono !== false && !cfg.fontFamily && !cfg.font && isMonoLabelSet(list));
    var fontMatch = (String(cfg.font || '').match(/(\d+(?:\.\d+)?)px/i) || [])[1];
    var rawFs = numOr(cfg.fontSize, fontMatch ? Number(fontMatch) : NaN);
    var fSize = rawFs > 0 ? rawFs : (isMono ? 12 : 11);
    var fontSpec = cfg.font || (fSize + 'px ' + (isMono ? 'JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace' : 'Inter, system-ui, sans-serif'));
    var maxW = 0;
    var wrappedLabels = list.map(function (lbl) {
      var lines = wrapLabelLines(lbl, maxChars, cfg.maxLines || 2);
      lines.forEach(function (ln) {
        var measured = measureTextPx(ln, fontSpec);
        if (isMono || _WIDE_RE.test(ln)) measured = Math.max(measured, visualUnits(ln) * fSize * 0.64);
        maxW = Math.max(maxW, measured);
      });
      return lines.join('\n');
    });
    return { gutterPx: Math.max(minPx, Math.min(maxPx, Math.ceil(maxW + padPx))), maxLinePx: Math.ceil(maxW), wrappedLabels: wrappedLabels, mono: isMono };
  }

  function filterNonOverlappingTicks(ticks, opts) {
    var list = Array.isArray(ticks) ? ticks.slice() : [];
    var cfg = opts || {};
    var axis = cfg.axis === 'y' ? 'y' : 'x';
    var gap = Math.max(2, Number(cfg.minGapPx != null ? cfg.minGapPx : 10));
    var fontSpec = cfg.font || '11px JetBrains Mono, monospace';
    var lineH = Number(cfg.lineHeightPx || 14);
    var keepEnds = !!cfg.keepEnds;
    list.sort(function (a, b) { return Number(a.pos || 0) - Number(b.pos || 0); });
    var kept = [];
    var lastEnd = -Infinity;
    list.forEach(function (tk, idx) {
      var pos = Number(tk.pos || 0);
      var lbl = String(tk.label != null ? tk.label : tk.value);
      var span = axis === 'x' ? Math.max(18, measureTextPx(lbl, fontSpec)) : lineH;
      var lo = pos - span * 0.5;
      var hi = pos + span * 0.5;
      var isLast = idx === list.length - 1;
      if (lo >= lastEnd + gap) {
        kept.push(tk);
        lastEnd = hi;
      } else if (keepEnds && isLast && kept.length > 0) {
        var prev = kept[kept.length - 1];
        var prevSpan = axis === 'x' ? Math.max(18, measureTextPx(String(prev.label != null ? prev.label : prev.value), fontSpec)) : lineH;
        if (kept.length > 1) {
          var beforePrev = kept[kept.length - 2];
          var bSpan = axis === 'x' ? Math.max(18, measureTextPx(String(beforePrev.label != null ? beforePrev.label : beforePrev.value), fontSpec)) : lineH;
          if ((lo - (Number(beforePrev.pos || 0) + bSpan * 0.5)) >= gap && (lo - (Number(prev.pos || 0) + prevSpan * 0.5)) < gap) {
            kept[kept.length - 1] = tk;
            lastEnd = hi;
          }
        }
      }
    });
    return kept;
  }

  function placeReferenceLabel(docOrSvg, opts) {
    var cfg = opts || {}, svgNS = 'http://www.w3.org/2000/svg', text = String(cfg.text || '');
    var doc = (docOrSvg && docOrSvg.ownerDocument) ? docOrSvg.ownerDocument : (typeof document !== 'undefined' ? document : null);
    var plotX0 = Number(cfg.plotX0 != null ? cfg.plotX0 : 0), plotX1 = Number(cfg.plotX1 != null ? cfg.plotX1 : 600);
    var plotY0 = Number(cfg.plotY0 != null ? cfg.plotY0 : 0), plotY1 = Number(cfg.plotY1 != null ? cfg.plotY1 : 260);
    var fontSpec = cfg.font || '600 11px JetBrains Mono, monospace';
    var estW = Math.ceil(measureTextPx(text, fontSpec));
    var x = Number(cfg.x != null ? cfg.x : (plotX1 - 8));
    var y = Number(cfg.y != null ? cfg.y : (plotY0 + 14));
    var anchor = cfg.anchor || (x > (plotX0 + plotX1) * 0.6 ? 'end' : (x < (plotX0 + plotX1) * 0.4 ? 'start' : 'middle'));
    var padX = 6;
    if (anchor === 'start') {
      var minS = plotX0 + padX, maxS = Math.max(minS, plotX1 - estW - padX);
      x = Math.max(minS, Math.min(maxS, x));
    } else if (anchor === 'end') {
      var minE = Math.min(plotX1 - padX, plotX0 + estW + padX), maxE = Math.max(minE, plotX1 - padX);
      x = Math.max(minE, Math.min(maxE, x));
    } else {
      var midLo = Math.min(plotX1 - padX, plotX0 + estW * 0.5 + padX), midHi = Math.max(midLo, plotX1 - estW * 0.5 - padX);
      x = Math.max(midLo, Math.min(midHi, x));
    }
    var yLo = plotY0 + 13, yHi = Math.max(yLo, plotY1 - 6);
    y = Math.max(yLo, Math.min(yHi, y));
    var haloColor = cfg.haloColor || 'var(--bg-surface, #FFFFFF)';
    var fillColor = cfg.fill || 'var(--text-secondary, #334155)';
    if (!doc || typeof doc.createElementNS !== 'function') {
      return { x: x, y: y, anchor: anchor, text: text, estWidth: estW };
    }
    var setAttrs = function (el, map) { Object.keys(map).forEach(function (k) { el.setAttribute(k, String(map[k])); }); return el; };
    var g = setAttrs(doc.createElementNS(svgNS, 'g'), { 'data-role': 'ref-label' });
    var rx = anchor === 'start' ? x - 4 : (anchor === 'end' ? x - estW - 4 : x - estW * 0.5 - 4);
    g.appendChild(setAttrs(doc.createElementNS(svgNS, 'rect'), { x: rx.toFixed(1), y: (y - 11.5).toFixed(1), width: (estW + 8).toFixed(1), height: 15, rx: 2, fill: haloColor, 'fill-opacity': 0.94, stroke: 'none' }));
    var txt = setAttrs(doc.createElementNS(svgNS, 'text'), { x: x.toFixed(1), y: y.toFixed(1), 'text-anchor': anchor, 'font-family': cfg.fontFamily || 'var(--font-mono, ui-monospace)', 'font-size': cfg.fontSize || 11, 'font-weight': cfg.fontWeight || 600, fill: fillColor, stroke: haloColor, 'stroke-width': 3.2, 'stroke-linejoin': 'round', 'paint-order': 'stroke fill' });
    txt.textContent = text;
    g.appendChild(txt);
    if (docOrSvg && docOrSvg.nodeType === 1) docOrSvg.appendChild(g);
    return g;
  }

  function toEpochMs(val) {
    if (typeof val === 'number') return Number.isFinite(val) ? val : NaN;
    if (val instanceof Date) return val.getTime();
    if (typeof val === 'string' && val.trim() !== '') {
      var trimmed = val.trim();
      return /^-?\d+(?:\.\d+)?$/.test(trimmed) ? Number(trimmed) : Date.parse(trimmed);
    }
    return NaN;
  }

  function buildCanonicalTimeGrid(startMs, endMs, stepMs, opts) {
    var s = toEpochMs(startMs);
    var e = toEpochMs(endMs);
    var step = Number(stepMs);
    if (!Number.isFinite(s) || !Number.isFinite(e) || !Number.isFinite(step) || step <= 0 || e < s) {
      return [];
    }
    var cfg = opts || {};
    if (cfg.align) s = Math.floor(s / step) * step;
    var maxBuckets = Math.max(1, Math.min(10000, Number(cfg.maxBuckets || 5000)));
    var intStep = Number.isInteger(s) && Number.isInteger(step);
    var out = [];
    for (var i = 0; i < maxBuckets; i += 1) {
      var cur = s + i * step;
      if (cur > e + step * 1e-6) break;
      out.push(intStep ? Math.round(cur) : roundClean(cur));
    }
    return out;
  }

  function extractNumericValues(node, out, depth) {
    var d = depth || 0;
    if (node == null || typeof node === 'boolean') return;
    if (typeof node === 'number') {
      if (Number.isFinite(node)) out.push(node);
      return;
    }
    if (Array.isArray(node)) {
      if (d >= 2 && node.length === 2 && (node[0] == null || typeof node[0] !== 'object') && (node[1] == null || typeof node[1] !== 'object')) {
        if (node[1] !== null && node[1] !== undefined && node[1] !== '' && typeof node[1] !== 'boolean') {
          var yPair = Number(node[1]);
          if (Number.isFinite(yPair)) out.push(yPair);
        }
        return;
      }
      for (var i = 0; i < node.length; i += 1) extractNumericValues(node[i], out, d + 1);
      return;
    }
    if (typeof node === 'object') {
      if (Array.isArray(node.data)) extractNumericValues(node.data, out, 1);
      else if (node.value !== undefined && node.value !== null && typeof node.value !== 'boolean') {
        if (Array.isArray(node.value)) extractNumericValues(node.value, out, 2);
        else {
          var vObj = Number(node.value);
          if (Number.isFinite(vObj)) out.push(vObj);
        }
      }
    }
  }

  function sharedNiceScale125(seriesArrays, opts) {
    var vals = [];
    extractNumericValues(seriesArrays, vals, 0);
    var cfg = Object.assign({}, opts || {});
    if (!vals.length) return niceScale125(0, 1, cfg);
    var lo = Math.min.apply(null, vals);
    var hi = Math.max.apply(null, vals);
    if (cfg.includeZero === undefined) cfg.includeZero = lo >= 0;
    if (cfg.headroomRatio) {
      var span = hi - lo;
      hi += (span > 0 ? span : (Math.abs(hi) || 1)) * Number(cfg.headroomRatio);
    }
    return niceScale125(lo, hi, cfg);
  }

  function maxLabelWidthPx(labels, fontSpec) {
    var list = Array.isArray(labels) ? labels : [];
    var isMono = String(fontSpec || '').toLowerCase().indexOf('mono') >= 0 || isMonoLabelSet(list);
    var fSize = Number(((String(fontSpec || '').match(/(\d+(?:\.\d+)?)px/i) || [])[1]) || (isMono ? 12 : 11));
    var w = 0;
    for (var i = 0; i < list.length; i += 1) {
      var lines = String(list[i] == null ? '' : list[i]).split('\n');
      for (var j = 0; j < lines.length; j += 1) {
        var measured = measureTextPx(lines[j], fontSpec);
        if (isMono || _WIDE_RE.test(lines[j])) measured = Math.max(measured, visualUnits(lines[j]) * fSize * 0.64);
        w = Math.max(w, measured);
      }
    }
    return Math.ceil(w);
  }

  function measureCellGutters(cell, cfg) {
    var tickFont = cell.tickFont || cfg.tickFont || '11px JetBrains Mono, monospace';
    var yTicks = cell.yTicks || cell.leftTicks || cell.ticks || [], rTicks = cell.rightTicks || [];
    var hasRight = !!(cell.hasRightAxis || rTicks.length || cell.rightTitle);
    var leftW = Math.max(cell.minLeft || cfg.minLeft || 44, (yTicks.length ? maxLabelWidthPx(yTicks, tickFont) + 12 : 44) + (cell.yLabel || cell.leftTitle ? 18 : 0));
    var rightW = Math.max(cell.minRight || cfg.minRight || (hasRight ? 48 : 16), hasRight ? maxLabelWidthPx(rTicks, tickFont) + 14 + (cell.rightTitle ? 18 : 0) : 16);
    var topH = Math.max(cell.minTop || cfg.minTop || 20, (cell.titleHeight || 0) + (cell.topLegendHeight || (cell.hasTopLegend ? 28 : 0)) + (cell.hasTopYName ? 26 : 16));
    var botH = Math.max(cell.minBottom || cfg.minBottom || 34, (cell.xTicks && cell.xTicks.length ? 22 : 14) + (cell.xLabel || cell.bottomTitle ? 18 : 0) + (cell.bottomLegendHeight || (cell.hasBottomLegend ? 30 : 0)));
    return {
      left: Math.min(cfg.maxLeft || 224, leftW), right: Math.min(cfg.maxRight || 160, rightW),
      top: topH, bottom: botH, padX: Number(cell.containerPadX || 0), stageHeight: Number(cell.stageHeight || 0),
    };
  }

  function computeGridFrameGutters(plotsMatrix, opts) {
    var cfg = opts || {}, mat = [];
    if (Array.isArray(plotsMatrix) && plotsMatrix.length) {
      if (Array.isArray(plotsMatrix[0])) mat = plotsMatrix;
      else if (cfg.orientation === 'row') mat = [plotsMatrix];
      else mat = plotsMatrix.map(function (p) { return [p]; });
    }
    var rows = mat.length, cols = mat.reduce(function (m, row) { return Math.max(m, Array.isArray(row) ? row.length : 0); }, 0);
    var colLeft = [], colRight = [], colPadX = [], rowTop = [], rowBottom = [], rowStageH = [], r, c, raw = [];
    for (c = 0; c < cols; c += 1) { colLeft[c] = 0; colRight[c] = 0; colPadX[c] = 0; }
    for (r = 0; r < rows; r += 1) {
      rowTop[r] = 0; rowBottom[r] = 0; rowStageH[r] = 0; raw[r] = [];
      var row = Array.isArray(mat[r]) ? mat[r] : [];
      for (c = 0; c < row.length; c += 1) {
        if (!row[c]) { raw[r][c] = null; continue; }
        var g = measureCellGutters(row[c], cfg);
        raw[r][c] = g;
        colLeft[c] = Math.max(colLeft[c], g.left); colRight[c] = Math.max(colRight[c], g.right); colPadX[c] = Math.max(colPadX[c], g.padX);
        rowTop[r] = Math.max(rowTop[r], g.top); rowBottom[r] = Math.max(rowBottom[r], g.bottom); rowStageH[r] = Math.max(rowStageH[r], g.stageHeight);
      }
    }
    var cells = [];
    for (r = 0; r < rows; r += 1) {
      cells[r] = [];
      for (c = 0; c < cols; c += 1) {
        if (!raw[r] || !raw[r][c]) { cells[r][c] = null; continue; }
        cells[r][c] = { row: r, col: c, left: colLeft[c], right: colRight[c], top: rowTop[r], bottom: rowBottom[r], padX: colPadX[c], stageHeight: rowStageH[r], containLabel: false };
      }
    }
    return { rows: rows, cols: cols, colLeft: colLeft, colRight: colRight, colPadX: colPadX, rowTop: rowTop, rowBottom: rowBottom, rowStageHeight: rowStageH, cells: cells };
  }

  var api = {
    visualUnits: visualUnits, niceScale125: niceScale125, formatTick: formatTick, wrapLabelLines: wrapLabelLines,
    measureCategoryGutter: measureCategoryGutter, filterNonOverlappingTicks: filterNonOverlappingTicks,
    placeReferenceLabel: placeReferenceLabel, buildCanonicalTimeGrid: buildCanonicalTimeGrid,
    sharedNiceScale125: sharedNiceScale125, computeGridFrameGutters: computeGridFrameGutters,
  };
  root.QuietSvgLayout = api;
  if (typeof module === 'object' && module.exports) module.exports = api;
}(typeof window !== 'undefined' ? window : globalThis));


// SPDX-License-Identifier: Apache-2.0
(function (root) {
  'use strict';

  function parseUtcMs(raw) {
    if (typeof raw === 'number') return Number.isFinite(raw) ? raw : NaN;
    if (raw instanceof Date) return raw.getTime();
    if (typeof raw !== 'string') return NaN;
    var s = raw.trim();
    if (!s) return NaN;
    if (/^-?\d+(?:\.\d+)?$/.test(s)) {
      var num = Number(s);
      return Number.isFinite(num) ? num : NaN;
    }
    var m = s.match(/^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2})(?::(\d{2})(?::(\d{2}))?)?)?$/);
    if (m) {
      var yr = Number(m[1]), mo = Number(m[2]), dy = Number(m[3]), hh = Number(m[4] || 0), mi = Number(m[5] || 0), ss = Number(m[6] || 0);
      var ms = Date.UTC(yr, mo - 1, dy, hh, mi, ss), dt = new Date(ms);
      return (dt.getUTCFullYear() === yr && dt.getUTCMonth() === mo - 1 && dt.getUTCDate() === dy &&
        dt.getUTCHours() === hh && dt.getUTCMinutes() === mi && dt.getUTCSeconds() === ss) ? ms : NaN;
    }
    var w = s.match(/^(\d{4})-W(\d{2})$/);
    if (w) {
      var wk = Number(w[2]);
      if (wk < 1 || wk > 53) return NaN;
      var j4 = new Date(Date.UTC(Number(w[1]), 0, 4)), d4 = j4.getUTCDay() || 7;
      return j4.getTime() + ((wk - 1) * 7 + (1 - d4)) * 86400000;
    }
    var ts = Date.parse(s);
    return Number.isFinite(ts) ? ts : NaN;
  }

  function pad2(n) { return n < 10 ? '0' + n : String(n); }

  function utcBucketInfo(ms, bin, cfg) {
    var dt = new Date(ms), y = dt.getUTCFullYear(), mo = pad2(dt.getUTCMonth() + 1), d = pad2(dt.getUTCDate());
    if (bin === '1h') return { sortMs: Date.UTC(y, dt.getUTCMonth(), dt.getUTCDate(), dt.getUTCHours()), key: y + '-' + mo + '-' + d + ' ' + pad2(dt.getUTCHours()) + ':00' };
    if (bin === '1d') return { sortMs: Date.UTC(y, dt.getUTCMonth(), dt.getUTCDate()), key: y + '-' + mo + '-' + d };
    var mon = new Date(Date.UTC(y, dt.getUTCMonth(), dt.getUTCDate())), day = mon.getUTCDay() || 7;
    var monMs = mon.getTime() + (1 - day) * 86400000;
    if (cfg && cfg.weekFormat === 'monday') {
      var md = new Date(monMs);
      return { sortMs: monMs, key: md.getUTCFullYear() + '-' + pad2(md.getUTCMonth() + 1) + '-' + pad2(md.getUTCDate()) };
    }
    var thu = new Date(mon.getTime() + (4 - day) * 86400000);
    var wk = Math.ceil(((thu.getTime() - Date.UTC(thu.getUTCFullYear(), 0, 1)) / 86400000 + 1) / 7);
    return { sortMs: monMs, key: thu.getUTCFullYear() + '-W' + pad2(wk) };
  }

  /** Deterministically bin hourly/daily UTC series into 1h (<=3d), 1d (4-92d), or ISO 1w (>92d) sums. */
  function binTimeSeries(dates, layersObj, opts) {
    var cfg = opts || {}, rawDates = Array.isArray(dates) ? dates : [], srcLayers = layersObj && typeof layersObj === 'object' ? layersObj : {};
    var names = Object.keys(srcLayers), parsed = [], minTs = Infinity, maxTs = -Infinity;
    for (var i = 0; i < rawDates.length; i += 1) {
      var ms = parseUtcMs(rawDates[i]);
      if (!Number.isFinite(ms)) continue;
      parsed.push({ idx: i, ms: ms });
      if (ms < minTs) minTs = ms;
      if (ms > maxTs) maxTs = ms;
    }
    if (!parsed.length) {
      var emptyL = {};
      names.forEach(function (nm) { emptyL[nm] = []; });
      return { dates: [], layers: emptyL, bin: cfg.bin || '1h', spanDays: 0 };
    }
    var spanDays = Math.max(0, (maxTs - minTs) / 86400000);
    var hLim = cfg.hourlyMaxDays != null ? Number(cfg.hourlyMaxDays) : 3, dLim = cfg.dailyMaxDays != null ? Number(cfg.dailyMaxDays) : 92;
    var bin = cfg.bin || (spanDays <= hLim ? '1h' : (spanDays <= dLim ? '1d' : '1w')), buckets = Object.create(null);
    parsed.forEach(function (pt) {
      var info = utcBucketInfo(pt.ms, bin, cfg);
      if (!buckets[info.key]) {
        var initVals = Object.create(null);
        names.forEach(function (nm) { initVals[nm] = 0; });
        buckets[info.key] = { key: info.key, sortMs: info.sortMs, vals: initVals };
      }
      var b = buckets[info.key];
      names.forEach(function (nm) {
        var arr = srcLayers[nm], v = Array.isArray(arr) ? Number(arr[pt.idx]) : 0;
        if (Number.isFinite(v)) b.vals[nm] += v;
      });
    });
    var ordered = Object.keys(buckets).map(function (k) { return buckets[k]; }).sort(function (a, b) { return a.sortMs - b.sortMs; });
    var outDates = ordered.map(function (b) { return b.key; }), outLayers = Object.create(null);
    names.forEach(function (nm) { outLayers[nm] = ordered.map(function (b) { return Math.round(b.vals[nm] * 1e9) / 1e9; }); });
    return { dates: outDates, layers: outLayers, bin: bin, spanDays: Math.round(spanDays * 100) / 100 };
  }

  function resolveCssColor(raw, doc) {
    var s = String(raw || '').trim();
    var targetDoc = doc || root.document || null;
    for (var depth = 0; depth < 4 && /^var\(/i.test(s); depth += 1) {
      var inner = s.slice(4, -1), comma = inner.indexOf(',');
      var tok = (comma >= 0 ? inner.slice(0, comma) : inner).trim();
      var fb = comma >= 0 ? inner.slice(comma + 1).trim() : '';
      var val = '';
      var csHost = (targetDoc && targetDoc.defaultView && typeof targetDoc.defaultView.getComputedStyle === 'function')
        ? targetDoc.defaultView
        : (typeof root.getComputedStyle === 'function' ? root : null);
      if (targetDoc && targetDoc.documentElement && csHost) {
        try { val = csHost.getComputedStyle(targetDoc.documentElement).getPropertyValue(tok).trim(); } catch (_err) {}
      }
      s = val || fb;
      if (!s) break;
    }
    return s;
  }

  function parseCssRgb(str, doc) {
    var s = resolveCssColor(str, doc);
    var m3 = s.match(/^#([0-9a-f]{3})$/i);
    if (m3) {
      var h3 = m3[1];
      return [parseInt(h3[0] + h3[0], 16), parseInt(h3[1] + h3[1], 16), parseInt(h3[2] + h3[2], 16)];
    }
    var m = s.match(/^#([0-9a-f]{6})$/i);
    if (m) return [parseInt(m[1].slice(0, 2), 16), parseInt(m[1].slice(2, 4), 16), parseInt(m[1].slice(4, 6), 16)];
    var r = s.match(/^rgba?\(\s*(\d+)\s*[,\s]+(\d+)\s*[,\s]+(\d+)/i);
    if (r) return [Number(r[1]), Number(r[2]), Number(r[3])];
    var ok = s.match(/^okl(?:ch|ab)\(\s*([0-9.]+)(%?)/i);
    if (ok) {
      var lRaw = parseFloat(ok[1]), lNorm = ok[2] === '%' ? (lRaw / 100) : lRaw;
      var g = Math.max(0, Math.min(255, Math.round(Math.pow(Math.max(0, Math.min(1, lNorm)), 1.5) * 255)));
      return [g, g, g];
    }
    return null;
  }

  function relLum(rgb) {
    if (!rgb) return 1;
    var f = function (c) { var s = c / 255; return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4); };
    return 0.2126 * f(rgb[0]) + 0.7152 * f(rgb[1]) + 0.0722 * f(rgb[2]);
  }

  function isValidCellForCol(c) {
    return Array.isArray(c) && c[0] != null && c[0] !== '' && Number.isFinite(Number(c[0]));
  }

  /** Trim trailing week columns whose cells lie strictly in the future and provide zero-cell contrast styling. */
  function trimTrailingFutureWeeks(weeks, cells, opts) {
    var wkList = Array.isArray(weeks) ? weeks.slice() : [], cellList = Array.isArray(cells) ? cells.filter(isValidCellForCol) : [];
    var cfg = opts || {};
    var todayMs = cfg.today != null ? parseUtcMs(cfg.today) : Date.now();
    var cutoff = Number.isFinite(todayMs) ? todayMs : Date.now();
    var endCol = wkList.length;
    while (endCol > 0) {
      var wkMs = parseUtcMs(wkList[endCol - 1]);
      var colHasData = cellList.some(function (c) {
        if (Number(c[0]) !== endCol - 1 || c.future || c[2] == null) return false;
        var v = Number(c[2]);
        return Number.isFinite(v) && v !== 0;
      });
      if ((Number.isFinite(wkMs) && wkMs > cutoff) || (!colHasData && cfg.dropEmptyTrailing)) endCol -= 1;
      else break;
    }
    return {
      weeks: wkList.slice(0, endCol),
      cells: cellList.filter(function (c) { var col = Number(c[0]); return col >= 0 && col < endCol; }),
    };
  }

  function heatmapZeroCellStyle(cardBg, borderHairline, docOrOpts) {
    var doc = docOrOpts && docOrOpts.documentElement ? docOrOpts : (docOrOpts && docOrOpts.document ? docOrOpts.document : root.document);
    var bgResolved = resolveCssColor(cardBg, doc);
    var lum = relLum(parseCssRgb(bgResolved, doc) || [255, 255, 255]);
    var isDark = lum < 0.2;
    var fill = isDark ? '#435266' : '#E2E8F0';
    var bdRaw = resolveCssColor(borderHairline, doc);
    var bd = bdRaw && bdRaw.toLowerCase() !== fill.toLowerCase() ? bdRaw : (isDark ? '#64748B' : '#CBD5E1');
    if (isDark && bd.toLowerCase() === '#1e293b') bd = '#64748B';
    return {
      fill: fill,
      borderColor: bd,
      borderWidth: 1,
      labelColor: isDark ? '#F1F5F9' : '#0F172A',
      minDeltaLuminance: 0.06,
    };
  }

  var DAY_MS = 86400000;
  var ROLLING_SPECS = Object.assign(Object.create(null), { '7d': ['7 days', 7], r7: ['7 days', 7], r7d: ['7 days', 7], '14d': ['14 days', 14], r14: ['14 days', 14], r14d: ['14 days', 14], '30d': ['30 days', 30], r30: ['30 days', 30], r30d: ['30 days', 30], '90d': ['90 days', 90], r90: ['90 days', 90], r90d: ['90 days', 90], '52w': ['52 weeks', 364], r52w: ['52 weeks', 364] });
  var CAL_LABELS = Object.assign(Object.create(null), { wtd: 'WTD', '2w-cal': '2W-Cal', '2w_cal': '2W-Cal', mtd: 'MTD', qtd: 'QTD', ytd: 'YTD', all: 'All Scanned', all_scanned: 'All Scanned' });
  var ROLL_TO_CAL = Object.assign(Object.create(null), { '7d': 'wtd', r7: 'wtd', r7d: 'wtd', '14d': '2w-cal', r14: '2w-cal', r14d: '2w-cal', '30d': 'mtd', r30: 'mtd', r30d: 'mtd', '90d': 'qtd', r90: 'qtd', r90d: 'qtd', '52w': 'ytd', r52w: 'ytd' });
  var CAL_TO_ROLL = Object.assign(Object.create(null), { wtd: '7d', '2w-cal': '14d', '2w_cal': '14d', mtd: '30d', qtd: '90d', ytd: '52w', all: '52w', all_scanned: '52w' });

  function toUtcDayMs(raw) {
    var ms = parseUtcMs(raw);
    if (!Number.isFinite(ms)) return NaN;
    var d = new Date(ms);
    return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  }

  function fmtUtcDay(ms) {
    var d = new Date(ms);
    return d.getUTCFullYear() + '-' + pad2(d.getUTCMonth() + 1) + '-' + pad2(d.getUTCDate());
  }

  function normMode(mode, preset) {
    var m = String(mode || '').toLowerCase();
    if (m === 'cal' || m === 'calendar' || m === 'cal-to-date') return 'cal';
    if (m === 'rolling') return 'rolling';
    return CAL_LABELS[String(preset || '').toLowerCase()] ? 'cal' : 'rolling';
  }

  function mapPresetForMode(preset, mode) {
    var p = String(preset || '30d').toLowerCase(), md = normMode(mode, p);
    if (md === 'cal') return CAL_LABELS[p] ? p : (ROLL_TO_CAL[p] || 'mtd');
    return ROLLING_SPECS[p] ? p : (CAL_TO_ROLL[p] || '30d');
  }

  function formatPresetLabel(preset, mode) {
    var p = mapPresetForMode(preset, mode), md = normMode(mode, p);
    return md === 'cal' ? (CAL_LABELS[p] || 'MTD') : (ROLLING_SPECS[p] ? ROLLING_SPECS[p][0] : '30 days');
  }

  function calStartMs(endMs, preset) {
    var d = new Date(endMs), y = d.getUTCFullYear(), mo = d.getUTCMonth();
    if (preset === 'wtd' || preset === '2w-cal' || preset === '2w_cal') {
      var monMs = endMs - ((d.getUTCDay() || 7) - 1) * DAY_MS;
      return preset === 'wtd' ? monMs : (monMs - 7 * DAY_MS);
    }
    if (preset === 'mtd') return Date.UTC(y, mo, 1);
    if (preset === 'qtd') return Date.UTC(y, Math.floor(mo / 3) * 3, 1);
    return Date.UTC(y, 0, 1);
  }

  /** Clamp lookback start & anchor end to {minDate, maxDate} and switch Rolling/Cal-to-Date labels cleanly. */
  function resolvePeriodBounds(opts) {
    var cfg = opts || {}, mode = normMode(cfg.mode, cfg.preset), preset = mapPresetForMode(cfg.preset || (mode === 'cal' ? 'mtd' : '30d'), mode);
    var todayMs = toUtcDayMs(cfg.today);
    if (!Number.isFinite(todayMs)) todayMs = toUtcDayMs(Date.now());
    var minMs = toUtcDayMs(cfg.minDate), maxMs = toUtcDayMs(cfg.maxDate);
    if (Number.isFinite(minMs) && Number.isFinite(maxMs) && minMs > maxMs) { var sw = minMs; minMs = maxMs; maxMs = sw; }
    var rawAnchor = toUtcDayMs(cfg.anchorDate);
    var endMs = Number.isFinite(rawAnchor) ? rawAnchor : (Number.isFinite(maxMs) ? maxMs : todayMs);
    var step = Number(cfg.stepDelta || 0);
    var stepSpan = mode === 'rolling' ? (ROLLING_SPECS[preset] ? ROLLING_SPECS[preset][1] : 30) : (preset === 'wtd' ? 7 : 14);
    if (step && preset !== 'all' && preset !== 'all_scanned') {
      var curStart = mode === 'rolling' ? (endMs - (stepSpan - 1) * DAY_MS) : calStartMs(endMs, preset);
      if (!(step < 0 && Number.isFinite(minMs) && curStart <= minMs)) {
        if (mode === 'cal' && preset === 'mtd') {
          var edm = new Date(endMs);
          endMs = Date.UTC(edm.getUTCFullYear(), edm.getUTCMonth() + step + 1, 0);
        } else if (mode === 'cal' && preset === 'qtd') {
          var edq = new Date(endMs);
          endMs = Date.UTC(edq.getUTCFullYear(), (Math.floor(edq.getUTCMonth() / 3) + step + 1) * 3, 0);
        } else if (mode === 'cal' && preset === 'ytd') {
          var edy = new Date(endMs);
          endMs = Date.UTC(edy.getUTCFullYear() + step, 11, 31);
        } else if (mode === 'cal' && step < 0) {
          endMs = curStart + (step + 1) * stepSpan * DAY_MS - DAY_MS;
        } else {
          endMs += step * stepSpan * DAY_MS;
        }
      }
    }
    if (Number.isFinite(maxMs) && endMs > maxMs) endMs = maxMs;
    if (Number.isFinite(minMs) && endMs < minMs) endMs = minMs;
    var rawStart = (preset === 'all' || preset === 'all_scanned') ? (Number.isFinite(minMs) ? minMs : endMs)
      : (mode === 'rolling' ? (endMs - (ROLLING_SPECS[preset][1] - 1) * DAY_MS) : calStartMs(endMs, preset));
    var startMs = (Number.isFinite(minMs) && rawStart < minMs) ? minMs : rawStart;
    if (startMs > endMs) startMs = endMs;
    var isCapped = Number.isFinite(maxMs) && Number.isFinite(todayMs) && maxMs < todayMs;
    var effMax = Number.isFinite(maxMs) ? maxMs : todayMs;
    return {
      mode: mode, preset: preset, label: formatPresetLabel(preset, mode),
      startDate: fmtUtcDay(startMs), endDate: fmtUtcDay(endMs),
      spanDays: Math.max(1, Math.round((endMs - startMs) / DAY_MS) + 1),
      anchorLabel: isCapped ? 'Latest Scanned' : 'Today', isCorpusCapped: isCapped,
      atLatest: endMs >= effMax, canStepPrev: !Number.isFinite(minMs) || startMs > minMs, canStepNext: endMs < effMax,
    };
  }

  var api = {
    parseUtcMs: parseUtcMs,
    binTimeSeries: binTimeSeries,
    trimTrailingFutureWeeks: trimTrailingFutureWeeks,
    resolveCssColor: resolveCssColor,
    heatmapZeroCellStyle: heatmapZeroCellStyle,
    mapPresetForMode: mapPresetForMode,
    formatPresetLabel: formatPresetLabel,
    resolvePeriodBounds: resolvePeriodBounds,
  };
  root.QuietTimeBinning = api;
  if (typeof module === 'object' && module.exports) module.exports = api;
}(typeof window !== 'undefined' ? window : globalThis));


// SPDX-License-Identifier: Apache-2.0
(function (root) {
  'use strict';

  function ensureGridContainLabel(opt) {
    if (!opt) return opt;
    if (Array.isArray(opt.grid)) opt.grid = opt.grid.map(function (g) { return Object.assign({ containLabel: true }, g || {}); });
    else if (opt.grid && typeof opt.grid === 'object') opt.grid = Object.assign({ containLabel: true }, opt.grid);
    return opt;
  }

  function applyNiceLinearAxisBounds(opt, payload) {
    if (!opt || !payload || !root.QuietSvgLayout || (payload.y && (payload.y.log || payload.y.logMapped))) return opt;
    var yAxes = Array.isArray(opt.yAxis) ? opt.yAxis : (opt.yAxis ? [opt.yAxis] : []);
    if (!yAxes[0] || yAxes[0].type !== 'value' || yAxes[0].max !== undefined) return opt;
    var vals = [];
    (payload.series || []).forEach(function (sr) {
      (sr.data || []).forEach(function (pt) {
        var raw = Array.isArray(pt) ? pt[1] : (pt && typeof pt === 'object' ? pt.value : pt);
        if (raw !== null && raw !== undefined && raw !== '' && typeof raw !== 'boolean' && Number.isFinite(Number(raw))) vals.push(Number(raw));
      });
    });
    (payload.envelopes || []).forEach(function (env) { if (typeof env.value === 'number' && Number.isFinite(env.value)) vals.push(env.value); });
    if (vals.length) {
      var rawMin = Math.min.apply(null, vals), rawMax = Math.max.apply(null, vals);
      var lo = yAxes[0].min !== undefined ? Number(yAxes[0].min) : rawMin, span = rawMax - rawMin;
      var hi = rawMax + (span > 0 ? span * 0.06 : (Math.abs(rawMax) * 0.06 || 1));
      var sc = root.QuietSvgLayout.niceScale125(lo, hi, { targetTicks: 5, includeZero: lo >= 0 });
      if (yAxes[0].min === undefined) yAxes[0].min = sc.min;
      yAxes[0].max = sc.max;
      if (yAxes[0].interval === undefined) yAxes[0].interval = sc.step;
    }
    return opt;
  }

  function applySafeMarkLines(opt, tokens) {
    if (!opt || !Array.isArray(opt.series)) return opt;
    var haloBg = (tokens && tokens.bgSurface) ? tokens.bgSurface : '#FFFFFF';
    opt.series.forEach(function (sr) {
      if (!sr || !sr.markLine || !Array.isArray(sr.markLine.data)) return;
      var parentLbl = sr.markLine.label || {};
      sr.markLine.data = sr.markLine.data.map(function (entry) {
        if (!entry || typeof entry !== 'object' || entry.xAxis !== undefined || (parentLbl.position && !(entry.label && entry.label.position))) return entry;
        var lbl = Object.assign({}, entry.label || {}), rawTxt = String(lbl.formatter || entry.name || '').toLowerCase();
        if (!lbl.position) lbl.position = rawTxt.indexOf('floor') >= 0 ? 'insideStartBottom' : 'insideEndTop';
        if (lbl.distance === undefined) lbl.distance = 4;
        if (!lbl.fontSize || lbl.fontSize < 11) lbl.fontSize = 11;
        if (!lbl.backgroundColor) lbl.backgroundColor = haloBg;
        if (!lbl.padding) lbl.padding = [2, 5];
        if (!lbl.borderRadius) lbl.borderRadius = 2;
        return Object.assign({}, entry, { label: lbl });
      });
    });
    return opt;
  }

  function applySafeLegendLayout(opt, containerWidth) {
    if (!opt || !opt.legend) return opt;
    var yAxes = Array.isArray(opt.yAxis) ? opt.yAxis : (opt.yAxis ? [opt.yAxis] : []);
    var baseGridIdx = (yAxes[0] && yAxes[0].gridIndex) || 0;
    var hasRightYAxis = yAxes.length > 1 && yAxes.some(function (ax, idx) {
      return !!ax && (ax.position === 'right' || (idx > 0 && (ax.gridIndex === undefined || ax.gridIndex === baseGridIdx)));
    });
    var w = Number(containerWidth || 0), isNarrow = w > 0 && w < 640;
    var legends = Array.isArray(opt.legend) ? opt.legend : [opt.legend];
    var needBottomPad = false, maxItems = 0;
    legends.forEach(function (lg) {
      if (!lg || typeof lg !== 'object' || lg.show === false) return;
      maxItems = Math.max(maxItems, Array.isArray(lg.data) ? lg.data.length : (Array.isArray(opt.series) ? opt.series.length : 0));
      var isScroll = lg.type === 'scroll', optInScroll = !!(lg.quietAllowScroll || lg.allowScroll);
      if (isScroll && (isNarrow || !optInScroll)) {
        lg.type = 'plain';
        if (lg.orient === 'vertical') lg.orient = 'horizontal';
        delete lg.top; lg.bottom = 0; lg.left = 'center'; delete lg.right;
        if (lg.itemGap == null) lg.itemGap = 10;
        needBottomPad = true;
      } else if (hasRightYAxis && lg.bottom == null) {
        if (lg.orient === 'vertical') lg.orient = 'horizontal';
        delete lg.top; lg.bottom = 0;
        if (lg.left == null || lg.left === 'right' || typeof lg.left === 'number') { lg.left = 'center'; delete lg.right; }
        needBottomPad = true;
      } else if (hasRightYAxis && lg.bottom != null) { needBottomPad = true; }
    });
    if (needBottomPad) {
      var minBot = (isNarrow && maxItems >= 3) ? 46 : 38;
      if (Array.isArray(opt.grid) && opt.grid.length) {
        var gi = opt.grid.length - 1;
        if (opt.grid[gi] && typeof opt.grid[gi] === 'object') opt.grid[gi] = Object.assign({ containLabel: true }, opt.grid[gi], { bottom: Math.max(Number(opt.grid[gi].bottom) || 0, minBot) });
      } else if (opt.grid && typeof opt.grid === 'object') {
        opt.grid = Object.assign({ containLabel: true }, opt.grid, { bottom: Math.max(Number(opt.grid.bottom) || 0, minBot) });
      } else opt.grid = { containLabel: true, bottom: minBot };
    }
    return opt;
  }

  function normalizeOption(opt, payload, tokens, containerWidth) {
    if (!opt) return opt;
    ensureGridContainLabel(opt);
    applySafeMarkLines(opt, tokens);
    applySafeLegendLayout(opt, containerWidth);
    if (payload && (payload.kind === 'cartesian' || !payload.kind)) applyNiceLinearAxisBounds(opt, payload);
    return opt;
  }

  function getTimeBinning() {
    if (root.QuietTimeBinning) return root.QuietTimeBinning;
    if (typeof require === 'function') { try { return require('./quiet-time-binning.js'); } catch (_err) {} }
    return null;
  }

  function parseUtcMs(raw) {
    var tb = getTimeBinning();
    if (tb && tb.parseUtcMs) return tb.parseUtcMs(raw);
    if (typeof raw === 'number') return Number.isFinite(raw) ? raw : NaN;
    var ts = Date.parse(String(raw || ''));
    return Number.isFinite(ts) ? ts : NaN;
  }

  function binTimeSeries(dates, layersObj, opts) {
    var tb = getTimeBinning();
    return tb ? tb.binTimeSeries(dates, layersObj, opts) : { dates: dates || [], layers: layersObj || {}, bin: '1h', spanDays: 0 };
  }

  function getSvgLayout() {
    if (root.QuietSvgLayout) return root.QuietSvgLayout;
    if (typeof require === 'function') { try { return require('./quiet-svg-chart-layout.js'); } catch (_err) {} }
    return null;
  }

  function toMatrix(matrixOrList, opts) {
    if (!Array.isArray(matrixOrList) || !matrixOrList.length) return [];
    if (Array.isArray(matrixOrList[0])) return matrixOrList;
    return (opts && opts.orientation === 'row') ? [matrixOrList] : matrixOrList.map(function (opt) { return [opt]; });
  }

  function inferAxisUnit(opt, ax, optKey, axKey) {
    if (opt && opt[optKey]) return String(opt[optKey]).trim();
    if (ax && ax[axKey]) return String(ax[axKey]).trim();
    if (ax && ax.name) {
      var m = String(ax.name).match(/(?:\(([^)]+)\)|\/\s*([^\s/]+))\s*$/);
      if (m) return (m[1] || m[2]).trim();
    }
    return '__default__';
  }

  function classifyXFormat(arr) {
    var list = Array.isArray(arr) ? arr.filter(function (v) { return v !== null && v !== undefined && String(v).trim() !== ''; }) : [];
    if (!list.length) return 'empty';
    var counts = { iso_date: 0, iso_week: 0, clock_hour: 0, weekday: 0, cat: 0 };
    list.forEach(function (v) {
      var s = String(v).trim();
      if (/^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2})?/.test(s)) counts.iso_date += 1;
      else if (/^\d{4}-W\d{2}$/.test(s)) counts.iso_week += 1;
      else if (/^(?:\d{1,2}h|\d{1,2}:\d{2})$/i.test(s)) counts.clock_hour += 1;
      else if (/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)$/i.test(s)) counts.weekday += 1;
      else counts.cat += 1;
    });
    var best = 'cat', bestN = 0;
    Object.keys(counts).forEach(function (k) { if (counts[k] > bestN) { bestN = counts[k]; best = k; } });
    return best;
  }

  function syncColumnXSpans(mat, opts) {
    var cols = mat.reduce(function (m, r) { return Math.max(m, r.length); }, 0);
    var fillVal = opts && opts.fillValue !== undefined ? opts.fillValue : 0, forcedX = (opts && (opts.timeGrid || opts.xBuckets)) || null;
    for (var c = 0; c < cols; c += 1) {
      var groups = {};
      for (var r = 0; r < mat.length; r += 1) {
        var opt = mat[r] && mat[r][c], xAx = opt && (Array.isArray(opt.xAxis) ? opt.xAxis[0] : opt.xAxis);
        if (!xAx || opt.independentXSpan || xAx.quietIndependentSpan) continue;
        var evKey = opt.eventKey != null ? opt.eventKey : (opts && opts.eventKey != null ? opts.eventKey : '');
        var xKey = inferAxisUnit(opt, xAx, 'xUnit', 'quietUnit') + '|' + String(evKey) + '|' + String(xAx.type || 'category');
        if (!groups[xKey]) groups[xKey] = [];
        groups[xKey].push({ opt: opt, xAx: xAx });
      }
      Object.keys(groups).forEach(function (k) {
        var grp = groups[k];
        if (grp.length < 2 && !forcedX) return;
        var xType = grp[0].xAx.type || 'category';
        if (xType === 'category') {
          if (!forcedX && grp.length >= 2) {
            var fmts = Object.create(null);
            grp.forEach(function (entry) { var fm = classifyXFormat(entry.xAx.data); if (fm !== 'empty') fmts[fm] = true; });
            if (Object.keys(fmts).length > 1) { grp.forEach(function (entry) { entry.opt.independentXSpan = true; }); return; }
          }
          var seen = Object.create(null), union = forcedX ? forcedX.slice() : [];
          if (!forcedX) {
            grp.forEach(function (e) { (e.xAx.data || []).forEach(function (l) { var sk = String(l); if (!seen[sk]) { seen[sk] = true; union.push(l); } }); });
            if (union.length > 1 && union.every(function (v) { return typeof v === 'number' || /^\d{4}-\d{2}-\d{2}|^\d{4}-W\d{2}|^\d{1,2}:\d{2}/.test(String(v)); })) {
              union.sort(function (a, b) {
                if (typeof a === 'number' && typeof b === 'number') return a - b;
                var ta = parseUtcMs(String(a)), tb = parseUtcMs(String(b));
                return (Number.isFinite(ta) && Number.isFinite(tb)) ? ta - tb : String(a).localeCompare(String(b));
              });
            }
          }
          grp.forEach(function (entry) {
            var oldCats = Array.isArray(entry.xAx.data) ? entry.xAx.data : [];
            (entry.opt.series || []).forEach(function (sr) {
              if (!Array.isArray(sr.data)) return;
              var byCat = Object.create(null);
              sr.data.forEach(function (pt, idx) {
                if (Array.isArray(pt)) byCat[String(pt[0])] = pt[1];
                else if (idx < oldCats.length) byCat[String(oldCats[idx])] = pt;
              });
              if (oldCats.length || sr.data.every(function (pt) { return Array.isArray(pt); })) {
                sr.data = union.map(function (b) { var bk = String(b); return Object.prototype.hasOwnProperty.call(byCat, bk) ? byCat[bk] : fillVal; });
              }
            });
            entry.xAx.data = union.slice();
          });
        } else if (xType === 'time' || xType === 'value') {
          var isT = xType === 'time', xs = [];
          var parseX = function (rawV) {
            if (rawV === null || rawV === undefined || rawV === '' || typeof rawV === 'boolean') return NaN;
            return isT ? parseUtcMs(rawV) : Number(rawV);
          };
          grp.forEach(function (entry) {
            [entry.xAx.min, entry.xAx.max].forEach(function (v) { var n = parseX(v); if (Number.isFinite(n)) xs.push(n); });
            (entry.opt.series || []).forEach(function (sr) {
              (sr.data || []).forEach(function (pt) {
                var rawX = Array.isArray(pt) ? pt[0] : (pt && typeof pt === 'object' && Array.isArray(pt.value) ? pt.value[0] : NaN);
                var xv = parseX(rawX);
                if (Number.isFinite(xv)) xs.push(xv);
              });
            });
          });
          if (forcedX && forcedX.length) {
            [forcedX[0], forcedX[forcedX.length - 1]].forEach(function (v) { var n = parseX(v); if (Number.isFinite(n)) xs.push(n); });
          }
          if (xs.length) {
            var loX = Math.min.apply(null, xs), hiX = Math.max.apply(null, xs);
            grp.forEach(function (entry) { entry.xAx.min = loX; entry.xAx.max = hiX; });
          }
        }
      });
    }
  }

  function collectAxisYValues(opt, axisIdx) {
    var vals = [], stackPos = {}, stackNeg = {};
    (opt.series || []).forEach(function (sr) {
      if (!sr || Number(sr.yAxisIndex || 0) !== axisIdx) return;
      var sKey = sr.stack ? String(sr.stack) : null;
      if (sKey && !stackPos[sKey]) { stackPos[sKey] = {}; stackNeg[sKey] = {}; }
      (sr.data || []).forEach(function (pt, idx) {
        var raw = Array.isArray(pt) ? pt[1] : (pt && typeof pt === 'object' ? (Array.isArray(pt.value) ? pt.value[1] : pt.value) : pt);
        if (raw === null || raw === undefined || raw === '' || typeof raw === 'boolean') return;
        var v = Number(raw);
        if (!Number.isFinite(v)) return;
        if (sKey) {
          var bk = Array.isArray(pt) ? String(pt[0]) : (pt && typeof pt === 'object' && Array.isArray(pt.value) ? String(pt.value[0]) : String(idx));
          if (v >= 0) stackPos[sKey][bk] = (stackPos[sKey][bk] || 0) + v; else stackNeg[sKey][bk] = (stackNeg[sKey][bk] || 0) + v;
        } else vals.push(v);
      });
      if (sr.markLine && Array.isArray(sr.markLine.data)) {
        sr.markLine.data.forEach(function (ml) { var mv = ml && ml.yAxis !== undefined ? Number(ml.yAxis) : NaN; if (Number.isFinite(mv)) vals.push(mv); });
      }
    });
    [stackPos, stackNeg].forEach(function (map) {
      Object.keys(map).forEach(function (sk) { Object.keys(map[sk]).forEach(function (bk) { vals.push(map[sk][bk]); }); });
    });
    return vals;
  }

  function syncUnitYSpans(mat, opts, svgLayout) {
    if (!svgLayout || (opts && opts.alignY === false)) return;
    var groups = {};
    mat.forEach(function (row) {
      row.forEach(function (opt) {
        if (!opt) return;
        var yAxes = Array.isArray(opt.yAxis) ? opt.yAxis : (opt.yAxis ? [opt.yAxis] : []), y0 = yAxes[0];
        if (!y0 || (y0.type && y0.type !== 'value') || opt.independentYSpan || y0.quietZoomedScale || y0.quietIndependentSpan) return;
        var uk = inferAxisUnit(opt, y0, 'yUnit', 'quietUnit');
        if (!groups[uk]) groups[uk] = [];
        groups[uk].push({ opt: opt, y0: y0 });
      });
    });
    Object.keys(groups).forEach(function (uk) {
      var grp = groups[uk], allVals = [];
      grp.forEach(function (entry) { Array.prototype.push.apply(allVals, collectAxisYValues(entry.opt, 0)); });
      if (!allVals.length) return;
      var sc = svgLayout.sharedNiceScale125(allVals, { targetTicks: (opts && opts.targetYTicks) || 5, includeZero: opts ? opts.includeZero : undefined, headroomRatio: (opts && opts.headroomRatio != null) ? opts.headroomRatio : 0.06 });
      grp.forEach(function (entry) {
        var hadMax = entry.y0.max !== undefined;
        if (grp.length > 1 || entry.y0.min === undefined) entry.y0.min = sc.min;
        if (grp.length > 1 || !hadMax) entry.y0.max = sc.max;
        if (grp.length > 1 || (!hadMax && entry.y0.interval === undefined)) entry.y0.interval = sc.step;
      });
    });
  }

  function formatAxisTickList(ax, fallbackVals, svgLayout) {
    var lo = ax && ax.min != null && Number.isFinite(Number(ax.min)) ? Number(ax.min) : (fallbackVals.length ? Math.min.apply(null, fallbackVals) : 0);
    var hi = ax && ax.max != null && Number.isFinite(Number(ax.max)) ? Number(ax.max) : (fallbackVals.length ? Math.max.apply(null, fallbackVals) : 100);
    var sc = svgLayout ? svgLayout.niceScale125(lo, hi, { targetTicks: 5 }) : { ticks: [lo, hi], step: (hi - lo) || 1 };
    var fmt = ax && ax.axisLabel && typeof ax.axisLabel.formatter === 'function' ? ax.axisLabel.formatter : null;
    return sc.ticks.map(function (v) { return fmt ? String(fmt(v)) : (svgLayout ? svgLayout.formatTick(v, sc.step) : String(v)); });
  }

  function measureYAxisDescriptor(ax, fallbackVals, svgLayout) {
    if (ax && ax.type === 'category' && Array.isArray(ax.data) && ax.data.length && svgLayout && svgLayout.measureCategoryGutter) {
      var al = ax.axisLabel || {};
      var mg = svgLayout.measureCategoryGutter(ax.data, { fontFamily: al.fontFamily, fontSize: al.fontSize, axisLabelMargin: al.margin });
      return { ticks: mg.wrappedLabels, minGutter: mg.gutterPx };
    }
    return { ticks: formatAxisTickList(ax, fallbackVals, svgLayout), minGutter: 0 };
  }

  var _baseGridMap = typeof WeakMap === 'function' ? new WeakMap() : null;

  function alignPlotGridFrames(matrixOrList, opts) {
    var cfg = opts || {}, svgLayout = getSvgLayout(), mat = toMatrix(matrixOrList, cfg);
    if (!mat.length) return matrixOrList;
    mat.forEach(function (row) {
      row.forEach(function (opt) {
        if (!opt) return;
        var rawG = Array.isArray(opt.grid) ? (opt.grid[0] || {}) : (opt.grid || {});
        if (_baseGridMap && !_baseGridMap.has(opt)) _baseGridMap.set(opt, Object.assign({}, rawG));
        applySafeMarkLines(opt, cfg.tokens);
        applySafeLegendLayout(opt, cfg.containerWidth);
      });
    });
    var collapseCols = !!(cfg.collapseColumns || (Number(cfg.containerWidth || 0) > 0 && Number(cfg.containerWidth) < (cfg.stackBreakpoint || 780)));
    var spanMat = collapseCols ? mat.reduce(function (a, r) { r.forEach(function (o) { if (o) a.push([o]); }); return a; }, []) : mat;
    syncColumnXSpans(spanMat, cfg);
    syncUnitYSpans(mat, cfg, svgLayout);
    if (!svgLayout) return matrixOrList;
    var descMat = mat.map(function (row) {
      return row.map(function (opt) {
        if (!opt) return null;
        var yAxes = Array.isArray(opt.yAxis) ? opt.yAxis : (opt.yAxis ? [opt.yAxis] : []), xAx = Array.isArray(opt.xAxis) ? opt.xAxis[0] : opt.xAxis;
        var g0 = Array.isArray(opt.grid) ? (opt.grid[0] || {}) : (opt.grid || {}), baseG = (_baseGridMap && _baseGridMap.get(opt)) || g0;
        var lg = Array.isArray(opt.legend) ? opt.legend[0] : opt.legend, lgOn = !!(lg && lg.show !== false);
        var hasBotLg = !!(lgOn && (lg.bottom != null || lg.top === 'bottom')), hasTopLg = !!(lgOn && !hasBotLg);
        var lgItems = Array.isArray(lg && lg.data) ? lg.data.length : (Array.isArray(opt.series) ? opt.series.length : 0);
        var lgBotFloor = hasBotLg ? (((Number(cfg.containerWidth || 0) > 0 && Number(cfg.containerWidth) < 640) && lgItems >= 3) ? 46 : 38) : 0;
        var baseBot = typeof baseG.bottom === 'number' ? baseG.bottom : null, y0 = yAxes[0] || {}, y1 = yAxes.length > 1 ? yAxes[1] : null;
        var primDesc = measureYAxisDescriptor(y0, collectAxisYValues(opt, 0), svgLayout);
        var secDesc = y1 ? measureYAxisDescriptor(y1, collectAxisYValues(opt, 1).length ? collectAxisYValues(opt, 1) : [0, 100], svgLayout) : { ticks: [], minGutter: 0 };
        var titleObj = Array.isArray(opt.title) ? opt.title[0] : opt.title;
        var hasTopYName = !!(y0.name && (!y0.nameLocation || y0.nameLocation === 'end'));
        if (hasTopYName && (y0.nameGap == null || Number(y0.nameGap) < 12)) y0.nameGap = 12;
        return {
          yTicks: primDesc.ticks, rightTicks: secDesc.ticks, hasRightAxis: !!y1, rightTitle: y1 ? y1.name : '',
          yLabel: y0.name && y0.nameLocation === 'middle' ? y0.name : '', hasTopYName: hasTopYName,
          titleHeight: (titleObj && titleObj.show !== false && titleObj.text) ? 28 : 0,
          xTicks: xAx && Array.isArray(xAx.data) && xAx.data.length ? xAx.data : ['0', '1'], xLabel: xAx && xAx.name ? xAx.name : '',
          hasTopLegend: hasTopLg, hasBottomLegend: hasBotLg, topLegendHeight: hasTopLg ? 28 : 0, bottomLegendHeight: lgBotFloor,
          minLeft: Math.max(typeof baseG.left === 'number' ? baseG.left : (cfg.minLeft || 44), primDesc.minGutter),
          minRight: Math.max(typeof baseG.right === 'number' ? baseG.right : (cfg.minRight || (y1 ? 48 : 16)), secDesc.minGutter),
          minTop: Math.max(typeof baseG.top === 'number' ? baseG.top : (cfg.minTop || 24), hasTopYName ? 30 : 24),
          minBottom: Math.max(baseBot !== null ? baseBot : (cfg.minBottom || 34), lgBotFloor),
          stageHeight: Number(opt.quietStageHeight || cfg.stageHeight || 0), containerPadX: Number(opt.quietContainerPadX || 0),
        };
      });
    });
    var applyCell = function (opt, cell) {
      if (!opt || !cell) return;
      if (Array.isArray(opt.grid) && opt.grid.length) {
        opt.grid[0] = Object.assign({}, opt.grid[0], { containLabel: false, left: cell.left, right: cell.right, top: cell.top });
        if (opt.grid.length === 1) opt.grid[0].bottom = cell.bottom;
      } else opt.grid = Object.assign({}, opt.grid || {}, { containLabel: false, left: cell.left, right: cell.right, top: cell.top, bottom: cell.bottom });
    };
    var flatIdx = [], gutterInput = collapseCols ? descMat.reduce(function (acc, row, r) {
      row.forEach(function (cell, c) { if (cell) { flatIdx.push([r, c, acc.length]); acc.push([cell]); } });
      return acc;
    }, []) : descMat;
    var gutters = svgLayout.computeGridFrameGutters(gutterInput, Object.assign({ maxLeft: 224 }, cfg));
    if (collapseCols) flatIdx.forEach(function (t) { applyCell(mat[t[0]][t[1]], gutters.cells[t[2]] && gutters.cells[t[2]][0]); });
    else mat.forEach(function (row, r) { row.forEach(function (opt, c) { applyCell(opt, gutters.cells[r] && gutters.cells[r][c]); }); });
    return matrixOrList;
  }

  function observeChartResize(hostEl, chart, opts) {
    if (!hostEl || !chart || typeof chart.resize !== 'function') return function () {};
    var raf = typeof root.requestAnimationFrame === 'function' ? root.requestAnimationFrame.bind(root) : function (fn) { return setTimeout(fn, 16); };
    var cancelRaf = typeof root.cancelAnimationFrame === 'function' ? root.cancelAnimationFrame.bind(root) : clearTimeout;
    var lastW = Math.round(hostEl.clientWidth || 0), rafId = 0, dead = false, ro = null, onWin = null;
    var cleanup = function () {
      dead = true;
      if (rafId) { cancelRaf(rafId); rafId = 0; }
      if (ro) { ro.disconnect(); ro = null; }
      if (onWin && typeof root.removeEventListener === 'function') { root.removeEventListener('resize', onWin); onWin = null; }
    };
    var trigger = function () {
      if (dead || (chart.isDisposed && chart.isDisposed())) { cleanup(); return; }
      if (rafId) return;
      rafId = raf(function () {
        rafId = 0;
        if (dead || (chart.isDisposed && chart.isDisposed())) { cleanup(); return; }
        var w = Math.round(hostEl.clientWidth || 0);
        if (w <= 0 || w === lastW) return;
        lastW = w;
        if (opts && typeof opts.onResize === 'function') opts.onResize(w, chart, hostEl); else chart.resize();
      });
    };
    if (typeof root.ResizeObserver === 'function') {
      ro = new root.ResizeObserver(function () {
        if (dead || (chart.isDisposed && chart.isDisposed())) { cleanup(); return; }
        var w = Math.round(hostEl.clientWidth || 0);
        if (w > 0 && w !== lastW) trigger();
      });
      ro.observe(hostEl);
      return cleanup;
    }
    if (typeof root.addEventListener === 'function') { onWin = trigger; root.addEventListener('resize', onWin); }
    return cleanup;
  }

  function alignSharedAxes(optionsArray, opts) { return alignPlotGridFrames(optionsArray, Object.assign({ orientation: 'column' }, opts || {})); }
  function trimTrailingFutureWeeks(weeks, cells, opts) {
    var tb = getTimeBinning();
    return (tb && typeof tb.trimTrailingFutureWeeks === 'function')
      ? tb.trimTrailingFutureWeeks(weeks, cells, opts)
      : { weeks: Array.isArray(weeks) ? weeks.slice() : [], cells: Array.isArray(cells) ? cells.slice() : [] };
  }

  var api = {
    ensureGridContainLabel: ensureGridContainLabel, applyNiceLinearAxisBounds: applyNiceLinearAxisBounds,
    applySafeMarkLines: applySafeMarkLines, applySafeLegendLayout: applySafeLegendLayout,
    alignPlotGridFrames: alignPlotGridFrames, alignSharedAxes: alignSharedAxes,
    observeChartResize: observeChartResize, normalizeOption: normalizeOption,
    binTimeSeries: binTimeSeries, trimTrailingFutureWeeks: trimTrailingFutureWeeks,
  };
  root.QuietEChartsDefaults = Object.assign(root.QuietEChartsDefaults || {}, api);
  if (typeof module === 'object' && module.exports) module.exports = api;
}(typeof window !== 'undefined' ? window : globalThis));


// SPDX-License-Identifier: Apache-2.0
(function (root) {
  'use strict';

  function readThemeTokens(doc) {
    var d = doc || (typeof document !== 'undefined' ? document : null);
    var cs = (d && d.documentElement && typeof getComputedStyle === 'function')
      ? getComputedStyle(d.documentElement) : null;
    var pick = function (tok, fb) {
      try {
        var v = cs ? cs.getPropertyValue(tok).trim() : '';
        return v || fb;
      } catch (_e) {
        return fb;
      }
    };
    return {
      textPrimary: pick('--text-primary', '#0F172A'),
      textSecondary: pick('--text-secondary', '#475569'),
      borderHairline: pick('--border-hairline', '#E2E8F0'),
      borderStrong: pick('--border-strong', '#94A3B8'),
      bgSurface: pick('--bg-surface', '#FFFFFF'),
      bgElevated: pick('--bg-elevated', '#F8FAFC'),
      accentFocal: pick('--accent-focal', '#1D4ED8'),
    };
  }

  function nice125(lo, hi, targetTicks) {
    if (root.QuietSvgLayout && typeof root.QuietSvgLayout.niceScale125 === 'function') {
      return root.QuietSvgLayout.niceScale125(lo, hi, { targetTicks: targetTicks || 5, includeZero: lo >= 0 });
    }
    var a = lo >= 0 ? 0 : lo;
    var span = Math.max(1e-9, hi - a);
    var raw = span / Math.max(2, (targetTicks || 5) - 1);
    var p = Math.pow(10, Math.floor(Math.log10(raw)));
    var f = raw / p;
    var m = f <= 1 ? 1 : (f <= 2 ? 2 : (f <= 5 ? 5 : 10));
    var step = m * p;
    var sMin = Math.floor(a / step) * step;
    var sMax = Math.ceil(hi / step) * step;
    return { min: sMin, max: sMax === sMin ? sMin + step : sMax, step: step };
  }

  function finiteNum(v) {
    if (v === null || v === undefined || v === '' || typeof v === 'boolean') return null;
    var n = Number(v);
    return Number.isFinite(n) ? n : null;
  }

  function normalizeCyclicalBuckets(buckets) {
    return (Array.isArray(buckets) ? buckets : []).map(function (b, idx) {
      var item = b && typeof b === 'object' ? b : {};
      var label = String(item.label != null ? item.label : (item.slot != null ? item.slot : (item.hour != null ? item.hour : (item.day != null ? item.day : idx))));
      var vals = Array.isArray(item.values) ? item.values.map(finiteNum).filter(function (v) { return v !== null; }) : [];
      var rawN = [item.activeDays, item.active_days, item.nActive, item.n_active, item.n, item.samples].find(function (v) { return v != null; });
      var activeDays = finiteNum(rawN);
      var min = finiteNum(item.min);
      var max = finiteNum(item.max);
      var avg = finiteNum(item.avg != null ? item.avg : item.mean);
      var recent = finiteNum(item.recent != null ? item.recent : (item.last24h != null ? item.last24h : (item.current != null ? item.current : item.today)));
      if (vals.length) {
        if (min === null) min = Math.min.apply(null, vals);
        if (max === null) max = Math.max.apply(null, vals);
        if (avg === null) avg = vals.reduce(function (s, x) { return s + x; }, 0) / vals.length;
        if (activeDays === null) activeDays = vals.length;
      }
      if (min !== null && max !== null && min > max) {
        var t = min; min = max; max = t;
      }
      if (avg === null && min !== null && max !== null) avg = (min + max) * 0.5;
      if (min !== null && max === null) max = avg !== null ? Math.max(min, avg) : min;
      if (max !== null && min === null) min = avg !== null ? Math.min(max, avg) : max;
      var hasObs = (activeDays === null || activeDays > 0) && min !== null && max !== null;
      return {
        idx: idx,
        label: label,
        min: hasObs ? min : null,
        avg: hasObs ? avg : null,
        max: hasObs ? max : null,
        recent: recent,
        activeDays: activeDays !== null ? activeDays : (hasObs ? 1 : 0),
      };
    });
  }

  function buildCyclicalWhiskerOption(buckets, opts) {
    var cfg = opts || {};
    var tok = cfg.tokens || readThemeTokens(cfg.document);
    var rows = normalizeCyclicalBuckets(buckets);
    var labels = rows.map(function (r) { return r.label; });
    var yVals = [];
    rows.forEach(function (r) {
      [r.min, r.avg, r.max, r.recent].forEach(function (v) { if (v !== null) yVals.push(v); });
    });
    var rawLo = yVals.length ? Math.min.apply(null, yVals) : 0;
    var rawHi = yVals.length ? Math.max.apply(null, yVals) : 10;
    var span = rawHi - rawLo;
    var padHi = rawHi + (span > 0 ? span * 0.08 : (Math.abs(rawHi) * 0.08 || 1));
    var ySc = nice125(rawLo >= 0 ? 0 : rawLo, padHi, 5);
    var unit = String(cfg.unit || '').trim();
    var rangeLabel = String(cfg.rangeLabel || 'Min–Max');
    var avgLabel = String(cfg.avgLabel || 'Active Avg');
    var recentLabel = String(cfg.recentLabel || 'Last 24h');
    var showLegend = cfg.showLegend !== false;
    var cw = Number(cfg.containerWidth || 640);
    var xInterval = cfg.xInterval !== undefined ? cfg.xInterval : (labels.length > 16 ? (cw < 480 ? 3 : 2) : 0);
    var yName = String(cfg.yName || (unit ? 'Activity / (' + unit + ')' : 'Per-Day Activity'));

    var stemData = rows.map(function (r) {
      return r.min === null ? [r.idx, null, null, null, r.recent, r.activeDays] : [r.idx, r.min, r.max, r.avg, r.recent, r.activeDays];
    });
    var avgData = rows.map(function (r) { return r.avg === null ? [r.idx, null] : [r.idx, r.avg]; });
    var recentData = rows.map(function (r) { return r.recent === null ? [r.idx, null] : [r.idx, r.recent]; });
    var fmtVal = function (v) {
      if (v === null || v === undefined || !Number.isFinite(Number(v))) return '—';
      var n = Number(v), absN = Math.abs(n);
      var s = absN > 0 && absN < 1 ? n.toFixed(2).replace(/0+$/, '').replace(/\.$/, '') : (Math.abs(n - Math.round(n)) < 0.05 ? String(Math.round(n)) : n.toFixed(1));
      return s + (unit ? ' ' + unit : '');
    };

    var opt = {
      animation: false,
      backgroundColor: 'transparent',
      textStyle: { fontFamily: 'Inter, system-ui, sans-serif', color: tok.textPrimary },
      tooltip: {
        trigger: 'axis',
        renderMode: 'richText',
        confine: true,
        backgroundColor: tok.bgElevated,
        borderColor: tok.borderStrong,
        borderWidth: 1,
        textStyle: { color: tok.textPrimary, fontSize: 12 },
        formatter: function (params) {
          var first = Array.isArray(params) ? params[0] : params;
          var idx = first && first.dataIndex != null ? Number(first.dataIndex) : 0;
          var r = rows[idx];
          if (!r) return '';
          var hdr = r.label + (r.activeDays ? ' (n=' + r.activeDays + ' active days)' : ' (0 active days)');
          if (r.min === null) return hdr + '\nNo observations recorded';
          return [
            hdr,
            rangeLabel + ': ' + fmtVal(r.min) + ' – ' + fmtVal(r.max),
            avgLabel + ': ' + fmtVal(r.avg),
            recentLabel + ': ' + fmtVal(r.recent),
          ].join('\n');
        },
      },
      legend: {
        show: showLegend,
        bottom: 0,
        left: 'center',
        itemWidth: 14,
        itemHeight: 8,
        itemGap: 14,
        textStyle: { color: tok.textSecondary, fontSize: 11 },
        data: [rangeLabel, avgLabel, recentLabel],
      },
      grid: { left: 48, right: 16, top: 32, bottom: showLegend ? 56 : 36, containLabel: true },
      xAxis: {
        type: 'category',
        name: String(cfg.xName || ''),
        nameLocation: 'middle',
        nameGap: 24,
        data: labels,
        axisLine: { lineStyle: { color: tok.textSecondary } },
        axisTick: { alignWithLabel: true },
        axisLabel: { color: tok.textSecondary, fontSize: 11, interval: xInterval, hideOverlap: true },
      },
      yAxis: {
        type: 'value',
        name: yName,
        nameLocation: 'end',
        nameGap: 12,
        nameTextStyle: { color: tok.textSecondary, fontSize: 11, fontWeight: 600, align: 'left' },
        min: ySc.min,
        max: ySc.max,
        interval: ySc.step,
        axisLine: { lineStyle: { color: tok.textSecondary } },
        axisLabel: { color: tok.textSecondary, fontSize: 11 },
        splitLine: { lineStyle: { color: tok.borderHairline, type: 'dashed' } },
      },
      series: [
        {
          id: 'cyclical-range',
          name: rangeLabel,
          type: 'custom',
          z: 2,
          itemStyle: { color: tok.textSecondary },
          renderItem: function (params, api) {
            var xv = api.value(0), lo = api.value(1), hi = api.value(2);
            if (lo === null || hi === null || !Number.isFinite(lo) || !Number.isFinite(hi)) return null;
            var pLo = api.coord([xv, lo]), pHi = api.coord([xv, hi]);
            if (!pLo || !pHi || !Number.isFinite(pLo[0]) || !Number.isFinite(pLo[1]) || !Number.isFinite(pHi[1])) return null;
            var cs = params && params.coordSys;
            var catW = (cs && labels.length) ? (cs.width / labels.length) : 16;
            var cap = Math.min(4.5, Math.max(2.5, catW * 0.22));
            return {
              type: 'group',
              children: [
                { type: 'line', shape: { x1: pLo[0], y1: pLo[1], x2: pHi[0], y2: pHi[1] }, style: { stroke: tok.textSecondary, lineWidth: 1.5, opacity: 0.72 } },
                { type: 'line', shape: { x1: pHi[0] - cap, y1: pHi[1], x2: pHi[0] + cap, y2: pHi[1] }, style: { stroke: tok.textSecondary, lineWidth: 1.5, opacity: 0.72 } },
                { type: 'line', shape: { x1: pLo[0] - cap, y1: pLo[1], x2: pLo[0] + cap, y2: pLo[1] }, style: { stroke: tok.textSecondary, lineWidth: 1.5, opacity: 0.72 } },
              ],
            };
          },
          data: stemData,
        },
        {
          id: 'cyclical-avg',
          name: avgLabel,
          type: 'custom',
          z: 3,
          itemStyle: { color: tok.textPrimary },
          renderItem: function (params, api) {
            var xv = api.value(0), av = api.value(1);
            if (av === null || !Number.isFinite(av)) return null;
            var pt = api.coord([xv, av]);
            if (!pt || !Number.isFinite(pt[0]) || !Number.isFinite(pt[1])) return null;
            var cs = params && params.coordSys;
            var catW = (cs && labels.length) ? (cs.width / labels.length) : 16;
            var half = Math.min(9, Math.max(4, catW * 0.34));
            return {
              type: 'line',
              shape: { x1: pt[0] - half, y1: pt[1], x2: pt[0] + half, y2: pt[1] },
              style: { stroke: tok.textPrimary, lineWidth: 2.4 },
            };
          },
          data: avgData,
        },
        {
          id: 'cyclical-recent',
          name: recentLabel,
          type: 'scatter',
          z: 4,
          symbol: 'circle',
          symbolSize: 7.5,
          itemStyle: { color: tok.accentFocal, borderColor: tok.bgSurface, borderWidth: 1.5 },
          data: recentData,
        },
      ],
    };
    return opt;
  }

  root.QuietEChartsDefaults = root.QuietEChartsDefaults || {};
  root.QuietEChartsDefaults.buildCyclicalWhiskerOption = buildCyclicalWhiskerOption;
  var api = { buildCyclicalWhiskerOption: buildCyclicalWhiskerOption, normalizeCyclicalBuckets: normalizeCyclicalBuckets };
  root.QuietCyclicalWhiskers = api;
  if (typeof module === 'object' && module.exports) module.exports = api;
}(typeof window !== 'undefined' ? window : globalThis));


// SPDX-License-Identifier: Apache-2.0
(function (root) {
  'use strict';

  function positionPopover(trigger, popover) {
    if (!trigger || !popover) return;
    var hasLinkedAnchor = popover.hasAttribute('popover') && popover.id &&
      trigger.getAttribute('popovertarget') === popover.id &&
      typeof CSS !== 'undefined' && typeof CSS.supports === 'function' &&
      CSS.supports('position-area', 'block-end');
    if (hasLinkedAnchor) return;
    var doc = popover.ownerDocument;
    var tr = trigger.getBoundingClientRect();
    var vw = (root.innerWidth || (doc && doc.documentElement && doc.documentElement.clientWidth) || 1024);
    var vh = (root.innerHeight || (doc && doc.documentElement && doc.documentElement.clientHeight) || 768);
    var isRtl = doc && ((doc.documentElement && doc.documentElement.dir === 'rtl') || doc.dir === 'rtl');
    popover.style.positionArea = 'none';
    popover.style.position = 'fixed';
    var pr = popover.getBoundingClientRect();
    var popW = Math.max(pr.width || 240, 220), popH = Math.max(pr.height || 180, 140);
    var anchorX = isRtl ? (tr.right - popW) : tr.left;
    var left = Math.max(8, Math.min(vw - popW - 8, anchorX));
    var spaceBelow = vh - tr.bottom - 12;
    var spaceAbove = tr.top - 12;
    var top;
    if (popH <= spaceBelow || spaceBelow >= spaceAbove) top = Math.max(8, Math.min(vh - popH - 8, tr.bottom + 6));
    else top = Math.max(8, tr.top - popH - 6);
    popover.style.left = Math.round(left) + 'px';
    popover.style.top = Math.round(top) + 'px';
  }

  function isPopOpen(pop) {
    if (!pop) return false;
    return pop.dataset.open === 'true' || (typeof pop.matches === 'function' && pop.matches(':is(:popover-open, .\\:popover-open)'));
  }

  function closeOtherPopovers(doc, exceptStepper) {
    if (!doc) return;
    doc.querySelectorAll('.va-period-stepper').forEach(function (st) {
      if (st !== exceptStepper) closePopover(st, false);
    });
  }

  function closePopover(stepper, restoreFocus) {
    if (!stepper) return;
    var trigger = stepper.querySelector('.va-period-trigger');
    var pop = stepper.querySelector('.va-preset-popover');
    if (!pop || !isPopOpen(pop)) return;
    pop.dataset.open = 'false';
    if (!(pop.hasAttribute('popover') && trigger && pop.id && trigger.getAttribute('popovertarget') === pop.id)) {
      pop.setAttribute('hidden', '');
    }
    if (pop.hasAttribute('popover') && typeof pop.hidePopover === 'function') {
      try { if (pop.matches(':is(:popover-open, .\\:popover-open)')) pop.hidePopover(); } catch (_e) {}
    }
    if (trigger) {
      trigger.setAttribute('aria-expanded', 'false');
      if (restoreFocus) trigger.focus({ preventScroll: true });
    }
  }

  function openPopover(stepper, focusFirst) {
    if (!stepper) return;
    var trigger = stepper.querySelector('.va-period-trigger');
    var pop = stepper.querySelector('.va-preset-popover');
    if (!trigger || !pop) return;
    closeOtherPopovers(stepper.ownerDocument, stepper);
    pop.removeAttribute('hidden');
    pop.dataset.open = 'true';
    trigger.setAttribute('aria-expanded', 'true');
    if (pop.hasAttribute('popover') && typeof pop.showPopover === 'function') {
      try { if (!pop.matches(':is(:popover-open, .\\:popover-open)')) pop.showPopover({ source: trigger }); } catch (_e) {}
    }
    positionPopover(trigger, pop);
    if (focusFirst) {
      var items = [].slice.call(pop.querySelectorAll('.va-preset-item:not(:disabled)'));
      var active = pop.querySelector('.va-preset-item[aria-checked="true"]:not(:disabled)') || items[0];
      if (active) active.focus({ preventScroll: true });
    }
  }

  function getBinning() { return root.QuietTimeBinning || (typeof require === 'function' ? (function () { try { return require('./quiet-time-binning.js'); } catch (_e) { return null; } }()) : null); }
  function resolveWindowBounds(opts) { var tb = getBinning(); return tb && tb.resolvePeriodBounds ? tb.resolvePeriodBounds(opts) : null; }
  function formatPresetLabel(preset, mode) { var tb = getBinning(); return tb && tb.formatPresetLabel ? tb.formatPresetLabel(preset, mode) : String(preset || ''); }
  function hasCorpusConfig(st) { return !!(st && (st.dataset.minDate || st.dataset.maxDate || st.dataset.anchorDate || st.dataset.mode)); }

  function syncBoundedState(st, stepDelta, toToday, opts) {
    if (!st) return null;
    var cfg = opts || {};
    var anchor = toToday ? (st.dataset.maxDate || cfg.today || st.dataset.today || '') : (cfg.anchorDate || st.dataset.anchorDate || '');
    var b = resolveWindowBounds({ mode: st.dataset.mode || '', preset: st.dataset.value || (st.dataset.mode === 'cal' ? 'mtd' : '30d'), anchorDate: anchor, minDate: st.dataset.minDate || '', maxDate: st.dataset.maxDate || '', today: cfg.today || st.dataset.today || '', stepDelta: stepDelta || 0 });
    if (!b) return null;
    st.dataset.mode = b.mode; st.dataset.value = b.preset; st.dataset.anchorDate = b.endDate;
    st.dataset.startDate = b.startDate; st.dataset.endDate = b.endDate;
    st.querySelectorAll('.va-preset-item').forEach(function (it) { it.setAttribute('aria-checked', it.dataset.preset === b.preset ? 'true' : 'false'); });
    var lblEl = st.querySelector('[data-period-label]');
    if (lblEl) lblEl.textContent = b.label + ' · ' + b.startDate + '–' + b.endDate;
    var pBtn = st.querySelector('[data-period-step="-1"]'), nBtn = st.querySelector('[data-period-step="1"]'), tBtn = st.querySelector('[data-period-today]');
    if (pBtn) pBtn.disabled = !b.canStepPrev;
    if (nBtn) nBtn.disabled = !b.canStepNext;
    if (tBtn) { tBtn.textContent = b.anchorLabel; tBtn.hidden = b.atLatest; }
    return b;
  }

  function setPeriodMode(st, mode, opts) {
    if (!st) return null;
    st.dataset.mode = mode;
    var b = syncBoundedState(st, 0, false, opts);
    if (b && typeof root.CustomEvent === 'function') st.dispatchEvent(new root.CustomEvent('quiet:period-change', { bubbles: true, detail: b }));
    return b;
  }

  function applyPresetChoice(stepper, item) {
    if (!stepper || !item || item.disabled) return;
    var val = item.dataset.preset || item.textContent.trim();
    var lbl = item.dataset.label || item.textContent.trim();
    var spanTxt = item.dataset.span || '';
    stepper.dataset.value = val;
    if (item.dataset.mode) stepper.dataset.mode = item.dataset.mode;
    else delete stepper.dataset.mode;
    stepper.querySelectorAll('.va-preset-item').forEach(function (b) {
      b.setAttribute('aria-checked', b === item ? 'true' : 'false');
    });
    var bounds = hasCorpusConfig(stepper) ? syncBoundedState(stepper, 0, false) : null;
    if (!bounds) {
      var lblEl = stepper.querySelector('[data-period-label]');
      if (lblEl) lblEl.textContent = spanTxt ? (lbl + ' · ' + spanTxt) : lbl;
      var todayBtn = stepper.querySelector('[data-period-today]');
      if (todayBtn) todayBtn.hidden = item.dataset.atToday === 'true';
    }
    closePopover(stepper, true);
    if (typeof root.CustomEvent === 'function') {
      var detail = bounds ? Object.assign({}, bounds, { span: spanTxt }) : { preset: val, label: lbl, span: spanTxt };
      stepper.dispatchEvent(new root.CustomEvent('quiet:period-change', { bubbles: true, detail: detail }));
    }
  }

  function bindStepper(stepper) {
    if (!stepper || stepper.dataset.quietBound === '1') return;
    stepper.dataset.quietBound = '1';
    if (hasCorpusConfig(stepper)) syncBoundedState(stepper, 0, false);
    var doc = stepper.ownerDocument;
    var trigger = stepper.querySelector('.va-period-trigger');
    var pop = stepper.querySelector('.va-preset-popover');
    if (trigger && pop) {
      var isNativeLinked = pop.hasAttribute('popover') && !!pop.id && trigger.getAttribute('popovertarget') === pop.id;
      if (isNativeLinked) {
        pop.removeAttribute('hidden');
        pop.addEventListener('toggle', function (ev) {
          var opening = ev && ev.newState === 'open';
          pop.dataset.open = opening ? 'true' : 'false';
          trigger.setAttribute('aria-expanded', opening ? 'true' : 'false');
          if (opening) {
            closeOtherPopovers(doc, stepper);
            positionPopover(trigger, pop);
          }
        });
      } else {
        trigger.addEventListener('click', function (ev) {
          if (isPopOpen(pop)) closePopover(stepper, false);
          else openPopover(stepper, ev.detail === 0);
        });
      }
      trigger.addEventListener('keydown', function (ev) {
        if (ev.key === 'ArrowDown') { ev.preventDefault(); openPopover(stepper, true); }
        else if (ev.key === 'Escape') { closePopover(stepper, true); }
      });
      pop.addEventListener('keydown', function (ev) {
        var items = [].slice.call(pop.querySelectorAll('.va-preset-item:not(:disabled)'));
        if (ev.key === 'Escape') { ev.preventDefault(); closePopover(stepper, true); return; }
        if (!items.length) return;
        var idx = items.indexOf(doc.activeElement);
        if (ev.key === 'ArrowDown') { ev.preventDefault(); items[(idx + 1) % items.length].focus(); }
        else if (ev.key === 'ArrowUp') { ev.preventDefault(); items[(idx - 1 + items.length) % items.length].focus(); }
        else if (ev.key === 'Home') { ev.preventDefault(); items[0].focus(); }
        else if (ev.key === 'End') { ev.preventDefault(); items[items.length - 1].focus(); }
      });
      pop.addEventListener('click', function (ev) {
        var item = ev.target && ev.target.closest ? ev.target.closest('.va-preset-item') : null;
        if (item) applyPresetChoice(stepper, item);
      });
    }
    stepper.addEventListener('click', function (ev) {
      var stepBtn = ev.target && ev.target.closest ? ev.target.closest('[data-period-step]') : null;
      if (stepBtn && !stepBtn.disabled && typeof root.CustomEvent === 'function') {
        var delta = Number(stepBtn.dataset.periodStep || 0);
        var bStep = hasCorpusConfig(stepper) ? syncBoundedState(stepper, delta, false) : null;
        var sDet = bStep ? Object.assign({ step: delta }, bStep) : { step: delta, preset: stepper.dataset.value || '' };
        stepper.dispatchEvent(new root.CustomEvent('quiet:period-change', { bubbles: true, detail: sDet }));
      }
      var todayBtn = ev.target && ev.target.closest ? ev.target.closest('[data-period-today]') : null;
      if (todayBtn && !todayBtn.hidden) {
        var bToday = hasCorpusConfig(stepper) ? syncBoundedState(stepper, 0, true) : null;
        todayBtn.hidden = true;
        if (typeof root.CustomEvent === 'function') {
          var tDet = bToday ? Object.assign({ today: true }, bToday) : { today: true, preset: stepper.dataset.value || '' };
          stepper.dispatchEvent(new root.CustomEvent('quiet:period-change', { bubbles: true, detail: tDet }));
        }
      }
    });
  }

  function expandActiveBranches(rail) {
    if (!rail) return;
    rail.querySelectorAll('.va-tree-dest[aria-current="page"], .va-tree-dest.is-active').forEach(function (dest) {
      var grp = dest.closest('.va-tree-group, .va-tree-children');
      while (grp && rail.contains(grp)) {
        grp.hidden = false;
        var parentRow = grp.previousElementSibling;
        var caret = parentRow && parentRow.querySelector ? parentRow.querySelector('.va-tree-caret') : null;
        if (caret) caret.setAttribute('aria-expanded', 'true');
        grp = grp.parentElement ? grp.parentElement.closest('.va-tree-group, .va-tree-children') : null;
      }
    });
  }

  function applyTreeChildCaps(rail) {
    if (!rail || !rail.ownerDocument) return;
    var doc = rail.ownerDocument;
    rail.querySelectorAll('.va-tree-children, .va-tree-group').forEach(function (grp) {
      if (grp.dataset.treeCap === 'false' || grp.querySelector(':scope > .va-tree-more')) return;
      var parsedMax = parseInt(grp.dataset.maxVisible || '5', 10);
      var maxVis = Math.max(1, Number.isFinite(parsedMax) ? parsedMax : 5);
      var kids = [].slice.call(grp.children).filter(function (el) {
        return !el.classList.contains('va-tree-more') && !el.classList.contains('va-tree-group') && !el.classList.contains('va-tree-children');
      });
      if (kids.length <= maxVis) return;
      var actIdx = kids.findIndex(function (el) {
        return el.matches('.is-active, [aria-current="page"]') || !!el.querySelector('.is-active, [aria-current="page"]');
      });
      var hiddenKids = [];
      kids.forEach(function (el, idx) {
        var keep = actIdx >= maxVis ? (idx < maxVis - 1 || idx === actIdx) : (idx < maxVis);
        if (!keep) {
          el.hidden = true;
          el.dataset.treeOverflow = '1';
          hiddenKids.push(el);
          var sub = el.nextElementSibling;
          if (sub && (sub.classList.contains('va-tree-group') || sub.classList.contains('va-tree-children')) && !sub.hidden) {
            sub.hidden = true;
            sub.dataset.treeOverflow = '1';
          }
        }
      });
      if (hiddenKids.length) {
        var btn = doc.createElement('button');
        btn.type = 'button';
        btn.className = 'va-tree-more';
        btn.textContent = '+ Show ' + hiddenKids.length + ' older…';
        grp.appendChild(btn);
      }
    });
  }

  function getBackdropFor(rail, doc) {
    if (rail && rail.nextElementSibling && rail.nextElementSibling.classList && rail.nextElementSibling.classList.contains('va-drawer-backdrop')) {
      return rail.nextElementSibling;
    }
    return doc ? doc.querySelector('.va-drawer-backdrop') : null;
  }

  function getTriggersFor(rail, doc) {
    if (!rail || !doc) return [];
    if (rail.id) {
      return [].slice.call(doc.querySelectorAll('[aria-controls="' + rail.id + '"], [data-rail-trigger="' + rail.id + '"]'));
    }
    return [].slice.call(doc.querySelectorAll('[data-rail-trigger=""]'));
  }

  function setRailOpen(rail, backdrop, open, restoreFocus) {
    if (!rail) return;
    if (open) expandActiveBranches(rail);
    rail.dataset.open = open ? 'true' : 'false';
    rail.classList.toggle('is-open', !!open);
    var doc = rail.ownerDocument;
    var isOverlay = rail.dataset.mode === 'overlay' || (root.innerWidth || 1200) < 1080;
    var bd = backdrop || getBackdropFor(rail, doc);
    if (bd) {
      var showBd = !!(open && isOverlay);
      bd.dataset.open = showBd ? 'true' : 'false';
      bd.classList.toggle('is-open', showBd);
    }
    var trigs = getTriggersFor(rail, doc);
    trigs.forEach(function (btn) { btn.setAttribute('aria-expanded', open ? 'true' : 'false'); });
    if (!open && restoreFocus && trigs[0] && typeof trigs[0].focus === 'function') trigs[0].focus({ preventScroll: true });
  }

  function bindRail(rail) {
    if (!rail || rail.dataset.quietBound === '1') return;
    rail.dataset.quietBound = '1';
    applyTreeChildCaps(rail);
    var doc = rail.ownerDocument;
    var backdrop = getBackdropFor(rail, doc);
    if (backdrop) backdrop.addEventListener('click', function () { setRailOpen(rail, backdrop, false, true); });
    rail.addEventListener('click', function (ev) {
      var moreBtn = ev.target && ev.target.closest ? ev.target.closest('.va-tree-more') : null;
      if (moreBtn) {
        var grp = moreBtn.closest('.va-tree-children, .va-tree-group');
        if (grp) {
          var firstShown = null;
          [].slice.call(grp.children).forEach(function (el) {
            if (el.hidden && el.dataset.treeOverflow === '1') {
              el.hidden = false;
              delete el.dataset.treeOverflow;
              if (!firstShown) firstShown = el;
            }
          });
          moreBtn.remove();
          var focusEl = firstShown && (firstShown.matches('button, a') ? firstShown : firstShown.querySelector('button, a'));
          if (focusEl && typeof focusEl.focus === 'function') focusEl.focus({ preventScroll: true });
        }
        return;
      }
      var caret = ev.target && ev.target.closest ? ev.target.closest('.va-tree-caret') : null;
      if (caret) {
        ev.stopPropagation();
        var exp = caret.getAttribute('aria-expanded') === 'true';
        caret.setAttribute('aria-expanded', exp ? 'false' : 'true');
        var row = caret.closest('.va-tree-row');
        var next = row ? row.nextElementSibling : null;
        var sub = (next && (next.classList.contains('va-tree-group') || next.classList.contains('va-tree-children'))) ? next : null;
        if (sub) sub.hidden = exp;
        return;
      }
      var dest = ev.target && ev.target.closest ? ev.target.closest('.va-tree-dest') : null;
      if (dest) {
        rail.querySelectorAll('.va-tree-dest').forEach(function (d) { d.removeAttribute('aria-current'); d.classList.remove('is-active'); });
        dest.setAttribute('aria-current', 'page');
        dest.classList.add('is-active');
        if (rail.dataset.mode === 'overlay' || (root.innerWidth || 1200) < 1080) setRailOpen(rail, backdrop, false, false);
        if (typeof root.CustomEvent === 'function') {
          rail.dispatchEvent(new root.CustomEvent('quiet:tree-navigate', { bubbles: true, detail: { target: dest.dataset.target || '', label: dest.textContent.trim() } }));
        }
        return;
      }
      if (ev.target && ev.target.closest && ev.target.closest('[data-rail-close]')) setRailOpen(rail, backdrop, false, true);
    });
  }

  function bindModalSheets(scope) {
    if (!scope || !scope.querySelectorAll) return;
    if (typeof HTMLDialogElement !== 'undefined' && !('closedBy' in HTMLDialogElement.prototype)) {
      scope.querySelectorAll('dialog.va-modal-sheet[closedby="any"]').forEach(function (dlg) {
        if (dlg.dataset.quietClosedBy === '1') return;
        dlg.dataset.quietClosedBy = '1';
        var pressedOut = false;
        var outside = function (ev) {
          if (ev.target !== dlg || (ev.button != null && ev.button !== 0)) return false;
          var r = dlg.getBoundingClientRect();
          return ev.clientX < r.left || ev.clientX > r.right || ev.clientY < r.top || ev.clientY > r.bottom;
        };
        dlg.addEventListener('pointerdown', function (ev) { pressedOut = outside(ev); });
        dlg.addEventListener('pointercancel', function () { pressedOut = false; });
        dlg.addEventListener('pointerup', function (ev) { if (pressedOut && outside(ev)) dlg.close(); pressedOut = false; });
      });
    }
  }

  var _docBound = false;
  function boot(container) {
    var scope = container && container.querySelectorAll ? container : (root.document || null);
    if (!scope) return;
    scope.querySelectorAll('[data-period-stepper], .va-period-stepper').forEach(bindStepper);
    scope.querySelectorAll('.va-side-rail').forEach(bindRail);
    bindModalSheets(scope);
    if (!_docBound && root.document) {
      _docBound = true;
      var doc = root.document;
      doc.addEventListener('click', function (ev) {
        var openDlgBtn = ev.target && ev.target.closest ? ev.target.closest('[data-dialog-open]') : null;
        if (openDlgBtn) {
          bindModalSheets(doc);
          doc.querySelectorAll('.va-period-stepper').forEach(function (st) { closePopover(st, false); });
          var dlg = doc.getElementById(openDlgBtn.dataset.dialogOpen);
          if (dlg && typeof dlg.showModal === 'function' && !dlg.open) dlg.showModal();
          return;
        }
        var closeDlgBtn = ev.target && ev.target.closest ? ev.target.closest('[data-dialog-close]') : null;
        if (closeDlgBtn) {
          var parentDlg = closeDlgBtn.closest('dialog');
          if (parentDlg && typeof parentDlg.close === 'function') parentDlg.close();
          return;
        }
        var trig = ev.target && ev.target.closest ? ev.target.closest('[data-rail-trigger]') : null;
        if (trig) {
          var targetId = trig.getAttribute('aria-controls') || trig.dataset.railTrigger;
          var rail = targetId ? doc.getElementById(targetId) : doc.querySelector('.va-side-rail');
          if (rail) setRailOpen(rail, getBackdropFor(rail, doc), !(rail.dataset.open === 'true' || rail.classList.contains('is-open')), false);
        }
        doc.querySelectorAll('.va-period-stepper').forEach(function (st) {
          if (!st.contains(ev.target)) closePopover(st, false);
        });
      });
      doc.addEventListener('keydown', function (ev) {
        if (doc.querySelector('dialog.va-modal-sheet[open], dialog:modal')) return;
        if (ev.key === 'Escape') {
          doc.querySelectorAll('.va-period-stepper').forEach(function (st) { closePopover(st, true); });
          doc.querySelectorAll('.va-side-rail[data-open="true"], .va-side-rail.is-open').forEach(function (r) {
            setRailOpen(r, getBackdropFor(r, doc), false, true);
          });
        }
      });
      var reposRaf = 0;
      var repositionOpen = function () {
        if (reposRaf) return;
        var rafFn = typeof root.requestAnimationFrame === 'function' ? root.requestAnimationFrame.bind(root) : function (fn) { fn(); return 0; };
        reposRaf = rafFn(function () {
          reposRaf = 0;
          doc.querySelectorAll('.va-period-stepper').forEach(function (st) {
            var pop = st.querySelector('.va-preset-popover');
            var trig = st.querySelector('.va-period-trigger');
            if (pop && trig && isPopOpen(pop)) positionPopover(trig, pop);
          });
        });
      };
      if (typeof root.addEventListener === 'function') root.addEventListener('resize', repositionOpen);
      doc.addEventListener('scroll', repositionOpen, true);
    }
  }

  if (root.document) {
    if (root.document.readyState === 'loading') root.document.addEventListener('DOMContentLoaded', function () { boot(root.document); });
    else boot(root.document);
  }

  var stepperApi = {
    boot: boot, openPopover: openPopover, closePopover: closePopover, applyPresetChoice: applyPresetChoice,
    positionPopover: positionPopover, resolveWindowBounds: resolveWindowBounds, formatPresetLabel: formatPresetLabel,
    setPeriodMode: setPeriodMode, syncBoundedState: syncBoundedState,
  };
  var railApi = { boot: boot, setRailOpen: setRailOpen, expandActiveBranches: expandActiveBranches, applyTreeChildCaps: applyTreeChildCaps };
  root.QuietPeriodStepper = stepperApi;
  root.QuietRailTree = railApi;
  if (typeof module === 'object' && module.exports) module.exports = { QuietPeriodStepper: stepperApi, QuietRailTree: railApi };
}(typeof window !== 'undefined' ? window : globalThis));


// SPDX-License-Identifier: Apache-2.0
(function (root) {
  'use strict';

  function nodeIdOf(n, fallbackIdx) {
    if (!n || typeof n !== 'object') return String(fallbackIdx);
    if (n.id != null) return String(n.id);
    if (n.name != null) return String(n.name);
    return String(fallbackIdx);
  }

  function nodeColOf(n) {
    var raw = n && (n.col != null ? n.col : (n.column != null ? n.column : (n.stage != null ? n.stage : n.depth)));
    var num = Number(raw);
    return Number.isFinite(num) ? num : 0;
  }

  function nodeCountOf(n) {
    var raw = n && (n.count != null ? n.count : (n.value != null ? n.value : 0));
    var num = Number(raw);
    return Number.isFinite(num) ? num : 0;
  }

  /**
   * Order multi-column Sankey intermediate columns by (primaryTargetRank, -count)
   * right-to-left to minimize diagonal ribbon crossings over labels.
   */
  function sortColumnsTopologically(nodes, edges, opts) {
    var srcNodes = Array.isArray(nodes) ? nodes : [], srcEdges = Array.isArray(edges) ? edges : [], cfg = opts || {};
    var byCol = Object.create(null), nodeMeta = Object.create(null), outEdges = Object.create(null);
    srcNodes.forEach(function (n, idx) {
      var id = nodeIdOf(n, idx), col = nodeColOf(n), cnt = nodeCountOf(n);
      var entry = { raw: n, id: id, col: col, count: cnt, origIdx: idx };
      nodeMeta[id] = entry;
      if (!byCol[col]) byCol[col] = [];
      byCol[col].push(entry);
    });
    srcEdges.forEach(function (e) {
      if (!e || e.source == null || e.target == null) return;
      var s = String(e.source), t = String(e.target), w = Number(e.count != null ? e.count : (e.value != null ? e.value : 0));
      if (!outEdges[s]) outEdges[s] = [];
      outEdges[s].push({ target: t, weight: Number.isFinite(w) ? w : 0 });
    });

    var colKeys = Object.keys(byCol).map(Number).sort(function (a, b) { return a - b; });
    var rankById = Object.create(null), orderedCols = Object.create(null);
    if (!colKeys.length) return { nodes: [], columns: orderedCols, rankById: rankById };

    var lastCol = colKeys[colKeys.length - 1];
    var termList = byCol[lastCol].slice();
    if (cfg.preserveTerminalOrder !== true) {
      termList.sort(function (a, b) {
        var ra = a.raw && a.raw.rank != null && a.raw.rank !== '' && Number.isFinite(Number(a.raw.rank)) ? Number(a.raw.rank) : Infinity;
        var rb = b.raw && b.raw.rank != null && b.raw.rank !== '' && Number.isFinite(Number(b.raw.rank)) ? Number(b.raw.rank) : Infinity;
        if (ra !== rb) return ra - rb;
        if (b.count !== a.count) return b.count - a.count;
        return a.origIdx - b.origIdx;
      });
    }
    orderedCols[lastCol] = termList.map(function (e, i) { rankById[e.id] = i; return e.raw; });

    var startColIdx = cfg.sortSource ? 0 : 1;
    if (colKeys.length > 1 && startColIdx === 1) {
      orderedCols[colKeys[0]] = byCol[colKeys[0]].map(function (e, i) { rankById[e.id] = i; return e.raw; });
    }
    for (var ci = colKeys.length - 2; ci >= startColIdx; ci -= 1) {
      var ck = colKeys[ci], list = byCol[ck].slice();
      list.forEach(function (entry) {
        var outs = outEdges[entry.id] || [], bestRank = Infinity, bestWeight = -1;
        outs.forEach(function (edge) {
          var tr = Object.prototype.hasOwnProperty.call(rankById, edge.target) ? rankById[edge.target] : Infinity;
          if (!Number.isFinite(tr)) return;
          if (edge.weight > bestWeight || (edge.weight === bestWeight && tr < bestRank)) {
            bestWeight = edge.weight;
            bestRank = tr;
          }
        });
        entry.primaryTargetRank = bestRank;
      });
      list.sort(function (a, b) {
        if (a.primaryTargetRank !== b.primaryTargetRank) return a.primaryTargetRank - b.primaryTargetRank;
        if (b.count !== a.count) return b.count - a.count;
        return a.origIdx - b.origIdx;
      });
      orderedCols[ck] = list.map(function (e, i) { rankById[e.id] = i; return e.raw; });
    }

    var orderedNodes = [];
    colKeys.forEach(function (ck) { Array.prototype.push.apply(orderedNodes, orderedCols[ck]); });
    return { nodes: orderedNodes, columns: orderedCols, rankById: rankById };
  }

  /** Compute proportional vertical highlight bounds for a partially matched Sankey node bar. */
  function computeActiveSlice(nodeY, nodeH, nodeCount, matchedCount, ribbonOffsetY) {
    var y = Number(nodeY) || 0, h = Number(nodeH) || 0, tot = Number(nodeCount) || 0, m = Number(matchedCount) || 0;
    if (!Number.isFinite(h) || h <= 0 || !Number.isFinite(tot) || tot <= 0 || !Number.isFinite(m) || m <= 0) {
      return { isFullBar: false, sliceY: y, sliceH: 0 };
    }
    var ratio = Math.min(1, Math.max(0, m / tot));
    if (ratio >= 0.9999) return { isFullBar: true, sliceY: y, sliceH: h };
    var sliceH = Math.min(h, Math.max(1.5, h * ratio));
    var off = Number.isFinite(Number(ribbonOffsetY)) ? Math.max(0, Number(ribbonOffsetY)) : 0;
    var sliceY = y + Math.min(off, Math.max(0, h - sliceH));
    return { isFullBar: false, sliceY: Math.round(sliceY * 100) / 100, sliceH: Math.round(sliceH * 100) / 100 };
  }

  /** Deduplicate redundant 'brand · brand@' stems into clean single addresses. */
  function dedupeStemEmail(stem, localPart) {
    var s = String(stem || '').trim(), lp = String(localPart || '').trim();
    if (!s) return lp;
    if (!lp) return s;
    var lpHead = lp.split('@')[0].trim();
    var norm = function (v) { return String(v || '').toLowerCase().replace(/[^a-z0-9]/g, ''); };
    var ns = norm(s), nh = norm(lpHead);
    if (s.toLowerCase() === lp.toLowerCase() || s.toLowerCase() === lpHead.toLowerCase() || (ns.length >= 2 && ns === nh)) {
      return lp.indexOf('@') >= 0 ? lp : s;
    }
    return s + ' · ' + lp;
  }

  var api = {
    sortColumnsTopologically: sortColumnsTopologically,
    computeActiveSlice: computeActiveSlice,
    dedupeStemEmail: dedupeStemEmail,
  };
  root.QuietSankeyLayout = api;
  if (typeof module === 'object' && module.exports) module.exports = api;
}(typeof window !== 'undefined' ? window : globalThis));


/* Quiet UI v9.6.0 — Card Export (Chart/Table Toggle, Copy TSV, Copy for AI) & Civic Brief Controls */
(() => {
  if (typeof window === 'undefined' || typeof document === 'undefined' || !document || typeof document.addEventListener !== 'function' || window.__quietCardExportInit) return;
  window.__quietCardExportInit = true;

  let toggleSeq = 0;

  function writeClipboard(text) {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      return navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
    }
    return fallbackCopy(text);
  }

  function fallbackCopy(text) {
    return new Promise((resolve, reject) => {
      const prev = document.activeElement;
      const ta = document.createElement('textarea');
      try {
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.top = '0';
        ta.style.left = '0';
        ta.style.opacity = '0';
        ta.style.pointerEvents = 'none';
        document.body.appendChild(ta);
        ta.focus({ preventScroll: true });
        ta.select();
        ta.setSelectionRange(0, text.length);
        if (document.execCommand('copy')) resolve();
        else reject(new Error('Clipboard copy rejected'));
      } catch (err) {
        reject(err);
      } finally {
        ta.remove();
        if (prev && typeof prev.focus === 'function') prev.focus({ preventScroll: true });
      }
    });
  }

  function announceStatus(card, label, isErr, triggerBtn) {
    if (triggerBtn && triggerBtn.classList && triggerBtn.classList.contains('va-footer-copy-link')) {
      const txtEl = triggerBtn.querySelector('.va-copy-link-label') || triggerBtn;
      clearTimeout(triggerBtn._qeBtnTimer);
      txtEl.textContent = label;
      triggerBtn.classList.toggle('is-copied', !isErr);
      triggerBtn.classList.toggle('is-error', !!isErr);
      triggerBtn._qeBtnTimer = setTimeout(() => {
        txtEl.textContent = 'Copy for AI';
        triggerBtn.classList.remove('is-copied', 'is-error');
      }, 2800);
    }
    const status = card.querySelector('.va-copy-status, .qe-copy-status');
    if (!status) return;
    toggleSeq = (toggleSeq + 1) % 2;
    status.textContent = label + (toggleSeq ? '\u00A0' : '');
    status.classList.add('is-visible');
    status.classList.toggle('is-error', !!isErr);
    clearTimeout(status._qeTimer);
    status._qeTimer = setTimeout(() => {
      status.classList.remove('is-visible', 'is-error');
      status.textContent = '';
    }, 2800);
  }

  let syncScheduled = false;
  const _cueObserver = typeof ResizeObserver === 'function'
    ? new ResizeObserver((entries) => {
        entries.forEach((entry) => {
          const el = entry.target;
          el.classList.toggle('has-overflow', el.scrollWidth > el.clientWidth + 2);
        });
      })
    : null;

  function syncScrollCues() {
    syncScheduled = false;
    document.querySelectorAll('.va-diverging-scroll').forEach((el) => {
      if (_cueObserver && !el._qeObserved) {
        el._qeObserved = true;
        _cueObserver.observe(el);
      }
      el.classList.toggle('has-overflow', el.scrollWidth > el.clientWidth + 2);
    });
  }

  function scheduleSyncScrollCues() {
    if (syncScheduled) return;
    syncScheduled = true;
    safeRaf(syncScrollCues);
  }

  const safeRaf = (fn) => (typeof requestAnimationFrame === 'function' ? requestAnimationFrame(fn) : setTimeout(fn, 0));

  function setCardMode(card, mode) {
    const chartPanel = card.querySelector('.va-card-chart-panel');
    const tablePanel = card.querySelector('.va-card-table-panel');
    const btnChart = card.querySelector('[data-qe-view="chart"]');
    const btnTable = card.querySelector('[data-qe-view="table"]');
    const edToggle = card.querySelector('[data-qe-editorial-toggle]');
    if (!chartPanel || !tablePanel) return;
    const showTable = mode === 'table';
    chartPanel.hidden = showTable;
    if (showTable) {
      tablePanel.removeAttribute('hidden');
    } else {
      tablePanel.setAttribute('hidden', 'until-found');
    }
    if (btnChart) {
      btnChart.setAttribute('aria-pressed', showTable ? 'false' : 'true');
      btnChart.classList.toggle('is-active', !showTable);
    }
    if (btnTable) {
      btnTable.setAttribute('aria-pressed', showTable ? 'true' : 'false');
      btnTable.classList.toggle('is-active', showTable);
    }
    if (edToggle) {
      edToggle.textContent = showTable ? 'Show chart' : 'Show data table';
      const targetId = showTable ? chartPanel.id : tablePanel.id;
      if (targetId) edToggle.setAttribute('aria-controls', targetId);
    }
    if (!showTable && window.QuietEChartsAdapter && typeof window.QuietEChartsAdapter.refresh === 'function') {
      safeRaf(() => window.QuietEChartsAdapter.refresh(card.ownerDocument || document));
    }
    scheduleSyncScrollCues();
  }

  function readPayload(card) {
    const el = card.querySelector('script.qe-export-payload');
    if (!el) return null;
    try { return JSON.parse(el.textContent || '{}'); } catch (_err) { return null; }
  }

  document.addEventListener('beforematch', (e) => {
    const panel = e.target && e.target.closest ? e.target.closest('.va-card-table-panel') : null;
    if (!panel) return;
    const card = panel.closest('.qe-figure, .va-figure-card');
    if (card) setCardMode(card, 'table');
  });

  document.addEventListener('click', (e) => {
    if (!e.target || typeof e.target.closest !== 'function') return;
    const viewBtn = e.target.closest('[data-qe-view]');
    if (viewBtn) {
      const card = viewBtn.closest('.qe-figure, .va-figure-card');
      if (card) setCardMode(card, viewBtn.getAttribute('data-qe-view'));
      return;
    }

    const edBtn = e.target.closest('[data-qe-editorial-toggle], [data-qe-editorial-return]');
    if (edBtn) {
      const card = edBtn.closest('.qe-figure, .va-figure-card');
      if (!card) return;
      if (edBtn.hasAttribute('data-qe-editorial-return')) {
        setCardMode(card, 'chart');
        const mainToggle = card.querySelector('[data-qe-editorial-toggle]');
        if (mainToggle && mainToggle.focus) mainToggle.focus();
      } else {
        const tblPanel = card.querySelector('.va-card-table-panel');
        const isTableOpen = Boolean(tblPanel && !tblPanel.hasAttribute('hidden'));
        setCardMode(card, isTableOpen ? 'chart' : 'table');
      }
      return;
    }

    const copyBtn = e.target.closest('[data-qe-copy]');
    if (copyBtn) {
      const card = copyBtn.closest('.qe-figure, .va-figure-card');
      if (!card) return;
      const payload = readPayload(card);
      if (!payload) return;
      const kind = copyBtn.getAttribute('data-qe-copy');
      const text = kind === 'ai' ? (payload.markdown || payload.tsv || '') : (payload.tsv || '');
      if (!text) return;
      writeClipboard(text).then(
        () => announceStatus(card, kind === 'ai' ? 'Copied for AI' : 'Copied data', false, copyBtn),
        () => announceStatus(card, 'Copy failed', true, copyBtn),
      );
      return;
    }

    const hexTile = e.target.closest('.va-hex-tile');
    if (hexTile) {
      activateHexTile(hexTile);
      return;
    }

    const scopeBtn = e.target.closest('[data-v22-scope]');
    if (scopeBtn) {
      const root = scopeBtn.closest('.va-question-brief');
      applyBriefScope(root, scopeBtn.getAttribute('data-v22-scope'));
    }
  });

  document.addEventListener('change', (e) => {
    const sel = e.target && e.target.closest ? e.target.closest('[data-v22-scope-select]') : null;
    if (!sel) return;
    applyBriefScope(sel.closest('.va-question-brief'), sel.value);
  });

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const hexTile = e.target && e.target.closest ? e.target.closest('.va-hex-tile') : null;
    if (hexTile) {
      e.preventDefault();
      activateHexTile(hexTile);
    }
  });

  function updateHexRing(svg, tile) {
    const ring = svg ? svg.querySelector('.va-hex-focus-ring') : null;
    if (!ring) return;
    const poly = tile ? tile.querySelector('polygon') : null;
    const pts = poly ? poly.getAttribute('points') : '';
    if (pts) {
      ring.setAttribute('points', pts);
      ring.removeAttribute('visibility');
    } else {
      ring.setAttribute('points', '');
      ring.setAttribute('visibility', 'hidden');
    }
  }

  function activateHexTile(tile) {
    const stage = tile.closest('.va-figure-card, .qe-figure, .va-hex-stage') || tile.parentElement;
    if (!stage) return;
    stage.querySelectorAll('.va-hex-tile.is-selected').forEach((n) => n.classList.remove('is-selected'));
    tile.classList.add('is-selected');
    updateHexRing(tile.closest('svg'), tile);
    const card = tile.closest('.va-figure-card, .qe-figure') || stage.parentElement;
    const ro = card ? card.querySelector('.va-hex-readout') : null;
    if (ro) {
      const nm = tile.getAttribute('data-state-name') || '';
      const ab = tile.getAttribute('data-state') || '';
      const fv = tile.getAttribute('data-full-value') || tile.getAttribute('data-value') || '';
      const note = tile.getAttribute('data-note') || '';
      ro.textContent = `${nm} (${ab}): ${fv}${note ? ' · ' + note : ''}`;
    }
  }

  function applyBriefScope(root, scope) {
    if (!root || !scope) return;
    const sel = root.querySelector('[data-v22-scope-select]');
    if (sel && sel.value !== scope) sel.value = scope;
    root.querySelectorAll('[data-v22-scope]').forEach((b) => {
      const on = b.getAttribute('data-v22-scope') === scope;
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
      b.classList.toggle('is-active', on);
    });
    const payloadEl = root.querySelector('script.v22-scope-payload');
    if (!payloadEl) return;
    let scopes = {};
    try { scopes = JSON.parse(payloadEl.textContent || '{}'); } catch (_err) { return; }
    const d = scopes[scope];
    if (!d) return;
    const lead = root.querySelector('[data-v22-lead]');
    if (lead) {
      const span = document.createElement('span');
      span.className = 'va-lead-highlight';
      span.textContent = d.lead_clause || '';
      lead.replaceChildren(span, document.createTextNode(' ' + (d.lead_rest || '')));
    }
    const callouts = root.querySelectorAll('[data-v22-callout]');
    const stats = Array.isArray(d.callouts) ? d.callouts : [];
    callouts.forEach((box, idx) => {
      const s = stats[idx];
      if (!s) return;
      const numEl = box.querySelector('.va-callout-num');
      const descEl = box.querySelector('.va-callout-desc');
      if (numEl) numEl.textContent = s.num || '';
      if (descEl) descEl.textContent = s.desc || '';
    });
    if (d.focus_state) {
      const tile = Array.from(root.querySelectorAll('.va-hex-tile')).find((el) => el.getAttribute('data-state') === d.focus_state);
      if (tile) activateHexTile(tile);
    } else {
      root.querySelectorAll('.va-hex-tile.is-selected').forEach((n) => n.classList.remove('is-selected'));
      updateHexRing(root.querySelector('.va-hex-map-svg'), null);
      const ro = root.querySelector('#v22-map .va-hex-readout, .va-hex-readout');
      if (ro) {
        const msg = d.focus_summary || '';
        const idx = msg.indexOf(' · Select ');
        if (idx >= 0) {
          const sp = document.createElement('span');
          sp.className = 'va-hex-prompt';
          sp.textContent = msg.slice(idx);
          ro.replaceChildren(document.createTextNode(msg.slice(0, idx)), sp);
        } else {
          const sp = document.createElement('span');
          sp.className = 'va-hex-prompt';
          sp.textContent = msg || 'Select any state hex tile to inspect exact rate and bin.';
          ro.replaceChildren(sp);
        }
      }
    }
  }

  if (typeof window.addEventListener === 'function') window.addEventListener('resize', scheduleSyncScrollCues, { passive: true });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', scheduleSyncScrollCues);
  else scheduleSyncScrollCues();
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(scheduleSyncScrollCues);
  const obsRoot = document.body || document.documentElement;
  if (typeof MutationObserver === 'function' && obsRoot) {
    new MutationObserver(scheduleSyncScrollCues).observe(obsRoot, { childList: true, subtree: true });
  }
})();


/* SPDX-License-Identifier: Apache-2.0 */
/* Quiet UI v9.7.0 — Edge-to-Edge Alarm Excursion Trace & Card Synchronization */
(function (global) {
  'use strict';

  var HEADER_META = Object.assign(Object.create(null), {
    nominal: { label: 'ALL SYSTEMS NOMINAL', state: 'nominal' },
    approaching: { label: 'APPROACHING LIMIT', state: 'warn' },
    unack: { label: '1 UNACK ALARM', state: 'fault' },
    ack: { label: '1 LATCHED FAULT', state: 'fault' }
  });

  function escHtml(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function fmtNum(v, dec) {
    var num = Number(v);
    if (!isFinite(num)) return '--';
    var d = (typeof dec === 'number' && isFinite(dec)) ? Math.max(0, Math.min(6, Math.round(dec))) : 1;
    return num.toFixed(d);
  }

  function computeExcursion(val, cfg) {
    var th = Number(cfg.threshold);
    var diff = val - th;
    var crossed = cfg.direction === 'below' ? val < th : val > th;
    var sign = diff >= 0 ? '+' : '';
    return { crossed: crossed, diff: diff, deltaStr: sign + fmtNum(diff, cfg.decimals) + ' ' + cfg.unit };
  }

  function resolveSampleAt(cfg, ph, elapsedMs) {
    var nom = Number(cfg.nominalStart), th = Number(cfg.threshold), peak = Number(cfg.breachPeak);
    var ackVal = (typeof cfg.ackValue === 'number' && isFinite(cfg.ackValue)) ? Number(cfg.ackValue) : (th + (peak - th) * 0.65);
    var span = th - nom;
    if (ph === 'nominal') {
      return nom + Math.sin(elapsedMs / 380) * Math.max(Math.abs(span) * 0.08, 0.002);
    }
    if (ph === 'approaching') {
      var af = Math.min(0.95, Math.max(0.15, (elapsedMs - 2000) / 2000));
      return nom + span * (0.35 + af * 0.62);
    }
    if (ph === 'unack') {
      var bf = Math.min(1, Math.max(0.28, (elapsedMs - 4000) / 3400));
      return th + (peak - th) * bf + Math.sin(elapsedMs / 420) * Math.abs(peak - th) * 0.05;
    }
    return ackVal;
  }

  function buildPhaseSeries(cfg, ph, elapsedMs) {
    var nom = Number(cfg.nominalStart), th = Number(cfg.threshold), peak = Number(cfg.breachPeak);
    var n = 34, arr = [];
    var span = th - nom, exc = peak - th;
    var seed = Number(elapsedMs || 0) / 520;
    var tail = resolveSampleAt(cfg, ph, Number(elapsedMs || 0));
    var ripNom = Math.max(Math.abs(span) * 0.06, Math.abs(th) * 0.0004 || 0.01);
    var ripExc = Math.max(Math.abs(exc) * 0.07, ripNom);
    for (var i = 0; i < n; i++) {
      var wave = Math.sin(i * 0.72 + seed) * 0.55 + Math.cos(i * 1.45 + seed * 0.6) * 0.45;
      var v;
      if (ph === 'nominal') {
        v = nom + wave * ripNom;
      } else if (ph === 'approaching') {
        if (i < 20) {
          v = nom + wave * ripNom;
        } else {
          var tApp = (i - 19) / (n - 20);
          v = nom + (tail - nom) * tApp + wave * ripNom * 0.5;
          if ((cfg.direction === 'below' && v <= th) || (cfg.direction !== 'below' && v >= th)) {
            v = th + (cfg.direction === 'below' ? 1 : -1) * Math.max(Math.abs(span) * 0.02, 0.002);
          }
        }
      } else {
        if (i <= 13) {
          v = nom + wave * ripNom;
        } else if (i <= 21) {
          var tRamp = (i - 13) / 8.5;
          v = nom + span * (0.1 + tRamp * 0.87) + wave * ripNom * 0.4;
          if ((cfg.direction === 'below' && v <= th) || (cfg.direction !== 'below' && v >= th)) {
            v = th + (cfg.direction === 'below' ? 1 : -1) * Math.max(Math.abs(span) * 0.015, 0.001);
          }
        } else if (ph === 'unack') {
          var uFrac = (i - 21) / (n - 22);
          var dip = Math.sin(uFrac * Math.PI * 0.82);
          v = th + exc * (0.32 + 0.68 * Math.min(1, uFrac * 0.85 + dip * 0.25)) + wave * ripExc;
        } else {
          var aFrac = (i - 21) / (n - 22);
          v = aFrac < 0.55 ? (th + exc * (0.35 + aFrac * 1.1) + wave * ripExc * 0.5) : (peak + (tail - peak) * ((aFrac - 0.55) / 0.45));
        }
      }
      arr.push(v);
    }
    arr[n - 1] = tail;
    return arr;
  }

  function computeScaleAndGrid(cfg, series) {
    var th = Number(cfg.threshold);
    var vals = series.concat([th, Number(cfg.nominalStart), Number(cfg.breachPeak)]);
    var lo = Math.min.apply(null, vals), hi = Math.max.apply(null, vals);
    var rawSpan = Math.max(hi - lo, Math.abs(th) * 0.004 || 0.5);
    var pad = rawSpan * 0.16;
    if (global.QuietSvgLayout && typeof global.QuietSvgLayout.niceScale125 === 'function') {
      var sc = global.QuietSvgLayout.niceScale125(lo - pad, hi + pad, { targetTicks: 4, includeZero: false });
      return sc;
    }
    var yMin = lo - pad, yMax = hi + pad;
    var step = (yMax - yMin) / 4;
    return { min: yMin, max: yMax, step: step, ticks: [yMin, yMin + step, yMin + step * 2, yMin + step * 3, yMax] };
  }

  function buildBreachPolygon(series, th, dir, mapX, mapY, yTh) {
    var n = series.length;
    if (n < 2) return { areaPath: '', crossX: null };
    var isHit = function (v) { return dir === 'below' ? v < th : v > th; };
    var polyPts = [], segs = [], curRun = null, firstCrossX = null;
    for (var i = 0; i < n; i++) {
      var v1 = series[i], h1 = isHit(v1), x1 = mapX(i, n), y1 = mapY(v1);
      if (i > 0) {
        var v0 = series[i - 1], h0 = isHit(v0), x0 = mapX(i - 1, n);
        if (h0 !== h1) {
          var t = (th - v0) / ((v1 - v0) || 1e-9);
          var xc = x0 + Math.max(0, Math.min(1, t)) * (x1 - x0);
          if (h1) {
            if (firstCrossX === null) firstCrossX = xc;
            curRun = [[xc, yTh]];
          } else if (curRun) {
            curRun.push([xc, yTh]);
            segs.push(curRun);
            curRun = null;
          }
        }
      } else if (h1) {
        if (firstCrossX === null) firstCrossX = x1;
        curRun = [[x1, yTh]];
      }
      if (h1 && curRun) curRun.push([x1, y1]);
      polyPts.push(x1.toFixed(1) + ',' + y1.toFixed(1));
    }
    if (curRun && curRun.length > 0) {
      curRun.push([mapX(n - 1, n), yTh]);
      segs.push(curRun);
    }
    var areaPath = segs.map(function (run) {
      var d = run.map(function (p, idx) { return (idx === 0 ? 'M' : 'L') + p[0].toFixed(1) + ',' + p[1].toFixed(1); }).join(' ');
      return '<path d="' + d + ' Z" fill="var(--status-err)" fill-opacity="0.18" stroke="none"/>';
    }).join('');
    return { areaPath: areaPath, crossX: firstCrossX, polyLine: polyPts.join(' ') };
  }

  function buildXLabels(ML, PW, W, MR, H, crossX) {
    var placed = [{ x: ML, text: '-12s', anchor: 'start', fill: 'var(--text-muted)', weight: '500' }];
    var bx = crossX !== null ? Math.max(ML + 74, Math.min(W - MR - 88, crossX)) : null;
    if (W >= 540) {
      var x8 = ML + PW * 0.24, x4 = ML + PW * 0.46;
      if ((x8 - ML) >= 68 && (bx === null || (bx - x8) >= 90)) {
        placed.push({ x: x8, text: '-8s', anchor: 'middle', fill: 'var(--text-muted)', weight: '500' });
      }
      if ((x4 - placed[placed.length - 1].x) >= 68 && (bx === null || (bx - x4) >= 88)) {
        placed.push({ x: x4, text: '-4s', anchor: 'middle', fill: 'var(--text-muted)', weight: '500' });
      }
    }
    if (bx !== null) {
      placed.push({ x: bx, text: '00:00 BREACH', anchor: 'middle', fill: 'var(--status-err)', weight: '700' });
    }
    placed.push({ x: W - MR, text: 'LIVE', anchor: 'end', fill: 'var(--status-err)', weight: '700' });
    return placed.map(function (it) {
      return '<text x="' + it.x.toFixed(1) + '" y="' + (H - 7) + '" text-anchor="' + it.anchor + '" font-family="var(--font-mono)" font-size="11" font-weight="' + it.weight + '" fill="' + it.fill + '">' + it.text + '</text>';
    }).join('');
  }

  function buildFocusSvg(cfg, phase, series, containerWidth) {
    var W = Math.max(460, Math.min(1120, Math.round(Number(containerWidth) || 960)));
    var H = 192, ML = 64, MR = 24, MT = 22, MB = 28;
    var PW = W - ML - MR, PH = H - MT - MB;
    var pts = (Array.isArray(series) && series.length >= 12) ? series : buildPhaseSeries(cfg, phase || 'unack', 4400);
    var sc = computeScaleAndGrid(cfg, pts);
    var yMin = sc.min, yMax = sc.max, th = Number(cfg.threshold), n = pts.length;
    var mapX = function (idx, total) { return ML + (total <= 1 ? PW : (idx / (total - 1)) * PW); };
    var mapY = function (v) { return MT + PH - ((v - yMin) / (yMax - yMin || 1)) * PH; };
    var yTh = mapY(th);
    var breach = buildBreachPolygon(pts, th, cfg.direction, mapX, mapY, yTh);
    var decGrid = (sc.step && sc.step < 0.05) ? 3 : ((sc.step && sc.step < 0.5) ? 2 : cfg.decimals);
    var gridHtml = (sc.ticks || []).filter(function (tv) {
      var ty = mapY(tv);
      return ty >= MT + 4 && ty <= MT + PH - 4;
    }).map(function (tv) {
      var ty = mapY(tv).toFixed(1);
      return '<line x1="' + ML + '" y1="' + ty + '" x2="' + (W - MR) + '" y2="' + ty + '" stroke="var(--border-hairline)" stroke-width="1"/>' +
        '<text x="' + (ML - 8) + '" y="' + (Number(ty) + 3.5).toFixed(1) + '" text-anchor="end" font-family="var(--font-mono)" font-size="11" fill="var(--text-muted)">' + fmtNum(tv, decGrid) + '</text>';
    }).join('');
    var crossPin = '';
    if (breach.crossX !== null) {
      var pinX = breach.crossX;
      var pinLblX = Math.max(ML + 68, Math.min(W - MR - 68, pinX));
      crossPin = '<line x1="' + pinX.toFixed(1) + '" y1="' + (MT + 2) + '" x2="' + pinX.toFixed(1) + '" y2="' + (MT + PH) + '" stroke="var(--status-err)" stroke-width="1.5" stroke-dasharray="4 3"/>' +
        '<circle cx="' + pinX.toFixed(1) + '" cy="' + yTh.toFixed(1) + '" r="4" fill="var(--status-err)" stroke="var(--bg-surface)" stroke-width="1.5"/>' +
        '<text x="' + pinLblX.toFixed(1) + '" y="' + (MT - 5) + '" text-anchor="middle" font-family="var(--font-sans)" font-size="11" font-weight="700" fill="var(--status-err)" paint-order="stroke fill" stroke="var(--bg-surface)" stroke-width="3.5" stroke-linejoin="round">Threshold Crossed</text>';
    }
    var strokeClr = phase === 'nominal' ? 'var(--accent-primary)' : (phase === 'approaching' ? 'var(--status-warn)' : 'var(--status-err)');
    var lastX = mapX(n - 1, n).toFixed(1), lastY = mapY(pts[n - 1]).toFixed(1);
    var limSideLeft = breach.crossX === null || breach.crossX > ML + PW * 0.42;
    var limX = limSideLeft ? (ML + 8) : (W - MR - 8);
    var limAnc = limSideLeft ? 'start' : 'end';
    var limY = (cfg.direction === 'below' || yTh > MT + PH * 0.55) ? Math.max(MT + 13, yTh - 6) : Math.min(MT + PH - 6, yTh + 13);
    return '<svg class="va-alarm-focus-svg" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="' + escHtml(cfg.paramLabel) + ' full-width excursion trace">' +
      '<rect x="' + ML + '" y="' + MT + '" width="' + PW + '" height="' + PH + '" fill="var(--bg-elevated)" rx="3"/>' +
      gridHtml + breach.areaPath +
      '<line x1="' + ML + '" y1="' + yTh.toFixed(1) + '" x2="' + (W - MR) + '" y2="' + yTh.toFixed(1) + '" stroke="var(--status-warn)" stroke-width="1.5" stroke-dasharray="5 4"/>' +
      crossPin +
      '<text x="' + limX.toFixed(1) + '" y="' + limY.toFixed(1) + '" text-anchor="' + limAnc + '" font-family="var(--font-mono)" font-size="11" font-weight="700" fill="var(--status-warn)" paint-order="stroke fill" stroke="var(--bg-elevated)" stroke-width="3.5" stroke-linejoin="round">Limit ' + fmtNum(th, cfg.decimals) + ' ' + escHtml(cfg.unit) + '</text>' +
      '<polyline fill="none" stroke="' + strokeClr + '" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round" points="' + (breach.polyLine || '') + '"/>' +
      '<circle cx="' + lastX + '" cy="' + lastY + '" r="4.5" fill="' + strokeClr + '" stroke="var(--bg-surface)" stroke-width="1.5"/>' +
      buildXLabels(ML, PW, W, MR, H, breach.crossX) +
      '</svg>';
  }

  function syncV08Card(card, inst, phMeta) {
    var cfg = inst.cfg, ph = inst.phase, val = inst.val;
    var valEl = card.querySelector('.v08-kpi-val'), pill = card.querySelector('.v08-kpi-head .va-pill'), subEl = card.querySelector('.v08-kpi-target');
    if (valEl) valEl.textContent = fmtNum(val, cfg.decimals) + ' ' + cfg.unit;
    if (pill) {
      pill.setAttribute('data-state', phMeta.state);
      pill.textContent = ph === 'nominal' ? 'LOCK ±0.02 Hz' : (ph === 'approaching' ? 'APPROACHING LIMIT' : (ph === 'unack' ? 'ACTIVE ALARM' : 'LATCHED PEAK ' + fmtNum(cfg.breachPeak, cfg.decimals) + ' ' + cfg.unit));
    }
    if (subEl) {
      var rateTxt = (inst.rate >= 0 ? '+' : '') + fmtNum(inst.rate, cfg.decimals) + ' ' + cfg.unit + '/s';
      var pkExc = computeExcursion(Number(cfg.breachPeak), cfg);
      subEl.textContent = ph === 'nominal'
        ? ('Reference 60.000 Hz · Limit ' + fmtNum(cfg.threshold, cfg.decimals) + ' ' + cfg.unit)
        : (ph === 'approaching'
          ? ('Rate ' + rateTxt + ' · Limit ' + fmtNum(cfg.threshold, cfg.decimals) + ' ' + cfg.unit)
          : ('Peak ' + fmtNum(cfg.breachPeak, cfg.decimals) + ' ' + cfg.unit + ' (' + pkExc.deltaStr + ') · Limit ' + fmtNum(cfg.threshold, cfg.decimals) + ' ' + cfg.unit));
    }
    var vis = card.querySelector('.v08-kpi-visual svg');
    if (vis && inst.series && inst.series.length > 2) {
      var col = ph === 'nominal' ? 'var(--accent-primary)' : (ph === 'approaching' ? 'var(--status-warn)' : 'var(--status-err)');
      var lo = 59.72, hi = 60.06, normPts = inst.series.slice(-12);
      var xs = normPts.map(function (_v, idx) { return 8 + (idx / (normPts.length - 1)) * 464; });
      var ys = normPts.map(function (v) { var t = Math.max(0.05, Math.min(0.95, (v - lo) / (hi - lo))); return 31 - t * 23; });
      var pl = vis.querySelector('polyline'), cr = vis.querySelector('circle'), bar = vis.querySelectorAll('rect')[1];
      if (pl) { pl.setAttribute('points', xs.map(function (x, i) { return x.toFixed(1) + ',' + ys[i].toFixed(1); }).join(' ')); pl.setAttribute('stroke', col); }
      if (cr) { cr.setAttribute('cx', xs[xs.length - 1].toFixed(1)); cr.setAttribute('cy', ys[ys.length - 1].toFixed(1)); cr.setAttribute('fill', col); }
      if (bar) {
        var fw = Math.max(4, Math.min(464, ((val - lo) / (hi - lo)) * 464));
        bar.setAttribute('width', fw.toFixed(1)); bar.setAttribute('fill', col);
      }
    }
  }

  function syncScalarCard(card, inst, phMeta) {
    var cfg = inst.cfg, ph = inst.phase, val = inst.val;
    var valEl = card.querySelector('.qe-scalar-val');
    if (valEl) {
      if (card.dataset.vaUnc === undefined) {
        var m = (valEl.textContent || '').match(/(±\s*[0-9.]+)/);
        card.dataset.vaUnc = m ? m[1] : '';
      }
      var unc = card.dataset.vaUnc;
      valEl.textContent = fmtNum(val, cfg.decimals) + (unc ? ' ' + unc : '') + ' ' + cfg.unit;
    }
    var pill = card.querySelector('.qe-scalar-disp .va-pill');
    if (pill) {
      pill.setAttribute('data-state', phMeta.state);
      pill.textContent = ph === 'nominal' ? 'Nominal' : (ph === 'approaching' ? 'CAUTION' : (ph === 'unack' ? 'TRIPWIRE' : 'LATCHED FAULT'));
    }
    var marg = card.querySelector('.qe-scalar-margin');
    if (marg) {
      var nom = Number(cfg.nominalStart), th = Number(cfg.threshold), den = Math.abs(nom - th) || 1;
      var remPct = ((cfg.direction === 'below' ? (val - th) : (th - val)) / den) * 100;
      marg.textContent = 'Margin ' + (remPct >= 0 ? '+' : '') + remPct.toFixed(1) + '%';
    }
    var svg = card.querySelector('svg.qe-gauge-svg');
    if (svg && typeof cfg.gaugeMin === 'number' && typeof cfg.gaugeMax === 'number') {
      var tPos = Math.max(0, Math.min(1, (val - cfg.gaugeMin) / ((cfg.gaugeMax - cfg.gaugeMin) || 1)));
      var ax = 24 + tPos * 292, fillCol = ph === 'nominal' ? 'var(--status-ok)' : (ph === 'approaching' ? 'var(--status-warn)' : 'var(--status-danger)');
      var polys = svg.querySelectorAll('polygon'), actPin = polys[polys.length - 1];
      if (actPin) {
        actPin.setAttribute('points', ax.toFixed(1) + ',27.0 ' + (ax - 4.5).toFixed(1) + ',39.5 ' + (ax + 4.5).toFixed(1) + ',39.5');
        actPin.setAttribute('fill', fillCol);
      }
      svg.querySelectorAll('text').forEach(function (tx) {
        if ((tx.textContent || '').indexOf('ACT') === 0) {
          tx.textContent = 'ACT\u00a0' + fmtNum(val, cfg.decimals) + ' ' + cfg.unit;
          tx.setAttribute('fill', fillCol);
          var anc = ax < 80 ? 'start' : (ax > 260 ? 'end' : 'middle');
          tx.setAttribute('text-anchor', anc);
          tx.setAttribute('x', Math.max(8, Math.min(332, ax)).toFixed(1));
        }
      });
    }
  }

  function syncTopbar(doc, inst, phMeta) {
    var bar = doc.querySelector('#va-shell-topbar .va-shell-topbar-status');
    if (!bar) return;
    var cfg = inst.cfg, ph = inst.phase;
    var pills = bar.querySelectorAll('.va-pill[data-variant="status"]');
    var metrics = bar.querySelectorAll('.va-topbar-metric');
    if (cfg.viewId === 'v01-icu-bedside-terminal') {
      if (pills[0]) { pills[0].setAttribute('data-state', phMeta.state); pills[0].textContent = phMeta.label; }
      if (metrics[0]) { metrics[0].setAttribute('data-state', phMeta.state); metrics[0].textContent = 'MAP ' + fmtNum(inst.val, cfg.decimals) + ' ' + cfg.unit; }
    } else if (cfg.viewId === 'v07-grid-scada-poi-console') {
      var lastPill = pills[pills.length - 1];
      if (lastPill) { lastPill.setAttribute('data-state', phMeta.state); lastPill.textContent = phMeta.label; }
      var freqMetric = metrics[1] || metrics[0];
      if (freqMetric) { freqMetric.setAttribute('data-state', phMeta.state); freqMetric.textContent = fmtNum(ph === 'unack' || ph === 'ack' ? inst.val : cfg.nominalStart, cfg.decimals) + ' ' + cfg.unit; }
    } else if (pills.length) {
      pills[0].setAttribute('data-state', phMeta.state);
      pills[0].textContent = phMeta.label;
    }
  }

  function syncBoundUI(host, inst) {
    var doc = inst.doc || global.document;
    if (!doc) return;
    var cfg = inst.cfg, ph = inst.phase;
    var phMeta = HEADER_META[ph] || HEADER_META.nominal;
    doc.querySelectorAll('[data-alarm-header-pill]').forEach(function (hp) {
      hp.setAttribute('data-state', phMeta.state);
      hp.textContent = phMeta.label;
    });
    syncTopbar(doc, inst, phMeta);
    var rateTxt = (inst.rate >= 0 ? '+' : '') + fmtNum(inst.rate, cfg.decimals) + ' ' + cfg.unit + '/s';
    host.querySelectorAll('[data-alarm-fault-target="1"]').forEach(function (card) {
      if (card.classList.contains('v08-kpi-card')) {
        syncV08Card(card, inst, phMeta);
      } else if (card.classList.contains('qe-scalar-card')) {
        syncScalarCard(card, inst, phMeta);
      } else if (card.classList.contains('v9-kpi-tile')) {
        var kv = card.querySelector('.v9-kpi-val'), ks = card.querySelector('.v9-kpi-sub');
        var dVal = ph === 'ack' ? Number(cfg.breachPeak) : inst.val;
        if (kv) { kv.textContent = fmtNum(dVal, cfg.decimals) + ' ' + cfg.unit; kv.setAttribute('data-tone', ph === 'nominal' ? '' : (ph === 'approaching' ? 'warn' : 'danger')); }
        if (ks) {
          var th = Number(cfg.threshold);
          ks.textContent = ph === 'nominal' ? ('SLO Ceiling: ' + fmtNum(th, 1) + ' ms (Normal)') :
            (ph === 'approaching' ? ('Approaching ' + fmtNum(th, 1) + ' ms (' + rateTxt + ')') :
              (ph === 'unack' ? ('BREACH ACTIVE (+' + fmtNum(dVal - th, 1) + ' ms over SLO)') : ('Latched Peak: +' + fmtNum(dVal - th, 1) + ' ms above ' + fmtNum(th, 1) + ' ms')));
        }
      } else if (card.classList.contains('v9-demo-subcard')) {
        var sp = card.querySelector('.va-pill');
        var uSuf = cfg.unit && cfg.unit.charAt(0) === '%' ? '%' : (' ' + (cfg.unit || ''));
        if (sp) { sp.setAttribute('data-state', phMeta.state); sp.textContent = ph === 'ack' ? ('LATCHED · ' + fmtNum(cfg.breachPeak, cfg.decimals) + uSuf) : phMeta.label; }
      }
    });
  }

  global.QuietAlarmTrace = {
    escHtml: escHtml,
    fmtNum: fmtNum,
    computeExcursion: computeExcursion,
    resolveSampleAt: resolveSampleAt,
    buildPhaseSeries: buildPhaseSeries,
    buildFocusSvg: buildFocusSvg,
    syncBoundUI: syncBoundUI
  };
})(typeof window !== 'undefined' ? window : this);


/* SPDX-License-Identifier: Apache-2.0 */
/* Quiet UI v9.7.0 — Reusable 4-Phase Automated Alarm Lifecycle Controller */
(function (global) {
  'use strict';

  var INSTANCES = [];
  var PHASES = Object.assign(Object.create(null), { nominal: 1, approaching: 2, unack: 3, ack: 4 });

  function getTrace() {
    return global.QuietAlarmTrace || {};
  }

  function hasPhase(k) {
    return typeof k === 'string' && Object.prototype.hasOwnProperty.call(PHASES, k);
  }

  function escHtml(s) {
    return getTrace().escHtml ? getTrace().escHtml(s) : String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function fmtNum(v, dec) {
    if (getTrace().fmtNum) return getTrace().fmtNum(v, dec);
    var num = Number(v);
    if (!isFinite(num)) return '--';
    var d = (typeof dec === 'number' && isFinite(dec)) ? Math.max(0, Math.min(6, Math.round(dec))) : 1;
    return num.toFixed(d);
  }

  function fmtDuration(secTotal) {
    var s = Math.max(0, Math.floor(secTotal));
    var m = Math.floor(s / 60), r = s % 60;
    return (m < 10 ? '0' : '') + m + 'm ' + (r < 10 ? '0' : '') + r + 's';
  }

  function resolveOverride(host, doc) {
    var attr = host.getAttribute('data-alarm-override') || (doc && doc.documentElement && doc.documentElement.getAttribute('data-alarm-override'));
    if (hasPhase(attr)) return attr;
    try {
      var q1 = new URLSearchParams(global.location.search || '').get('alarm');
      if (hasPhase(q1)) return q1;
    } catch (_e) {}
    try {
      if (global.parent && global.parent !== global) {
        var q2 = new URLSearchParams(global.parent.location.search || '').get('alarm');
        if (hasPhase(q2)) return q2;
      }
    } catch (_e2) {}
    return '';
  }

  function computeExcursion(val, cfg) {
    if (getTrace().computeExcursion) return getTrace().computeExcursion(val, cfg);
    var th = Number(cfg.threshold), diff = val - th;
    return { crossed: cfg.direction === 'below' ? val < th : val > th, diff: diff, deltaStr: (diff >= 0 ? '+' : '') + fmtNum(diff, cfg.decimals) + ' ' + cfg.unit };
  }

  function sampleForPhase(cfg, ph, elapsedMs) {
    var nom = Number(cfg.nominalStart), th = Number(cfg.threshold), peak = Number(cfg.breachPeak);
    var val = getTrace().resolveSampleAt ? getTrace().resolveSampleAt(cfg, ph, elapsedMs) : nom;
    var rate = ph === 'nominal' ? (cfg.direction === 'below' ? -0.05 : 0.05) :
      (ph === 'approaching' ? ((th - nom) / 2.0) : (ph === 'unack' ? ((peak - th) / 2.2) : 0));
    return { val: val, rate: rate };
  }

  function measureChartWidth(host, el) {
    var slot = el ? el.querySelector('[data-alarm-svg-slot]') : null;
    var w = (slot && slot.clientWidth > 120) ? (slot.clientWidth - 20) : (host.clientWidth > 120 ? (host.clientWidth - 60) : 960);
    return Math.max(460, Math.min(1120, w));
  }

  function buildFocusSvgForHost(host, el, cfg, phase, series) {
    var T = getTrace();
    var w = measureChartWidth(host, el);
    return T.buildFocusSvg ? T.buildFocusSvg(cfg, phase, series, w) : '';
  }

  function renderTakeover(host, inst) {
    var el = host.querySelector('[data-alarm-takeover]');
    if (!el) return;
    var cfg = inst.cfg;
    var exc = computeExcursion(inst.val, cfg);
    var rateTxt = (inst.rate >= 0 ? '+' : '') + fmtNum(inst.rate, cfg.decimals) + ' ' + cfg.unit + '/s';
    var boundTxt = (cfg.direction === 'below' ? '>= ' : '<= ') + fmtNum(cfg.threshold, cfg.decimals) + ' ' + cfg.unit;
    var sibHtml = (cfg.siblings || []).map(function (s) {
      return '<span class="va-alarm-sibling-chip"><span class="va-alarm-sibling-dot" aria-hidden="true"></span><strong>' + escHtml(s.label) + '</strong> <span>' + escHtml(s.val) + '</span></span>';
    }).join('');
    var hintId = 'va-alarm-ack-hint-' + INSTANCES.indexOf(inst);
    var wChart = measureChartWidth(host, null);
    var svgHtml = getTrace().buildFocusSvg ? getTrace().buildFocusSvg(cfg, 'unack', inst.series, wChart) : '';
    el.innerHTML =
      '<div class="va-alarm-takeover-head">' +
        '<div class="va-alarm-takeover-title-group">' +
          '<div><span class="va-pill" data-variant="status" data-state="fault">ACTIVE UNACKNOWLEDGED ALARM</span> <span class="va-pill" data-variant="tag">' + escHtml(cfg.channelTag || 'CHANNEL BREACH') + '</span></div>' +
          '<h2 class="va-alarm-takeover-title">' + escHtml(cfg.paramLabel) + ' Out of Operating Bounds</h2>' +
        '</div>' +
        '<div class="va-alarm-timer-wrap"><span class="va-alarm-timer-label">BREACH ELAPSED</span><span class="va-alarm-timer va-nums" aria-live="off" data-alarm-timer>' + fmtDuration(inst.breachSec) + '</span></div>' +
      '</div>' +
      '<div class="va-alarm-metrics-grid">' +
        '<div class="va-alarm-metric-cell is-excursion"><span class="va-alarm-metric-k">Live Reading</span><span class="va-alarm-metric-v va-nums" data-alarm-live-metric>' + fmtNum(inst.val, cfg.decimals) + ' ' + escHtml(cfg.unit) + '</span></div>' +
        '<div class="va-alarm-metric-cell"><span class="va-alarm-metric-k">Operating Boundary</span><span class="va-alarm-metric-v va-nums">' + escHtml(boundTxt) + '</span></div>' +
        '<div class="va-alarm-metric-cell is-excursion"><span class="va-alarm-metric-k">Excursion Delta</span><span class="va-alarm-metric-v va-nums" data-alarm-delta>' + escHtml(exc.deltaStr) + '</span></div>' +
        '<div class="va-alarm-metric-cell"><span class="va-alarm-metric-k">Rate of Change</span><span class="va-alarm-metric-v va-nums" data-alarm-rate>' + escHtml(rateTxt) + '</span></div>' +
      '</div>' +
      '<div class="va-alarm-chart-card" data-alarm-svg-slot>' + svgHtml + '</div>' +
      '<div class="va-alarm-timeline" aria-label="Breach Progression Timeline">' +
        '<div class="va-alarm-tl-step"><span>-00:08</span><span>Safe Window</span></div>' +
        '<div class="va-alarm-tl-step"><span>-00:03</span><span>Pre-Alarm Trend</span></div>' +
        '<div class="va-alarm-tl-step is-active"><span>00:00</span><span>Limit Crossed</span></div>' +
        '<div class="va-alarm-tl-step"><span>Active</span><span>Operator Ack Pending</span></div>' +
      '</div>' +
      (sibHtml ? '<div class="va-alarm-siblings" aria-label="Nominal Sibling Channels">' + sibHtml + '</div>' : '') +
      '<div class="va-alarm-takeover-actions">' +
        '<button type="button" class="va-alarm-ack-btn" data-alarm-ack aria-describedby="' + hintId + '">Acknowledge Alarm</button>' +
        '<div class="va-alarm-action-hints" id="' + hintId + '">' +
          '<span class="va-alarm-shortcut-note"><kbd class="va-kbd">Enter</kbd> / <kbd class="va-kbd">Space</kbd> to silence and restore balanced view</span>' +
          '<span class="va-alarm-limit-note">' + escHtml(cfg.ackActionHint || '') + '</span>' +
        '</div>' +
      '</div>';
    var ackBtn = el.querySelector('[data-alarm-ack]');
    if (ackBtn) ackBtn.addEventListener('click', function () { acknowledge(inst, true); });
  }

  function renderBanner(host, inst) {
    var bn = host.querySelector('[data-alarm-banner]');
    if (!bn) return;
    var cfg = inst.cfg, ph = inst.phase;
    var peakExc = computeExcursion(Number(cfg.breachPeak), cfg);
    var stState = ph === 'nominal' ? 'nominal' : (ph === 'approaching' ? 'warn' : 'fault');
    var stText = ph === 'nominal' ? 'CALM BASELINE' : (ph === 'approaching' ? 'APPROACHING LIMIT' : (ph === 'ack' ? 'ACKNOWLEDGED · LATCHED FAULT' : 'ACTIVE ALARM'));
    var extra = ph === 'approaching'
      ? '<span class="va-alarm-rate-note">Rate ' + (inst.rate >= 0 ? '+' : '') + fmtNum(inst.rate, cfg.decimals) + ' ' + escHtml(cfg.unit) + '/s</span>'
      : (ph === 'ack'
        ? '<span class="va-alarm-rate-note">Latched Peak ' + fmtNum(cfg.breachPeak, cfg.decimals) + ' ' + escHtml(cfg.unit) + ' (' + escHtml(peakExc.deltaStr) + ')</span>'
        : '<span class="va-alarm-limit-note">Limit ' + fmtNum(cfg.threshold, cfg.decimals) + ' ' + escHtml(cfg.unit) + '</span>');
    var btns = ph === 'ack'
      ? '<button type="button" class="va-alarm-btn va-alarm-btn-replay" data-alarm-replay>Replay Breach</button>' +
        '<button type="button" class="va-alarm-btn" data-alarm-reset>Return to Calm</button>'
      : '<button type="button" class="va-alarm-btn va-alarm-btn-replay" data-alarm-replay>Replay Breach</button>';
    var benchCtrl = cfg.benchControls
      ? '<button type="button" class="va-alarm-btn" data-alarm-jump="nominal" aria-pressed="' + (ph === 'nominal' ? 'true' : 'false') + '">1 · Calm</button>' +
        '<button type="button" class="va-alarm-btn" data-alarm-jump="approaching" aria-pressed="' + (ph === 'approaching' ? 'true' : 'false') + '">2 · Approach</button>' +
        '<button type="button" class="va-alarm-btn" data-alarm-jump="unack" aria-pressed="' + (ph === 'unack' ? 'true' : 'false') + '">3 · Takeover</button>' +
        '<button type="button" class="va-alarm-btn" data-alarm-jump="ack" aria-pressed="' + (ph === 'ack' ? 'true' : 'false') + '">4 · Ack</button>'
      : '';
    bn.innerHTML =
      '<div class="va-alarm-banner-left">' +
        '<span class="va-pill" data-variant="status" data-state="' + stState + '">' + stText + '</span>' +
        '<span class="va-alarm-param-name">' + escHtml(cfg.paramLabel) + '</span>' +
        '<span class="va-alarm-live-val va-nums" data-alarm-banner-val>' + fmtNum(inst.val, cfg.decimals) + ' ' + escHtml(cfg.unit) + '</span>' +
        extra +
      '</div>' +
      '<div class="va-alarm-banner-right">' + benchCtrl + btns + '</div>';
    var rep = bn.querySelector('[data-alarm-replay]');
    if (rep) rep.addEventListener('click', function () { replay(inst, true); });
    var rst = bn.querySelector('[data-alarm-reset]');
    if (rst) rst.addEventListener('click', function () { setPhase(inst, 'nominal', true, '[data-alarm-replay]'); });
    bn.querySelectorAll('[data-alarm-jump]').forEach(function (jb) {
      jb.addEventListener('click', function () {
        var targetPh = jb.getAttribute('data-alarm-jump');
        setPhase(inst, targetPh, true, targetPh === 'unack' ? '[data-alarm-ack]' : '[data-alarm-jump="' + targetPh + '"]');
      });
    });
  }

  function announce(host, text) {
    var lr = host.querySelector('.va-alarm-live');
    if (lr) lr.textContent = text;
  }

  function setPhase(inst, ph, holdManual, focusSel) {
    if (!hasPhase(ph)) ph = 'nominal';
    if (holdManual) stopTimers(inst);
    var doc = inst.doc, T = getTrace();
    var hadFocus = !!(doc && doc.activeElement && inst.host.contains(doc.activeElement));
    var prev = inst.phase;
    inst.phase = ph;
    inst.manualHold = !!holdManual;
    inst.host.setAttribute('data-alarm-phase', ph);
    if (ph === 'nominal') {
      inst.breachSec = 0;
      if (holdManual) inst.elapsedMs = 0;
    } else if (ph === 'approaching') {
      inst.breachSec = 0;
      if (holdManual) inst.elapsedMs = 3100;
    } else if (ph === 'unack') {
      if (holdManual && inst.elapsedMs < 4000) inst.elapsedMs = 4400;
      inst.breachSec = Math.max(1, Math.floor(Math.max(0, inst.elapsedMs - 4000) / 1000) + 1);
    } else {
      inst.breachSec = Math.max(inst.breachSec, 4);
    }
    var sm = sampleForPhase(inst.cfg, ph, inst.elapsedMs);
    inst.val = sm.val;
    inst.rate = sm.rate;
    inst.series = T.buildPhaseSeries ? T.buildPhaseSeries(inst.cfg, ph, inst.elapsedMs) : [sm.val];
    renderBanner(inst.host, inst);
    if (ph === 'unack') renderTakeover(inst.host, inst);
    if (T.syncBoundUI) T.syncBoundUI(inst.host, inst);
    if (focusSel || hadFocus) {
      var targetSel = focusSel || (ph === 'unack' ? '[data-alarm-ack]' : '[data-alarm-replay]');
      var fEl = inst.host.querySelector(targetSel);
      if (fEl && typeof fEl.focus === 'function') fEl.focus({ preventScroll: true });
    }
    if (prev !== ph) {
      var msg = ph === 'approaching' ? (inst.cfg.paramLabel + ' approaching operating limit.') :
        (ph === 'unack' ? ('Alarm triggered: ' + inst.cfg.paramLabel + ' breached limit. Action required.') :
          (ph === 'ack' ? 'Alarm acknowledged. Balanced diagnostic view restored.' : (inst.cfg.paramLabel + ' returned to calm baseline.')));
      announce(inst.host, msg);
    }
  }

  function acknowledge(inst, restoreFocus) {
    stopTimers(inst);
    setPhase(inst, 'ack', true, restoreFocus ? '[data-alarm-replay]' : '');
  }

  function replay(inst, restoreFocus) {
    stopTimers(inst);
    inst.manualHold = false;
    inst.elapsedMs = 0;
    inst.breachSec = 0;
    setPhase(inst, 'nominal', false, restoreFocus ? '[data-alarm-replay]' : '');
    startLoop(inst);
  }

  function stopTimers(inst) {
    if (inst.timerId) { global.clearInterval(inst.timerId); inst.timerId = 0; }
  }

  function tick(inst) {
    if (!inst.host.isConnected) {
      stopTimers(inst);
      inst.host.__vaAlarmBound = false;
      delete inst.host.__vaAlarmInst;
      var i = INSTANCES.indexOf(inst);
      if (i >= 0) INSTANCES.splice(i, 1);
      return;
    }
    if (inst.doc.hidden || inst.manualHold || inst.phase === 'ack') return;
    inst.elapsedMs += 250;
    var T = getTrace();
    var nextPhase = inst.elapsedMs < 2000 ? 'nominal' : (inst.elapsedMs < 4000 ? 'approaching' : 'unack');
    var sm = sampleForPhase(inst.cfg, nextPhase, inst.elapsedMs);
    inst.val = sm.val;
    inst.rate = sm.rate;
    inst.series = T.buildPhaseSeries ? T.buildPhaseSeries(inst.cfg, nextPhase, inst.elapsedMs) : inst.series.concat([inst.val]).slice(-34);
    if (nextPhase !== inst.phase) {
      setPhase(inst, nextPhase, false, '');
      return;
    }
    if (nextPhase === 'unack') {
      inst.breachSec = Math.max(1, Math.floor((inst.elapsedMs - 4000) / 1000) + 1);
      var tEl = inst.host.querySelector('[data-alarm-timer]'), mEl = inst.host.querySelector('[data-alarm-live-metric]');
      var dEl = inst.host.querySelector('[data-alarm-delta]'), sEl = inst.host.querySelector('[data-alarm-svg-slot]');
      if (tEl) tEl.textContent = fmtDuration(inst.breachSec);
      if (mEl) mEl.textContent = fmtNum(inst.val, inst.cfg.decimals) + ' ' + inst.cfg.unit;
      if (dEl) dEl.textContent = computeExcursion(inst.val, inst.cfg).deltaStr;
      if (sEl) sEl.innerHTML = buildFocusSvgForHost(inst.host, inst.host.querySelector('[data-alarm-takeover]'), inst.cfg, 'unack', inst.series);
    } else {
      var bVal = inst.host.querySelector('[data-alarm-banner-val]');
      if (bVal) bVal.textContent = fmtNum(inst.val, inst.cfg.decimals) + ' ' + inst.cfg.unit;
    }
    if (T.syncBoundUI) T.syncBoundUI(inst.host, inst);
  }

  function startLoop(inst) {
    stopTimers(inst);
    inst.timerId = global.setInterval(function () { tick(inst); }, 250);
  }

  function normalizeCfg(rawCfg) {
    if (!rawCfg || typeof rawCfg !== 'object' || Array.isArray(rawCfg)) return null;
    if (![rawCfg.nominalStart, rawCfg.threshold, rawCfg.breachPeak].every(function (n) { return typeof n === 'number' && isFinite(n); })) return null;
    rawCfg.paramLabel = String(rawCfg.paramLabel || 'Monitored Channel');
    rawCfg.unit = rawCfg.unit != null ? String(rawCfg.unit) : '';
    rawCfg.siblings = Array.isArray(rawCfg.siblings)
      ? rawCfg.siblings.filter(function (s) { return s && typeof s === 'object'; }).map(function (s) {
          return { label: String(s.label || ''), val: String(s.val != null ? s.val : '') };
        })
      : [];
    return rawCfg;
  }

  function mountHost(host, doc) {
    if (host.__vaAlarmBound) return;
    var raw = host.getAttribute('data-alarm-config');
    if (!raw) return;
    var cfg;
    try { cfg = normalizeCfg(JSON.parse(raw)); } catch (_e) { return; }
    if (!cfg) return;
    host.__vaAlarmBound = true;
    var T = getTrace();
    var inst = {
      host: host, doc: doc, cfg: cfg, phase: 'nominal', elapsedMs: 0, breachSec: 0, timerId: 0, manualHold: false,
      val: Number(cfg.nominalStart), rate: 0, series: T.buildPhaseSeries ? T.buildPhaseSeries(cfg, 'nominal', 0) : [Number(cfg.nominalStart)]
    };
    host.__vaAlarmInst = inst;
    INSTANCES.push(inst);
    var ov = resolveOverride(host, doc);
    if (ov) setPhase(inst, ov, true, '');
    else if (cfg.initialMode === 'ack') setPhase(inst, 'ack', true, '');
    else { setPhase(inst, 'nominal', false, ''); startLoop(inst); }
  }

  function bindHandoffLinks(doc) {
    doc.querySelectorAll('a[data-quiet-handoff-world][data-quiet-handoff-view]').forEach(function (a) {
      if (a.__vaHandoffWired) return;
      a.__vaHandoffWired = true;
      a.addEventListener('click', function (ev) {
        var w = a.getAttribute('data-quiet-handoff-world'), v = a.getAttribute('data-quiet-handoff-view');
        try {
          if (global.parent && global.parent !== global && global.parent.QuietStudioPortalV9 &&
              typeof global.parent.QuietStudioPortalV9.openExamples === 'function' && w && v) {
            ev.preventDefault();
            global.parent.QuietStudioPortalV9.openExamples(w, v);
          }
        } catch (_e) {}
      });
    });
  }

  function boot(docRef) {
    var doc = docRef || global.document;
    if (!doc) return;
    destroyAll(doc);
    doc.querySelectorAll('.va-alarm-console[data-alarm-config]').forEach(function (h) { mountHost(h, doc); });
    bindHandoffLinks(doc);
    if (!doc.__vaVisWired) {
      doc.__vaVisWired = true;
      doc.addEventListener('visibilitychange', function () {
        INSTANCES.forEach(function (inst) {
          if (inst.doc === doc && inst.host.isConnected && !doc.hidden && inst.phase === 'unack') renderTakeover(inst.host, inst);
        });
      });
      var win = doc.defaultView || global;
      if (win && win.addEventListener) {
        win.addEventListener('beforeprint', function () {
          INSTANCES.forEach(function (inst) { if (inst.doc === doc && inst.phase === 'unack') acknowledge(inst, false); });
        });
      }
    }
  }

  function destroyAll(docRef) {
    for (var i = INSTANCES.length - 1; i >= 0; i--) {
      if (!docRef || INSTANCES[i].doc === docRef) {
        stopTimers(INSTANCES[i]);
        INSTANCES[i].host.__vaAlarmBound = false;
        delete INSTANCES[i].host.__vaAlarmInst;
        INSTANCES.splice(i, 1);
      }
    }
  }

  global.QuietAlarmLifecycle = {
    boot: boot,
    destroyAll: destroyAll,
    setPhase: function (host, phase) { if (host && host.__vaAlarmInst) { stopTimers(host.__vaAlarmInst); setPhase(host.__vaAlarmInst, phase, true, ''); } },
    replay: function (host) { if (host && host.__vaAlarmInst) replay(host.__vaAlarmInst, false); },
    acknowledge: function (host) { if (host && host.__vaAlarmInst) acknowledge(host.__vaAlarmInst, false); }
  };

  if (global.document) {
    if (global.document.readyState === 'loading') global.document.addEventListener('DOMContentLoaded', function () { boot(global.document); });
    else boot(global.document);
  }
})(typeof window !== 'undefined' ? window : this);


/* Quiet UI v9.7.0 Wave 3 — Plumb-Line Responsive SVG Renderer (1:1 text scale, zero mobile scroll) */
(function (global) {
  'use strict';

  var NS = 'http://www.w3.org/2000/svg';
  var V23_COHORTS = [
    ['ewr-edge-01 (Canary 1)', 'Canary r42', 7.4, 'var(--accent-focal)', '0.14'],
    ['fra-edge-02 (Canary 2)', 'Canary r42', 6.9, 'var(--accent-focal)', '0.14'],
    ['NA West/Central (5 clusters)', 'Held r41', 36.1, 'var(--text-muted)', '0.06'],
    ['EU Core (4 clusters)', 'Held r41', 28.8, 'var(--text-muted)', '0.06'],
    ['APAC Edge (3 clusters)', 'Held r41', 20.8, 'var(--text-muted)', '0.06'],
  ];

  var V24_BUCKETS = [
    ['14:00', 0, 0, 0, 1], ['14:02', 0, 1, 0, 1], ['14:05', 0, 0, 1, 0], ['14:07', 0, 1, 0, 1],
    ['14:10', 0, 0, 1, 0], ['14:12', 0, 1, 0, 1], ['14:15', 0, 1, 1, 0], ['14:17', 0, 1, 1, 0],
    ['14:20', 2, 1, 1, 0], ['14:22', 2, 2, 0, 0], ['14:25', 2, 1, 1, 0], ['14:27', 1, 1, 1, 0],
    ['14:30', 1, 1, 0, 0], ['14:32', 1, 1, 1, 0], ['14:35', 0, 1, 1, 0], ['14:37', 0, 0, 1, 1],
    ['14:40', 0, 1, 0, 1], ['14:42', 0, 0, 1, 1], ['14:45', 0, 0, 0, 1], ['14:47', 0, 0, 0, 1],
    ['14:50', 0, 0, 0, 2], ['14:52', 0, 0, 0, 1], ['14:55', 0, 0, 0, 1], ['14:57', 0, 0, 0, 1],
  ];

  var V25_PROFILE = [
    [0, 0], [68, -110], [140, -180], [210, -420], [240, -760], [302, -1180],
    [362, -1420], [440, -2940], [515, -3680], [585, -3850], [618, -1250], [640, 0],
  ];

  var V25_STATIONS = [
    [0, 0, 26.0, 'NOMINAL', 'shelf'], [68, -110, 24.2, 'NOMINAL', 'shelf'],
    [140, -180, 22.9, 'NOMINAL', 'shelf'], [210, -420, 21.8, 'NOMINAL', 'shelf'],
    [240, -760, 20.9, 'NOMINAL', 'branch'], [302, -1180, 20.1, 'NOMINAL', 'branch'],
    [362, -1420, 16.4, 'WARN', 'fault'], [440, -2940, 17.3, 'NOMINAL', 'deep'],
    [515, -3680, 17.8, 'NOMINAL', 'deep'], [640, 0, 18.2, 'NOMINAL', 'deep'],
  ];

  var V25_NODES = [
    [0, 0, 'shelf', 'NOMINAL', 'CLS-Alpha', 'CLS-Alpha', 'Alpha', 'start', 0, 22, 22],
    [68, -110, 'shelf', 'NOMINAL', 'Repeater R1', 'R1', 'R1', 'middle', 0, 58, 58],
    [140, -180, 'shelf', 'NOMINAL', 'Repeater R2', 'R2', 'R2', 'middle', 0, 22, 22],
    [210, -420, 'shelf', 'NOMINAL', 'Repeater R3', 'R3', 'R3', 'end', -9, 68, 72],
    [240, -760, 'branch', 'NOMINAL', 'BU-03', 'BU-03', 'BU-03', 'start', 9, 22, 22],
    [302, -1180, 'branch', 'NOMINAL', 'Repeater R4', 'R4', 'R4', 'end', -9, 96, 96],
    [362, -1420, 'fault', 'WARN', 'R5', 'R5', 'R5', 'end', -9, 108, 108],
    [440, -2940, 'deep', 'NOMINAL', 'Repeater R6', 'R6', 'R6', 'end', -9, 140, 146],
    [515, -3680, 'deep', 'NOMINAL', 'Repeater R7', 'R7', 'R7', 'end', -9, 166, 172],
    [585, -3850, 'deep', 'NOMINAL', 'Repeater R8', 'Repeater R8', 'R8', 'middle', 0, 198, 198],
    [640, 0, 'deep', 'NOMINAL', 'CLS-Bravo', 'CLS-Bravo', 'Bravo', 'end', 0, 22, 22],
  ];

  function el(doc, tag, attrs, text) {
    var node = doc.createElementNS(NS, tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) { node.setAttribute(k, String(attrs[k])); });
    }
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function clearSvg(svg) {
    while (svg.firstChild) svg.removeChild(svg.firstChild);
  }

  function clamp(lo, hi, v) {
    return Math.max(lo, Math.min(hi, v));
  }

  function applySpanFilter(node, grp, activeGrp) {
    if (!activeGrp || activeGrp === 'all') return;
    var mine = grp === activeGrp;
    node.setAttribute('data-span-dim', mine ? '0' : '1');
    node.setAttribute('data-span-hot', mine ? '1' : '0');
  }

  function renderV23Blast(svg, vw) {
    var doc = svg.ownerDocument, mob = vw < 560, h = mob ? 276 : 236;
    var ml = mob ? 2 : 196, mr = mob ? 6 : 136, pw = Math.max(120, vw - ml - mr);
    clearSvg(svg);
    svg.setAttribute('viewBox', '0 0 ' + vw + ' ' + h);
    svg.appendChild(el(doc, 'text', { x: 2, y: 16, 'font-size': '12', 'font-weight': '650', fill: 'var(--text-primary)' },
      mob ? 'Traffic Share by Cohort (14 Clusters)' : 'Traffic Share by Cluster Cohort (14 Edge Clusters)'));
    var y0 = mob ? 26 : 24, y1 = mob ? 250 : 210, yTick = mob ? 266 : 226;
    for (var i = 0; i <= 4; i += 1) {
      var gx = (ml + (i * pw) / 4).toFixed(1);
      svg.appendChild(el(doc, 'line', {
        x1: gx, y1: y0, x2: gx, y2: y1, stroke: 'var(--border-subtle)',
        'stroke-dasharray': i === 0 ? 'none' : '2 3',
      }));
      var anc = mob && i === 0 ? 'start' : (mob && i === 4 ? 'end' : 'middle');
      svg.appendChild(el(doc, 'text', { x: gx, y: yTick, 'text-anchor': anc, 'font-size': '11.5', fill: 'var(--text-muted)' }, (i * 10) + '%'));
    }
    V23_COHORTS.forEach(function (row, idx) {
      var bw = ((row[2] / 40) * pw).toFixed(1), valTxt = row[2].toFixed(1) + '% (' + row[1] + ')';
      if (mob) {
        var top = 40 + idx * 42;
        svg.appendChild(el(doc, 'text', { x: 2, y: top, 'font-size': '11.5', fill: 'var(--text-primary)' }, row[0]));
        svg.appendChild(el(doc, 'text', { x: vw - 2, y: top, 'text-anchor': 'end', 'font-size': '11.5', 'font-weight': '600', fill: 'var(--text-primary)' }, valTxt));
        svg.appendChild(el(doc, 'rect', { x: ml, y: top + 5, width: pw.toFixed(1), height: 15, rx: 3, fill: 'var(--text-muted)', opacity: row[4] }));
        svg.appendChild(el(doc, 'rect', { x: ml, y: top + 5, width: bw, height: 15, rx: 3, fill: row[3] }));
      } else {
        var y = 32 + idx * 36;
        svg.appendChild(el(doc, 'text', { x: 2, y: y + 15, 'font-size': '11.5', fill: 'var(--text-primary)' }, row[0]));
        svg.appendChild(el(doc, 'rect', { x: ml, y: y, width: pw.toFixed(1), height: 22, rx: 3, fill: 'var(--text-muted)', opacity: row[4] }));
        svg.appendChild(el(doc, 'rect', { x: ml, y: y, width: bw, height: 22, rx: 3, fill: row[3] }));
        svg.appendChild(el(doc, 'text', { x: vw - 2, y: y + 15, 'text-anchor': 'end', 'font-size': '11.5', 'font-weight': '600', fill: 'var(--text-primary)' }, valTxt));
      }
    });
  }

  function renderV24Hist(svg, vw) {
    var doc = svg.ownerDocument, mob = vw < 560, ml = 26, pw = Math.max(180, vw - ml - 8);
    var step = pw / 24, bw = clamp(7, 36, step * 0.72), scope = svg.closest('[data-v24-scope]');
    var active = scope && scope.dataset.v24ActiveBucket !== undefined ? scope.dataset.v24ActiveBucket : '';
    var hlX = ml + 8 * step, hlW = 6 * step, pillW = mob ? 142 : 148;
    var hlCx = clamp(ml + pillW / 2, vw - 8 - pillW / 2, hlX + hlW / 2);
    clearSvg(svg);
    svg.setAttribute('viewBox', '0 0 ' + vw + ' 178');
    svg.appendChild(el(doc, 'rect', { x: hlX.toFixed(1), y: 24, width: hlW.toFixed(1), height: 124, rx: 3, fill: 'var(--status-danger)', opacity: '0.06' }));
    svg.appendChild(el(doc, 'rect', { x: (hlCx - pillW / 2).toFixed(1), y: 14, width: pillW, height: 18, rx: 2, fill: 'var(--bg-surface)', opacity: '0.94' }));
    svg.appendChild(el(doc, 'text', { x: hlCx.toFixed(1), y: 27, 'text-anchor': 'middle', 'font-size': '11.5', 'font-weight': '650', fill: 'var(--status-danger)' }, 'Burst Peak 14:20Z–14:35Z'));
    for (var yv = 0; yv <= 4; yv += 1) {
      var yy = 148 - yv * 24;
      svg.appendChild(el(doc, 'line', { x1: ml, y1: yy, x2: ml + pw, y2: yy, stroke: 'var(--border-subtle)', 'stroke-dasharray': '2 3' }));
      svg.appendChild(el(doc, 'text', { x: ml - 6, y: yy + 4, 'text-anchor': 'end', 'font-size': '11.5', fill: 'var(--text-muted)' }, String(yv)));
    }
    var segMeta = [['var(--status-danger)', 1], ['var(--status-warn)', 2], ['var(--accent-focal)', 3], ['var(--text-muted)', 4]];
    V24_BUCKETS.forEach(function (b, i) {
      var x = ml + i * step + (step - bw) / 2, tot = b[1] + b[2] + b[3] + b[4], curY = 148;
      var grp = el(doc, 'g', {
        class: 'w2-svg-bar-grp', role: 'button', tabindex: '0', 'data-v24-bucket': String(i),
        'aria-pressed': active === String(i) ? 'true' : 'false',
        'aria-label': 'Bucket ' + b[0] + ' UTC: ' + tot + ' events',
      });
      grp.appendChild(el(doc, 'rect', { class: 'w2-bucket-hit', x: (x - 2).toFixed(1), y: 28, width: (bw + 4).toFixed(1), height: 122, rx: 2, fill: 'transparent' }));
      segMeta.forEach(function (sm) {
        var cnt = b[sm[1]];
        if (cnt <= 0) return;
        var sh = cnt * 24;
        curY -= sh;
        grp.appendChild(el(doc, 'rect', { x: x.toFixed(1), y: curY.toFixed(1), width: bw.toFixed(1), height: (sh - 1).toFixed(1), rx: 1.5, fill: sm[0] }));
      });
      var showTick = mob ? (i === 0 || i === 6 || i === 12 || i === 18 || i === 23) : (i % 4 === 0 || i === 23);
      if (showTick) {
        var anc = i === 0 ? 'start' : (i === 23 ? 'end' : 'middle');
        var tx = i === 0 ? ml : (i === 23 ? ml + pw : x + bw / 2);
        grp.appendChild(el(doc, 'text', { x: tx.toFixed(1), y: 166, 'text-anchor': anc, 'font-size': '11.5', fill: 'var(--text-muted)' }, b[0]));
      }
      svg.appendChild(grp);
    });
  }

  function renderV25Bathy(svg, vw) {
    var doc = svg.ownerDocument, mob = vw < 560, med = vw >= 560 && vw < 940;
    var ml = mob ? 44 : 56, mr = mob ? 10 : 12, pw = Math.max(180, vw - ml - mr), h = mob ? 216 : 210;
    var kx = function (km) { return ml + (km / 640) * pw; };
    var dy = function (d) { return 36 + (Math.abs(d) / 4000) * 144; };
    var scope = svg.closest('[data-v25-scope]'), activeGrp = scope ? (scope.dataset.v25ActiveSpan || 'all') : 'all';
    clearSvg(svg);
    svg.setAttribute('viewBox', '0 0 ' + vw + ' ' + h);
    var cPath = 'M ' + V25_PROFILE.map(function (p) { return kx(p[0]).toFixed(1) + ' ' + dy(p[1]).toFixed(1); }).join(' L ');
    var sPath = cPath + ' L ' + kx(640).toFixed(1) + ' 36.0 L ' + kx(0).toFixed(1) + ' 36.0 Z';
    svg.appendChild(el(doc, 'path', { d: sPath, fill: 'var(--accent-focal)', opacity: '0.08' }));
    [0, 1000, 2000, 3000, 4000].forEach(function (d) {
      var yy = dy(d).toFixed(1), lbl = d === 0 ? '0 m' : (mob ? '-' + (d / 1000) + 'km' : '-' + d + ' m');
      svg.appendChild(el(doc, 'line', { x1: ml, y1: yy, x2: ml + pw, y2: yy, stroke: 'var(--border-subtle)', 'stroke-dasharray': '2 3' }));
      svg.appendChild(el(doc, 'text', { x: ml - 6, y: (Number(yy) + 4).toFixed(1), 'text-anchor': 'end', 'font-size': '11.5', fill: 'var(--text-muted)' }, lbl));
    });
    svg.appendChild(el(doc, 'path', { d: cPath, fill: 'none', stroke: 'var(--text-primary)', 'stroke-width': '2.2' }));
    var xf = kx(362), boxW = mob ? 124 : 222, boxX = clamp(ml + 4, vw - mr - boxW, xf + 8);
    svg.appendChild(el(doc, 'line', { x1: xf.toFixed(1), y1: 28, x2: xf.toFixed(1), y2: 196, stroke: 'var(--status-warn)', 'stroke-dasharray': '4 3', 'stroke-width': '1.5' }));
    svg.appendChild(el(doc, 'rect', { x: boxX.toFixed(1), y: 44, width: boxW, height: 20, rx: 3, fill: 'var(--bg-surface)', stroke: 'var(--status-warn)' }));
    svg.appendChild(el(doc, 'text', { x: (boxX + 6).toFixed(1), y: 58, 'font-size': '11.5', 'font-weight': '650', fill: 'var(--status-warn)' },
      mob ? 'S5 Fault (+4.8 dB)' : 'Span S5 Fault (+4.8 dB · 362 km)'));
    V25_NODES.forEach(function (n) {
      var cx = kx(n[0]), cy = dy(n[1]), isWarn = n[3] === 'WARN', isBu = n[0] === 240;
      var col = isWarn ? 'var(--status-warn)' : (isBu ? 'var(--accent-focal)' : 'var(--text-primary)');
      var grp = el(doc, 'g', { class: 'w2-span-node', 'data-span-group': n[2] });
      applySpanFilter(grp, n[2], activeGrp);
      grp.appendChild(el(doc, 'circle', { cx: cx.toFixed(1), cy: cy.toFixed(1), r: isWarn || isBu ? 6.5 : 4.5, fill: col, stroke: 'var(--bg-surface)', 'stroke-width': '1.8' }));
      var dx = mob && n[7] !== 'middle' ? (n[8] > 0 ? 7 : (n[8] < 0 ? -7 : 0)) : n[8];
      var lblTxt = mob ? n[6] : (med ? n[5] : n[4]);
      grp.appendChild(el(doc, 'text', {
        class: 'va-svg-halo-text', x: (cx + dx).toFixed(1),
        y: mob ? n[10] : n[9], 'text-anchor': n[7], 'font-size': '11.5', 'font-weight': '600', fill: col,
      }, lblTxt));
      svg.appendChild(grp);
    });
  }

  function renderV25Osnr(svg, vw) {
    var doc = svg.ownerDocument, mob = vw < 560, ml = mob ? 44 : 56, mr = mob ? 10 : 12;
    var pw = Math.max(180, vw - ml - mr), scope = svg.closest('[data-v25-scope]');
    var activeGrp = scope ? (scope.dataset.v25ActiveSpan || 'all') : 'all';
    var kx = function (km) { return ml + (km / 640) * pw; };
    var oy = function (db) { return 184 - ((clamp(12, 28, db) - 12) / 16) * 150; };
    clearSvg(svg);
    svg.setAttribute('viewBox', '0 0 ' + vw + ' 214');
    [12, 16, 20, 24, 28].forEach(function (db) {
      var yy = oy(db);
      svg.appendChild(el(doc, 'line', { x1: ml, y1: yy.toFixed(1), x2: ml + pw, y2: yy.toFixed(1), stroke: 'var(--border-subtle)', 'stroke-dasharray': '2 3' }));
      svg.appendChild(el(doc, 'text', { x: ml - 6, y: (yy + 4).toFixed(1), 'text-anchor': 'end', 'font-size': '11.5', fill: 'var(--text-muted)' }, db + ' dB'));
    });
    (mob ? [0, 240, 362, 640] : [0, 160, 240, 362, 480, 640]).forEach(function (km) {
      var anc = km === 0 ? 'start' : (km === 640 ? 'end' : 'middle');
      svg.appendChild(el(doc, 'text', { x: kx(km).toFixed(1), y: 204, 'text-anchor': anc, 'font-size': '11.5', fill: 'var(--text-muted)' }, km + ' km'));
    });
    var yFec = oy(15.0), xf = kx(362);
    svg.appendChild(el(doc, 'line', { x1: kx(240).toFixed(1), y1: 24, x2: kx(240).toFixed(1), y2: 184, stroke: 'var(--border-strong)', 'stroke-dasharray': '2 4' }));
    svg.appendChild(el(doc, 'line', { x1: xf.toFixed(1), y1: 18, x2: xf.toFixed(1), y2: 184, stroke: 'var(--status-warn)', 'stroke-dasharray': '4 3', 'stroke-width': '1.5' }));
    svg.appendChild(el(doc, 'line', { x1: ml, y1: yFec.toFixed(1), x2: ml + pw, y2: yFec.toFixed(1), stroke: 'var(--status-danger)', 'stroke-dasharray': '6 4', 'stroke-width': '1.6' }));
    var fecW = mob ? 124 : 168;
    svg.appendChild(el(doc, 'rect', { x: (ml + pw - fecW - 2).toFixed(1), y: (yFec - 18).toFixed(1), width: fecW, height: 16, rx: 2, fill: 'var(--bg-surface)', opacity: '0.94' }));
    svg.appendChild(el(doc, 'text', { x: (ml + pw - 6).toFixed(1), y: (yFec - 6).toFixed(1), 'text-anchor': 'end', 'font-size': '11.5', 'font-weight': '650', fill: 'var(--status-danger)' },
      mob ? 'SD-FEC (15.0 dB)' : 'SD-FEC Floor (15.0 dB)'));
    var lPath = 'M ' + V25_STATIONS.map(function (s) { return kx(s[0]).toFixed(1) + ' ' + oy(s[2]).toFixed(1); }).join(' L ');
    svg.appendChild(el(doc, 'path', { d: lPath, fill: 'none', stroke: 'var(--accent-focal)', 'stroke-width': '2.3' }));
    V25_STATIONS.forEach(function (s) {
      var w = s[3] === 'WARN', grp = el(doc, 'g', { class: 'w2-span-mark', 'data-span-group': s[4] });
      applySpanFilter(grp, s[4], activeGrp);
      grp.appendChild(el(doc, 'circle', { cx: kx(s[0]).toFixed(1), cy: oy(s[2]).toFixed(1), r: w ? 6.0 : 4.2, fill: w ? 'var(--status-warn)' : 'var(--accent-focal)', stroke: 'var(--bg-surface)', 'stroke-width': '1.6' }));
      svg.appendChild(grp);
    });
    var ow = mob ? 142 : 198, ox = clamp(ml + 4, vw - mr - ow, xf + 8);
    svg.appendChild(el(doc, 'rect', { x: ox.toFixed(1), y: 42, width: ow, height: 20, rx: 3, fill: 'var(--bg-surface)', stroke: 'var(--status-warn)' }));
    svg.appendChild(el(doc, 'text', { x: (ox + 6).toFixed(1), y: 56, 'font-size': '11.5', 'font-weight': '650', fill: 'var(--status-warn)' },
      mob ? 'Min OSNR 16.4 (+1.4 dB)' : 'Min OSNR 16.4 dB (+1.4 dB)'));
  }

  function renderV26Box(svg, vw) {
    var doc = svg.ownerDocument, mob = vw < 560, ml = mob ? 42 : 48, mr = mob ? 10 : 14;
    var pw = Math.max(180, vw - ml - mr), xg = svg.querySelector('[data-v26-xgrid]');
    var geom = { w: vw, h: 264, ml: ml, mr: mr, yTop: 38, lineTop: 24, yBot: 232, mobile: mob };
    svg.setAttribute('viewBox', '0 0 ' + vw + ' 264');
    svg.setAttribute('data-v26-geom', JSON.stringify(geom));
    var ceilBg = svg.querySelector('[data-v26-ceil-bg]'), ceilLbl = svg.querySelector('[data-v26-ceil-lbl]');
    if (ceilBg) ceilBg.setAttribute('x', String(ml + 6));
    if (ceilLbl) ceilLbl.setAttribute('x', String(ml + 12));
    if (xg) {
      clearSvg(xg);
      (mob ? [0, 12, 24, 36] : [0, 6, 12, 18, 24, 30, 36]).forEach(function (m) {
        var anc = m === 0 ? 'start' : (m === 36 ? 'end' : 'middle');
        xg.appendChild(el(doc, 'text', {
          'data-v26-xtick': String(m), x: (ml + (m / 36) * pw).toFixed(1), y: 252,
          'text-anchor': anc, 'font-size': '11.5', fill: 'var(--text-muted)',
        }, 'Mo ' + m));
      });
    }
    var scope = svg.closest('[data-v26-root]');
    if (scope && typeof scope._v26Refresh === 'function') scope._v26Refresh();
  }

  function renderSvgBox(box, forceWidth) {
    if (!box) return;
    var svg = box.querySelector('svg[data-v23-blast-svg], svg[data-v24-hist-svg], svg[data-v25-bathy-svg], svg[data-v25-osnr-svg], svg[data-v26-svg]');
    if (!svg) return;
    var rawW = forceWidth || box.getBoundingClientRect().width;
    if (!rawW || rawW < 120) return;
    var vw = clamp(300, 1400, Math.round(rawW));
    if (svg.dataset.w2RenderedW === String(vw) && !forceWidth) return;
    svg.dataset.w2RenderedW = String(vw);
    if (svg.hasAttribute('data-v23-blast-svg')) renderV23Blast(svg, vw);
    else if (svg.hasAttribute('data-v24-hist-svg')) renderV24Hist(svg, vw);
    else if (svg.hasAttribute('data-v25-bathy-svg')) renderV25Bathy(svg, vw);
    else if (svg.hasAttribute('data-v25-osnr-svg')) renderV25Osnr(svg, vw);
    else if (svg.hasAttribute('data-v26-svg')) renderV26Box(svg, vw);
  }

  var sharedRo = null, globalWired = false;

  function ensureRo() {
    if (!sharedRo && typeof ResizeObserver !== 'undefined') {
      sharedRo = new ResizeObserver(function (entries) { entries.forEach(function (en) { renderSvgBox(en.target); }); });
    }
    return sharedRo;
  }

  function refreshAll(forceWidth, root) {
    var doc = root || document;
    if (doc && doc.querySelectorAll) doc.querySelectorAll('.w2-svg-box').forEach(function (box) { renderSvgBox(box, forceWidth); });
  }

  function observeStageMain(doc) {
    var stageMain = doc && doc.getElementById ? doc.getElementById('va-stage-main') : null;
    if (!stageMain || stageMain.dataset.w2SvgMo === '1' || typeof MutationObserver === 'undefined') return;
    stageMain.dataset.w2SvgMo = '1';
    var mo = new MutationObserver(function () { bootSvgEngine(doc); });
    mo.observe(stageMain, { childList: true });
  }

  function bootSvgEngine(root) {
    var doc = root || document, ro = ensureRo();
    if (doc && doc.querySelectorAll) {
      doc.querySelectorAll('.w2-svg-box').forEach(function (box) {
        if (ro && box.dataset.w2SvgObserved !== '1') { box.dataset.w2SvgObserved = '1'; ro.observe(box); }
        renderSvgBox(box);
      });
    }
    observeStageMain(doc);
    if (!globalWired) {
      globalWired = true;
      global.addEventListener('resize', function () { refreshAll(); });
      global.addEventListener('beforeprint', function () { refreshAll(1120); });
      global.addEventListener('afterprint', function () {
        document.querySelectorAll('.w2-svg-box svg').forEach(function (s) { delete s.dataset.w2RenderedW; });
        refreshAll();
      });
    }
  }

  global.QuietWave2Svg = { boot: bootSvgEngine, refresh: refreshAll, renderOne: renderSvgBox };
  if (typeof document !== 'undefined' && document) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { bootSvgEngine(document); });
    else bootSvgEngine(document);
  }
})(typeof window !== 'undefined' ? window : globalThis);


/* SPDX-License-Identifier: Apache-2.0 */
/* Quiet UI v9.7.0 Wave 2 — Client Runtime for v23/v24/v25/v26 & Specimens 51-53 */
(function (global) {
  'use strict';

  function sevState(sev) {
    if (sev === 'CRITICAL' || sev === 'BREAKING') return 'fault';
    if (sev === 'WARN' || sev === 'MODERATE') return 'warn';
    return 'nominal';
  }

  function syncV23PhaseUi(els, phase) {
    var btnStates = {
      baseline: [false, true, true, true, 'nominal', 'BASELINE r41', 'Baseline r41 active on 14/14 clusters — snapshot revert verified.', 'warn', '2 of 14 clusters', '14.3% traffic · ewr-edge-01, fra-edge-02'],
      staged: [true, false, false, true, 'warn', 'CANARY r42 STAGED', 'Candidate r42 staged on 2/14 canary clusters (14.3% traffic · 30 min soak running).', 'warn', '2 of 14 clusters', '14.3% traffic · Canary r42 soaking (ewr-edge-01, fra-edge-02)'],
      promoted: [true, true, false, false, 'nominal', 'PROMOTED r42', 'Candidate r42 promoted across 14/14 clusters (1-click r41 revert ready).', 'nominal', '14 of 14 clusters', '100% traffic · Global r42 active'],
    }[phase];
    if (!btnStates) return;
    if (els.stage) els.stage.disabled = btnStates[0];
    if (els.confirm) els.confirm.disabled = btnStates[1];
    if (els.revert) els.revert.disabled = btnStates[2];
    if (els.toast) els.toast.hidden = btnStates[3];
    if (els.pill) { els.pill.setAttribute('data-state', btnStates[4]); els.pill.textContent = btnStates[5]; }
    if (els.gate) els.gate.textContent = btnStates[6];
    if (els.blastTile) els.blastTile.setAttribute('data-state', btnStates[7]);
    if (els.blastVal) els.blastVal.textContent = btnStates[8];
    if (els.blastSub) els.blastSub.textContent = btnStates[9];
  }

  function wireV23(scope) {
    if (!scope || scope.dataset.w2Bound === '1') return;
    scope.dataset.w2Bound = '1';
    var activeFilter = 'all', timerId = 0;
    var filterBtns = scope.querySelectorAll('[data-v23-filter]');
    var ctxCheck = scope.querySelector('[data-v23-context]');
    var rows = scope.querySelectorAll('.v23-row');
    var toast = scope.querySelector('[data-v23-toast]');
    var els = {
      pill: scope.querySelector('#v23-header-status-pill, [data-v23-pill]'),
      gate: scope.querySelector('[data-v23-gate-status]'),
      stage: scope.querySelector('[data-v23-stage]'),
      confirm: scope.querySelector('[data-v23-confirm]'),
      revert: scope.querySelector('[data-v23-revert]'),
      toast: toast,
      blastTile: scope.querySelector('[data-v23-kpi-tile="blast"]'),
      blastVal: scope.querySelector('[data-v23-kpi="blast"]'),
      blastSub: scope.querySelector('[data-v23-kpi="blast_sub"]'),
    };
    function applyRows() {
      var showCtx = !!(ctxCheck && ctxCheck.checked);
      rows.forEach(function (tr) {
        var cat = tr.getAttribute('data-v23-cat') || '';
        tr.hidden = !(cat === 'context' ? showCtx : (activeFilter === 'all' || cat === activeFilter));
      });
    }
    function clearUndoTimer() { if (timerId) { global.clearTimeout(timerId); timerId = 0; } }
    function armUndoTimer() {
      clearUndoTimer();
      timerId = global.setTimeout(function () {
        timerId = 0;
        if (toast && (!toast.matches || !toast.matches(':hover, :focus-within'))) toast.hidden = true;
      }, 7500);
    }
    function setPhase(phase) {
      scope.setAttribute('data-v23-phase', phase);
      clearUndoTimer();
      syncV23PhaseUi(els, phase);
      if (phase === 'promoted' && toast) armUndoTimer();
    }
    filterBtns.forEach(function (btn) {
      btn.addEventListener('click', function () {
        activeFilter = btn.getAttribute('data-v23-filter') || 'all';
        filterBtns.forEach(function (b) { b.setAttribute('aria-pressed', b === btn ? 'true' : 'false'); });
        applyRows();
      });
    });
    if (ctxCheck) ctxCheck.addEventListener('change', applyRows);
    if (els.stage) els.stage.addEventListener('click', function () { setPhase('staged'); });
    if (els.confirm) els.confirm.addEventListener('click', function () { setPhase('promoted'); });
    if (els.revert) els.revert.addEventListener('click', function () { setPhase('baseline'); });
    var toastRevert = scope.querySelector('[data-v23-toast-revert]');
    if (toastRevert) toastRevert.addEventListener('click', function () { setPhase('baseline'); });
    if (toast) {
      var maybeArm = function () { if (!toast.hidden && (!toast.matches || !toast.matches(':hover, :focus-within'))) armUndoTimer(); };
      toast.addEventListener('mouseenter', clearUndoTimer);
      toast.addEventListener('focusin', clearUndoTimer);
      toast.addEventListener('mouseleave', maybeArm);
      toast.addEventListener('focusout', maybeArm);
    }
    applyRows();
  }

  function v24SetInspectorEmpty(scope, isEmpty) {
    var emp = scope.querySelector('[data-v24-insp-empty]');
    var bdy = scope.querySelector('[data-v24-insp-body]');
    var sev = scope.querySelector('[data-insp-sev]');
    var copyBtn = scope.querySelector('[data-v24-copy]');
    if (emp) emp.hidden = !isEmpty;
    if (bdy) bdy.hidden = isEmpty;
    if (sev) sev.hidden = isEmpty;
    if (copyBtn) copyBtn.disabled = isEmpty;
  }

  function v24SelectRow(scope, rows, row, copyOut) {
    if (!row) return;
    v24SetInspectorEmpty(scope, false);
    rows.forEach(function (r) { r.setAttribute('aria-selected', r === row ? 'true' : 'false'); });
    var map = {
      '[data-insp-ts]': row.getAttribute('data-ev-ts') || '',
      '[data-insp-svc]': row.getAttribute('data-ev-svc') || '',
      '[data-insp-span]': row.getAttribute('data-ev-span') || '',
      '[data-insp-trace]': row.getAttribute('data-ev-trace') || '',
      '[data-insp-caller]': row.getAttribute('data-ev-caller') || '',
      '[data-insp-code]': (row.getAttribute('data-ev-code') || '') + ' · ' + (row.getAttribute('data-ev-dur') || ''),
      '[data-insp-msg]': row.getAttribute('data-ev-msg') || '',
    };
    Object.keys(map).forEach(function (sel) {
      var el = scope.querySelector(sel);
      if (el) el.textContent = map[sel];
    });
    var sevPill = scope.querySelector('[data-insp-sev]');
    if (sevPill) {
      var sev = row.getAttribute('data-ev-sev') || 'NOMINAL';
      sevPill.textContent = sev;
      sevPill.setAttribute('data-state', sevState(sev));
    }
    if (copyOut) copyOut.textContent = '';
  }

  function v24SyncBucketButtons(scope, activeBucket) {
    scope.dataset.v24ActiveBucket = activeBucket === null ? '' : String(activeBucket);
    scope.querySelectorAll('.w2-svg-bar-grp[data-v24-bucket]').forEach(function (g) {
      g.setAttribute('aria-pressed', g.getAttribute('data-v24-bucket') === activeBucket ? 'true' : 'false');
    });
  }

  function v24BindRowEvents(scope, rows, copyOut) {
    rows.forEach(function (row) {
      row.addEventListener('click', function () { v24SelectRow(scope, rows, row, copyOut); });
      row.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter' || ev.key === ' ') {
          ev.preventDefault();
          v24SelectRow(scope, rows, row, copyOut);
        } else if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
          ev.preventDefault();
          var vis = rows.filter(function (r) { return !r.hidden; });
          var next = vis[vis.indexOf(row) + (ev.key === 'ArrowDown' ? 1 : -1)];
          if (next) { next.focus(); v24SelectRow(scope, rows, next, copyOut); }
        }
      });
    });
  }

  function v24BindCopy(scope, rows, copyBtn, copyOut) {
    if (!copyBtn) return;
    copyBtn.addEventListener('click', function () {
      var active = scope.querySelector('.v24-row[aria-selected="true"]') || rows[0];
      if (!active || active.hidden) return;
      var summary = ['data-ev-ts', 'data-ev-svc', 'data-ev-span', 'data-ev-trace', 'data-ev-code', 'data-ev-msg']
        .map(function (attr) { return active.getAttribute(attr); }).join(' | ');
      if (global.navigator && global.navigator.clipboard && global.navigator.clipboard.writeText) {
        global.navigator.clipboard.writeText(summary).catch(function () {});
      }
      if (copyOut) copyOut.textContent = 'Copied ' + (active.getAttribute('data-ev-trace') || 'trace');
    });
  }

  function wireV24(scope) {
    if (!scope || scope.dataset.w2Bound === '1') return;
    scope.dataset.w2Bound = '1';
    var activeCat = 'all', activeBucket = null;
    var filterBtns = scope.querySelectorAll('[data-v24-filter]');
    var searchInput = scope.querySelector('[data-v24-search]');
    var rows = Array.prototype.slice.call(scope.querySelectorAll('.v24-row'));
    var tableEl = scope.querySelector('[data-v24-table]');
    var emptyEl = scope.querySelector('[data-v24-empty]');
    var clearBtn = scope.querySelector('[data-v24-clear]');
    var countEl = scope.querySelector('[data-v24-visible-count]');
    var copyOut = scope.querySelector('[data-v24-copy-status]');

    function applyFilters() {
      var q = searchInput ? searchInput.value.trim().toLowerCase() : '', visibleRows = [];
      rows.forEach(function (tr) {
        var okCat = activeCat === 'all' || (tr.getAttribute('data-v24-cat') || '') === activeCat;
        var okB = activeBucket === null || (tr.getAttribute('data-v24-bucket') || '') === String(activeBucket);
        var okQ = !q || (tr.getAttribute('data-v24-search') || '').indexOf(q) !== -1;
        var vis = okCat && okB && okQ;
        tr.hidden = !vis;
        if (vis) visibleRows.push(tr);
      });
      if (countEl) countEl.textContent = 'Showing ' + visibleRows.length + ' / ' + rows.length + ' events';
      if (tableEl) tableEl.hidden = visibleRows.length === 0;
      if (emptyEl) emptyEl.hidden = visibleRows.length !== 0;
      if (visibleRows.length === 0) {
        rows.forEach(function (r) { r.setAttribute('aria-selected', 'false'); });
        v24SetInspectorEmpty(scope, true);
      } else if (visibleRows.every(function (r) { return r.getAttribute('aria-selected') !== 'true'; })) {
        v24SelectRow(scope, rows, visibleRows[0], copyOut);
      } else {
        v24SetInspectorEmpty(scope, false);
      }
    }
    filterBtns.forEach(function (btn) {
      btn.addEventListener('click', function () {
        activeCat = btn.getAttribute('data-v24-filter') || 'all';
        if (activeCat === 'all') { activeBucket = null; v24SyncBucketButtons(scope, null); }
        filterBtns.forEach(function (b) { b.setAttribute('aria-pressed', b === btn ? 'true' : 'false'); });
        applyFilters();
      });
    });
    function toggleBucket(grp) {
      var b = grp.getAttribute('data-v24-bucket');
      activeBucket = activeBucket === b ? null : b;
      v24SyncBucketButtons(scope, activeBucket);
      applyFilters();
    }
    scope.addEventListener('click', function (ev) {
      var grp = ev.target && ev.target.closest ? ev.target.closest('.w2-svg-bar-grp[data-v24-bucket]') : null;
      if (grp) toggleBucket(grp);
    });
    scope.addEventListener('keydown', function (ev) {
      var grp = ev.target && ev.target.closest ? ev.target.closest('.w2-svg-bar-grp[data-v24-bucket]') : null;
      if (grp && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); toggleBucket(grp); }
    });
    if (searchInput) searchInput.addEventListener('input', applyFilters);
    if (clearBtn) {
      clearBtn.addEventListener('click', function () {
        activeCat = 'all'; activeBucket = null;
        if (searchInput) searchInput.value = '';
        filterBtns.forEach(function (b) { b.setAttribute('aria-pressed', b.getAttribute('data-v24-filter') === 'all' ? 'true' : 'false'); });
        v24SyncBucketButtons(scope, null);
        applyFilters();
      });
    }
    v24BindRowEvents(scope, rows, copyOut);
    v24BindCopy(scope, rows, scope.querySelector('[data-v24-copy]'), copyOut);
  }

  function wireV25(scope) {
    if (!scope || scope.dataset.w2Bound === '1') return;
    scope.dataset.w2Bound = '1';
    scope.dataset.v25ActiveSpan = 'all';
    var btns = scope.querySelectorAll('[data-v25-span]');
    btns.forEach(function (btn) {
      btn.addEventListener('click', function () {
        var grp = btn.getAttribute('data-v25-span') || 'all';
        scope.dataset.v25ActiveSpan = grp;
        btns.forEach(function (b) { b.setAttribute('aria-pressed', b === btn ? 'true' : 'false'); });
        scope.querySelectorAll('.w2-span-node, .w2-span-mark, .w2-span-row').forEach(function (el) {
          var mine = el.getAttribute('data-span-group') === grp;
          if (grp === 'all') {
            el.removeAttribute('data-span-dim');
            el.removeAttribute('data-span-hot');
          } else {
            el.setAttribute('data-span-dim', mine ? '0' : '1');
            el.setAttribute('data-span-hot', mine ? '1' : '0');
          }
        });
      });
    });
  }

  function computeV26(gPct, cPct, floorMo) {
    var g = gPct / 100.0, c = cPct / 100.0, upB = (250.0 + 275.0 * c) / 1000.0;
    var multB = c * 0.56 + (1.0 - c) * 1.05, ptsA = [0.0], ptsB = [upB], ptsC = [2.10];
    var cumA = 0.0, cumB = upB, cumC = 2.10, cross = null, crossC = null;
    for (var m = 1; m <= 36; m += 1) {
      var paygo = (110.0 * Math.pow(1.0 + g, (m - 1) / 12.0)) / 1000.0;
      var colo = (64.0 + 12.0 * Math.pow(1.0 + 0.5 * g, (m - 1) / 12.0)) / 1000.0;
      cumA += paygo; cumB += paygo * multB; cumC += colo;
      ptsA.push(cumA); ptsB.push(cumB); ptsC.push(cumC);
      if (cross === null && cumB <= cumA) cross = m;
      if (crossC === null && cumC <= cumA) crossC = m;
    }
    var runA = Math.max(14, Math.round(38 - g * 18)), runB = Math.max(16, Math.round(36 - c * 4 - g * 10)), runC = Math.max(10, Math.round(22 - g * 12));
    var totalA = Math.round(cumA * 100) / 100, totalB = Math.round(cumB * 100) / 100, totalC = Math.round(cumC * 100) / 100;
    var feasA = runA >= floorMo, feasB = runB >= floorMo, feasC = runC >= floorMo;
    var opts = [
      { name: 'Option B Hybrid', tot: totalB, ok: feasB },
      { name: 'Option A PayGo', tot: totalA, ok: feasA },
      { name: 'Option C Colo', tot: totalC, ok: feasC },
    ];
    var compliant = opts.filter(function (x) { return x.ok && x.tot <= 5.20; }).sort(function (x, y) { return x.tot - y.tot; });
    var anyRun = opts.some(function (x) { return x.ok; });
    var cStatus = compliant.length ? 'compliant' : (anyRun ? 'over_constrained' : 'runway_blocked');
    var winner = compliant.length ? compliant[0].name : (anyRun ? 'Over-Constrained' : 'None (Runway Blocked)');
    var recState = compliant.length ? 'nominal' : (anyRun ? 'warn' : 'fault');
    return {
      ptsA: ptsA, ptsB: ptsB, ptsC: ptsC, upB: Math.round(upB * 100) / 100,
      totalA: totalA, totalB: totalB, totalC: totalC,
      savings: Math.round((totalA - totalB) * 100) / 100, savingsC: Math.round((totalA - totalC) * 100) / 100,
      crossover: cross, crossoverC: crossC, runA: runA, runB: runB, runC: runC,
      feasA: feasA, feasB: feasB, feasC: feasC, winner: winner, recState: recState, constraintStatus: cStatus,
      yMax: Math.max(totalA, totalB, totalC) > 6.2 ? 8.0 : 6.5,
    };
  }

  function readV26Geom(scope) {
    var svg = scope.querySelector('[data-v26-svg]'), g = null;
    try { g = svg ? JSON.parse(svg.getAttribute('data-v26-geom') || 'null') : null; } catch (e) { g = null; }
    var ml = g && g.ml ? g.ml : 48, mr = g && g.mr ? g.mr : 14, w = g && g.w ? g.w : 1120;
    var yTop = g && g.yTop && g.yTop >= 32 ? g.yTop : 38, lineTop = g && g.lineTop ? g.lineTop : 24, yBot = g && g.yBot ? g.yBot : 232;
    return { ml: ml, mr: mr, w: w, pw: Math.max(180, w - ml - mr), yTop: yTop, lineTop: lineTop, yBot: yBot, spanY: yBot - yTop, mobile: !!(g && g.mobile) };
  }

  function polyPath(vals, yMax, geom) {
    return 'M ' + vals.map(function (v, m) {
      return (geom.ml + (m / 36.0) * geom.pw).toFixed(1) + ' ' + (geom.yBot - (Math.min(yMax, v) / yMax) * geom.spanY).toFixed(1);
    }).join(' L ');
  }

  function setAttrs(el, attrs) {
    if (el) Object.keys(attrs).forEach(function (k) { el.setAttribute(k, String(attrs[k])); });
  }

  function renderV26YGrid(yGrid, yMax, geom) {
    if (!yGrid || !yGrid.ownerDocument) return;
    while (yGrid.firstChild) yGrid.removeChild(yGrid.firstChild);
    var ns = 'http://www.w3.org/2000/svg';
    (yMax > 7.0 ? [0.0, 2.0, 4.0, 6.0, 8.0] : [0.0, 2.0, 4.0, 6.0]).forEach(function (v) {
      var yy = geom.yBot - (v / yMax) * geom.spanY;
      var ln = yGrid.ownerDocument.createElementNS(ns, 'line');
      setAttrs(ln, { x1: geom.ml, y1: yy.toFixed(1), x2: geom.ml + geom.pw, y2: yy.toFixed(1), stroke: 'var(--border-subtle)', 'stroke-dasharray': '2 3' });
      var tx = yGrid.ownerDocument.createElementNS(ns, 'text');
      setAttrs(tx, { x: geom.ml - 6, y: (yy + 4).toFixed(1), 'text-anchor': 'end', 'font-size': '11.5', fill: 'var(--text-muted)' });
      tx.textContent = '$' + v.toFixed(1) + 'M';
      yGrid.appendChild(ln); yGrid.appendChild(tx);
    });
  }

  function fmtSav(diff) { return diff >= 0 ? '$' + diff.toFixed(2) + 'M saved' : '+$' + Math.abs(diff).toFixed(2) + 'M cost'; }

  function syncV26MatrixAndCards(scope, mod, r) {
    var cbTxt = mod.crossover !== null ? 'Month ' + mod.crossover : 'No crossover';
    var savTxt = mod.savings >= 0 ? 'Saves $' + mod.savings.toFixed(2) + 'M vs PayGo' : '+$' + Math.abs(mod.savings).toFixed(2) + 'M vs PayGo';
    if (mod.constraintStatus === 'over_constrained') savTxt = 'Raise commit >= 75% or adjust $5.20M ceiling';
    else if (mod.constraintStatus === 'runway_blocked') savTxt = 'No option meets ' + r + ' mo runway floor';
    var kpiMap = {
      winner: mod.winner, savings: savTxt, crossover: cbTxt,
      cross_sub: mod.crossover !== null ? 'Option B crosses below Option A' : 'Option B stays above Option A',
      total_b: '$' + mod.totalB.toFixed(2) + 'M',
      total_sub: mod.totalB > 5.20 ? '+$' + (mod.totalB - 5.20).toFixed(2) + 'M over $5.20M ceiling' : 'vs $5.20M budget ceiling',
      runway_b: mod.runB + ' mo', runway_note: 'Option C ' + mod.runC + ' mo vs ' + r + ' mo floor',
    };
    Object.keys(kpiMap).forEach(function (k) { var el = scope.querySelector('[data-v26-kpi="' + k + '"]'); if (el) el.textContent = kpiMap[k]; });
    var winTile = scope.querySelector('[data-v26-kpi-tile="winner"]'), totTile = scope.querySelector('[data-v26-kpi-tile="total"]');
    var runTile = scope.querySelector('[data-v26-kpi-tile="runway"]'), badge = scope.querySelector('[data-v26-rec-badge]');
    if (winTile) winTile.setAttribute('data-state', mod.recState);
    if (totTile) totTile.setAttribute('data-state', mod.totalB > 5.20 ? 'warn' : 'nominal');
    if (runTile) runTile.setAttribute('data-state', mod.feasC ? 'nominal' : 'warn');
    if (badge) {
      badge.setAttribute('data-state', mod.recState);
      badge.textContent = mod.constraintStatus === 'over_constrained' ? 'OVER-CONSTRAINED · > $5.20M CEILING' : (mod.recState === 'fault' ? 'RUNWAY GATE BLOCKED' : 'RECOMMENDED: ' + mod.winner.toUpperCase());
    }
    var disp = function (name, feas, tot) { return !feas ? 'RUNWAY BLOCKED' : (tot > 5.20 ? 'OVER CEILING' : (mod.winner === name ? 'RECOMMENDED' : 'VIABLE')); };
    var mat = {
      upfront: ['$0.00M', '$' + mod.upB.toFixed(2) + 'M', '$2.10M'],
      total: ['$' + mod.totalA.toFixed(2) + 'M', '$' + mod.totalB.toFixed(2) + 'M', '$' + mod.totalC.toFixed(2) + 'M'],
      savings: ['$0.00M (Base)', fmtSav(mod.savings), fmtSav(mod.savingsC)],
      crossover: ['Baseline', cbTxt, mod.crossoverC !== null ? 'Month ' + mod.crossoverC : 'No crossover'],
      runway: [mod.runA + ' mo', mod.runB + ' mo', mod.runC + ' mo'],
      cap: [mod.totalA <= 5.2 ? 'Within Cap' : 'Over Ceiling', mod.totalB <= 5.2 ? 'Within Cap' : 'Over Ceiling', mod.totalC <= 5.2 ? 'Within Cap' : 'Over Ceiling'],
      disp: [disp('Option A PayGo', mod.feasA, mod.totalA), disp('Option B Hybrid', mod.feasB, mod.totalB), disp('Option C Colo', mod.feasC, mod.totalC)],
    };
    Object.keys(mat).forEach(function (rk) {
      var row = scope.querySelector('[data-v26-row="' + rk + '"]');
      if (row) ['a', 'b', 'c'].forEach(function (col, idx) { var cell = row.querySelector('[data-col="' + col + '"]'); if (cell) cell.textContent = mat[rk][idx]; });
    });
  }

  function wireV26(scope) {
    if (!scope || scope.dataset.w2Bound === '1') return;
    scope.dataset.w2Bound = '1';
    var gEl = scope.querySelector('[data-v26-input="growth"]'), cEl = scope.querySelector('[data-v26-input="commit"]'), rEl = scope.querySelector('[data-v26-input="runway"]');
    if (!gEl || !cEl || !rEl) return;
    function update() {
      [gEl, cEl, rEl].forEach(function (inp) {
        var mn = Number(inp.min || 0), mx = Number(inp.max || 100), val = Number(inp.value || 0);
        inp.style.setProperty('--pct', (mx > mn ? ((val - mn) / (mx - mn)) * 100 : 50).toFixed(1) + '%');
      });
      var g = Number(gEl.value), c = Number(cEl.value), r = Number(rEl.value), mod = computeV26(g, c, r), geom = readV26Geom(scope);
      var outs = { growth: g + '%', commit: c + '%', runway: r + ' mo' };
      Object.keys(outs).forEach(function (k) { var el = scope.querySelector('[data-v26-out="' + k + '"]'); if (el) el.textContent = outs[k]; });
      syncV26MatrixAndCards(scope, mod, r);
      renderV26YGrid(scope.querySelector('[data-v26-ygrid]'), mod.yMax, geom);
      var yCeil = geom.yBot - (5.2 / mod.yMax) * geom.spanY;
      setAttrs(scope.querySelector('[data-v26-ceil-line]'), { x1: geom.ml, x2: geom.ml + geom.pw, y1: yCeil.toFixed(1), y2: yCeil.toFixed(1) });
      setAttrs(scope.querySelector('[data-v26-ceil-bg]'), { x: geom.ml + 6, y: (yCeil - 18).toFixed(1) });
      setAttrs(scope.querySelector('[data-v26-ceil-lbl]'), { x: geom.ml + 12, y: (yCeil - 6).toFixed(1) });
      setAttrs(scope.querySelector('[data-v26-path="a"]'), { d: polyPath(mod.ptsA, mod.yMax, geom) });
      setAttrs(scope.querySelector('[data-v26-path="b"]'), { d: polyPath(mod.ptsB, mod.yMax, geom) });
      setAttrs(scope.querySelector('[data-v26-path="c"]'), { d: polyPath(mod.ptsC, mod.yMax, geom) });
      var cl = scope.querySelector('[data-v26-cross-line]'), cd = scope.querySelector('[data-v26-cross-dot]');
      var cb = scope.querySelector('[data-v26-cross-bg]'), ct = scope.querySelector('[data-v26-cross-lbl]');
      if (mod.crossover === null) {
        [cl, cd, cb, ct].forEach(function (n) { if (n) n.setAttribute('display', 'none'); });
      } else {
        var cx = geom.ml + (mod.crossover / 36.0) * geom.pw, cy = geom.yBot - (Math.min(mod.yMax, mod.ptsB[mod.crossover]) / mod.yMax) * geom.spanY;
        var boxW = geom.mobile ? 132 : 184, boxX = Math.min(cx + 8.0, geom.ml + geom.pw - boxW);
        [cl, cd, cb, ct].forEach(function (n) { if (n) n.removeAttribute('display'); });
        setAttrs(cl, { x1: cx.toFixed(1), x2: cx.toFixed(1), y1: geom.lineTop, y2: geom.yBot });
        setAttrs(cd, { cx: cx.toFixed(1), cy: cy.toFixed(1) });
        setAttrs(cb, { x: boxX.toFixed(1), y: Math.max(20.0, cy - 26).toFixed(1), width: boxW });
        setAttrs(ct, { x: (boxX + 6).toFixed(1), y: Math.max(33.0, cy - 13).toFixed(1) });
        if (ct) ct.textContent = geom.mobile ? 'Crossover (Mo ' + mod.crossover + ')' : 'Break-Even Crossover (Mo ' + mod.crossover + ')';
      }
    }
    scope._v26Refresh = update;
    [gEl, cEl, rEl].forEach(function (el) { el.addEventListener('input', update); el.addEventListener('change', update); });
    update();
  }

  function bootWave2(root) {
    var doc = root || document;
    doc.querySelectorAll('[data-v23-scope]').forEach(wireV23);
    doc.querySelectorAll('[data-v24-scope]').forEach(wireV24);
    doc.querySelectorAll('[data-v25-scope]').forEach(wireV25);
    doc.querySelectorAll('[data-v26-root]').forEach(wireV26);
    if (global.QuietWave2Svg && typeof global.QuietWave2Svg.boot === 'function') {
      global.QuietWave2Svg.boot(doc);
    }
  }

  global.QuietWave2Runtime = { boot: bootWave2 };
  if (typeof document !== 'undefined' && document) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { bootWave2(document); });
    else bootWave2(document);
  }
})(typeof window !== 'undefined' ? window : globalThis);
