/* SPDX-License-Identifier: MIT */
/* mcp-adv-netutils Public Site - 4-Theme Sync, Popovers, Quickstart, Docs Filter & Code Copy */
(() => {
  const THEME_KEY = "netutils_theme";
  const SVG_NS = "http://www.w3.org/2000/svg";
  const PAD = 8;
  const THEMES = {
    white: { scheme: "light", bg: "#FFFFFF" },
    paper: { scheme: "light", bg: "#F6F4EF" },
    "dark-paper": { scheme: "dark", bg: "#141312" },
    dark: { scheme: "dark", bg: "#090D16" },
  };
  const QUICKSTARTS = {
    stdio: {
      cmd: "docker run -i --rm ghcr.io/frankxlt/mcp-adv-netutils:latest --stdio",
      caption: "Runs all 33 network check, saved destination, and monitoring tools locally over --stdio — zero open ports or secrets required.",
    },
    http: {
      cmd: "./mcp-adv-netutils --http --http-addr=:8000 --data-dir=./data",
      caption: "Starts Network Studio (/web), Saved Destinations, 30-day history, 5-minute monitoring, and remote/LAN MCP doorways.",
    },
    compose: {
      cmd: "docker compose up -d",
      caption: "Launches the single compact container with persistent /data history, 5-minute monitoring, and Network Studio (/web).",
    },
  };
  const MCP_TOOL_CATALOG_META = {
    total: 33,
    featuredTool: "manage_saved_destinations",
    featuredDetail: "list | save | delete | run with TargetGuard validation and automatic dest_<id> cron watchlist synchronization",
  };

  const mql = (q) => (typeof window.matchMedia === "function" ? window.matchMedia(q) : null);
  const byId = (id) => document.getElementById(id);
  const darkMql = mql("(prefers-color-scheme: dark)");
  const reducedMotionMql = mql("(prefers-reduced-motion: reduce)");
  const desktopMql = mql("(min-width: 900px)");
  const copyTimers = new WeakMap();
  let currentTheme = "white";
  let lastCopyMsg = "";

  function mk(tag, cls, text, attrs) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (attrs) for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    return node;
  }

  function makeSvgIcon(cls, shapes) {
    const svg = document.createElementNS(SVG_NS, "svg");
    const attrs = { class: cls, viewBox: "0 0 24 24", width: "16", height: "16", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" };
    for (const [k, v] of Object.entries(attrs)) svg.setAttribute(k, v);
    for (const [tag, sAttrs] of shapes) {
      const node = document.createElementNS(SVG_NS, tag);
      for (const [k, v] of Object.entries(sAttrs)) node.setAttribute(k, v);
      svg.appendChild(node);
    }
    return svg;
  }

  function normalizeTheme(raw) {
    const key = String(raw || "").trim();
    if (Object.hasOwn(THEMES, key)) return key;
    if (key === "system") return darkMql && darkMql.matches ? "dark" : "white";
    return null;
  }

  function readSafe(fn) {
    try { return normalizeTheme(fn()); } catch (_e) { return null; }
  }

  function syncThemeUI(rawTheme) {
    const theme = normalizeTheme(rawTheme) || "white";
    const meta = THEMES[theme];
    currentTheme = theme;
    document.documentElement.setAttribute("data-theme", theme);
    document.querySelector('meta[name="color-scheme"]')?.setAttribute("content", meta.scheme);
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", meta.bg);
    document.querySelectorAll("[data-theme-opt]").forEach((btn) => {
      const active = btn.getAttribute("data-theme-opt") === theme;
      btn.setAttribute("aria-pressed", String(active));
      btn.classList.toggle("is-active", active);
    });
    const studioSelect = byId("themeSelect");
    if (studioSelect && studioSelect.value !== theme) studioSelect.value = theme;
    return theme;
  }

  function setTheme(rawTheme, persist = true) {
    const theme = syncThemeUI(rawTheme);
    if (persist) { try { localStorage.setItem(THEME_KEY, theme); } catch (_e) {} }
    const detail = { theme };
    window.dispatchEvent(new CustomEvent("netutils-theme-changed", { detail }));
    window.dispatchEvent(new CustomEvent("v9-theme-changed", { detail }));
    return theme;
  }

  function initThemeControls() {
    const urlTheme = readSafe(() => new URLSearchParams(window.location.search).get("theme"));
    const stored = () => readSafe(() => localStorage.getItem(THEME_KEY));
    const docTheme = normalizeTheme(document.documentElement.getAttribute("data-theme"));
    setTheme(urlTheme || stored() || docTheme || "white", Boolean(urlTheme));
    document.querySelectorAll("[data-theme-opt]").forEach((btn) => btn.addEventListener("click", () => setTheme(btn.getAttribute("data-theme-opt"), true)));
    byId("themeSelect")?.addEventListener("change", (ev) => setTheme(ev.target.value, true));
    window.addEventListener("storage", (ev) => { if (ev.key === null || ev.key === THEME_KEY) syncThemeUI(stored() || "white"); });
    window.addEventListener("netutils-theme-changed", (ev) => {
      const next = normalizeTheme(ev?.detail?.theme);
      if (next && next !== currentTheme) syncThemeUI(next);
    });
  }

  function clearPopoverPosition(pop) {
    if (!pop) return;
    Object.assign(pop.style, { position: "", margin: "", inset: "", top: "", left: "" });
    pop.style.removeProperty("position-anchor");
  }

  function clampPopover(pop, trigger, alignRight) {
    if (!pop || !trigger) return;
    clearPopoverPosition(pop);
    const rect = pop.getBoundingClientRect();
    const trig = trigger.getBoundingClientRect();
    const anchored = typeof CSS !== "undefined" && typeof CSS.supports === "function" && CSS.supports("position-area", "block-end");
    const overflows = rect.right > window.innerWidth - PAD || rect.left < PAD;
    if (anchored && !overflows && rect.bottom <= window.innerHeight - PAD) return;
    const maxLeft = Math.max(PAD, window.innerWidth - rect.width - PAD);
    const rawLeft = alignRight ? trig.right - rect.width : trig.left;
    const rawTop = Math.min(trig.bottom + 6, Math.max(PAD, window.innerHeight - rect.height - PAD));
    pop.style.setProperty("position-anchor", "none");
    Object.assign(pop.style, { position: "fixed", margin: "0", inset: "auto", top: `${Math.round(Math.max(PAD, rawTop))}px`, left: `${Math.round(Math.min(Math.max(PAD, rawLeft), maxLeft))}px` });
  }

  function initTopbarPopovers() {
    const entries = [
      { popId: "oawContextPopover", alignRight: false },
      { popId: "oawPillarPopover", alignRight: true },
      { popId: "oawUserPopover", alignRight: true },
    ].map((it) => ({ ...it, el: byId(it.popId), trigger: document.querySelector(`[popovertarget="${it.popId}"]`) })).filter((it) => it.el && it.trigger);
    if (!entries.length) return;
    const native = typeof HTMLElement !== "undefined" && Object.hasOwn(HTMLElement.prototype, "popover");
    const isOpen = (el) => (native ? el.matches(":popover-open") : el.classList.contains("is-open"));
    const closeAll = (exceptEl = null) => entries.forEach(({ el, trigger }) => {
      if (el === exceptEl) return;
      if (native) { try { if (el.matches(":popover-open")) el.hidePopover(); } catch (_e) {} return; }
      el.classList.remove("is-open"); clearPopoverPosition(el); trigger.setAttribute("aria-expanded", "false");
    });

    entries.forEach((entry) => {
      if (!native) {
        entry.trigger.addEventListener("click", () => {
          const opening = !isOpen(entry.el);
          closeAll(opening ? entry.el : null);
          entry.el.classList.toggle("is-open", opening);
          entry.trigger.setAttribute("aria-expanded", String(opening));
          if (opening) clampPopover(entry.el, entry.trigger, entry.alignRight);
          else clearPopoverPosition(entry.el);
        });
      }
      entry.el.addEventListener("toggle", (ev) => {
        const open = ev.newState === "open";
        entry.trigger.setAttribute("aria-expanded", String(open));
        if (open) requestAnimationFrame(() => clampPopover(entry.el, entry.trigger, entry.alignRight));
        else clearPopoverPosition(entry.el);
      });
      entry.el.addEventListener("click", (ev) => {
        const origin = ev.target instanceof Element ? ev.target : ev.target?.parentElement;
        if (origin && origin.closest("a[href]")) closeAll(null);
      });
    });

    document.addEventListener("keydown", (ev) => {
      if (ev.key !== "Escape") return;
      const openEntry = entries.find(({ el }) => isOpen(el));
      if (!openEntry) return;
      if (!native) closeAll(null);
      requestAnimationFrame(() => openEntry.trigger.focus({ preventScroll: true }));
    });
    if (!native) {
      document.addEventListener("click", (ev) => {
        const path = typeof ev.composedPath === "function" ? ev.composedPath() : [ev.target];
        if (!entries.some(({ el, trigger }) => path.includes(el) || path.includes(trigger))) closeAll(null);
      });
    }
    window.addEventListener("resize", () => entries.forEach((entry) => { if (isOpen(entry.el)) clampPopover(entry.el, entry.trigger, entry.alignRight); }));
  }

  function initQuickstartSwitcher() {
    const cmdEl = byId("quickstart-cmd");
    if (!cmdEl) return;
    const capEl = byId("quickstartCaption");
    const boxEl = byId("quickstartBox");
    const setMode = (mode, sourceBtn, scrollIntoView = false) => {
      const key = Object.hasOwn(QUICKSTARTS, mode) ? mode : "stdio";
      const cfg = QUICKSTARTS[key];
      cmdEl.textContent = sourceBtn?.dataset?.quickstartCmd || cfg.cmd;
      if (capEl) capEl.textContent = sourceBtn?.dataset?.quickstartCaption || cfg.caption;
      document.querySelectorAll("[data-quickstart-mode]").forEach((btn) => {
        const active = btn.getAttribute("data-quickstart-mode") === key;
        btn.setAttribute("aria-pressed", String(active));
        if (btn.classList.contains("hero-cmd-pill")) btn.classList.toggle("is-selected", active);
      });
      if (scrollIntoView && boxEl) boxEl.scrollIntoView({ behavior: reducedMotionMql?.matches ? "auto" : "smooth", block: "nearest" });
    };
    document.querySelectorAll("[data-quickstart-mode]").forEach((btn) => {
      btn.addEventListener("click", () => setMode(btn.getAttribute("data-quickstart-mode"), btn, btn.classList.contains("hero-cmd-pill")));
    });
  }

  function reportCopy(button, ok) {
    if (!button) return;
    const sib = button.nextElementSibling;
    const tip = sib?.getAttribute("role") === "status" ? sib : button.parentElement?.querySelector('[role="status"]');
    clearTimeout(copyTimers.get(button));
    button.removeAttribute("data-copied"); button.removeAttribute("data-failed");
    let message = ok ? "Copied" : "Copy failed";
    if (message === lastCopyMsg) message += "\u00A0";
    lastCopyMsg = message;
    if (tip) tip.textContent = "";
    void button.offsetWidth;
    button.setAttribute(ok ? "data-copied" : "data-failed", "true");
    requestAnimationFrame(() => { if (tip) tip.textContent = message; });
    copyTimers.set(button, setTimeout(() => { button.removeAttribute("data-copied"); button.removeAttribute("data-failed"); if (tip) tip.textContent = ""; }, 2000));
  }

  async function runCopyCommand(button, targetEl) {
    if (!button) return;
    const targetId = button.getAttribute("commandfor") || button.getAttribute("data-copy-target") || "quickstart-cmd";
    const target = targetEl || byId(targetId) || button.closest(".copy-box")?.querySelector("pre");
    const raw = target ? (target.matches("input, textarea") ? target.value : (target.innerText || target.textContent || "")) : "";
    const text = String(raw).trim();
    if (!text) { reportCopy(button, false); return; }
    try {
      if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") throw new Error("no clipboard");
      await navigator.clipboard.writeText(text);
      reportCopy(button, true);
    } catch (_e) { reportCopy(button, false); }
  }

  function initCopyCommands() {
    document.addEventListener("command", (ev) => { if (ev.command === "--copy") runCopyCommand(ev.source, ev.target); }, true);
    document.addEventListener("click", (ev) => {
      if (ev.defaultPrevented) return;
      const origin = ev.target instanceof Element ? ev.target : ev.target?.parentElement;
      if (!origin) return;
      const dataBtn = origin.closest("button[data-copy-target]");
      if (dataBtn) { runCopyCommand(dataBtn, byId(dataBtn.getAttribute("data-copy-target") || "")); return; }
      if (!("CommandEvent" in window)) {
        const cmdBtn = origin.closest('button[command="--copy"]');
        if (cmdBtn) runCopyCommand(cmdBtn, byId(cmdBtn.getAttribute("commandfor") || "quickstart-cmd"));
      }
    });
  }

  function enhanceCodeAndTables() {
    let seq = 0;
    document.querySelectorAll(".docs-main pre, [data-doc-section] pre, .docs-prose pre, .copy-box pre, pre[data-copyable]").forEach((pre) => {
      if (pre.hasAttribute("data-no-copy")) return;
      if (pre.classList.contains("ascii-preview") && !pre.hasAttribute("data-copyable") && !pre.closest(".copy-box")) return;
      if (!pre.hasAttribute("tabindex")) pre.setAttribute("tabindex", "0");
      if (!pre.id) { seq += 1; pre.id = `site-code-${seq}`; }
      let box = pre.closest(".copy-box");
      if (!box) { box = mk("div", "copy-box"); pre.parentNode.insertBefore(box, pre); box.appendChild(pre); }
      if (box.querySelector(".copy-btn")) return;
      const btn = mk("button", "copy-btn", null, { type: "button", command: "--copy", commandfor: pre.id, "aria-label": "Copy code block" });
      btn.append(
        makeSvgIcon("icon-copy", [["path", { d: "M11 9h9a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-9a2 2 0 0 1-2-2v-9a2 2 0 0 1 2-2Z" }], ["path", { d: "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" }]]),
        makeSvgIcon("icon-check", [["polyline", { points: "20 6 9 17 4 12" }]]),
      );
      const ctrl = mk("div", "copy-control");
      ctrl.append(btn, mk("span", "copy-tip", "", { role: "status", "aria-live": "polite" }));
      box.appendChild(ctrl);
    });
    document.querySelectorAll(".docs-prose table, [data-doc-section] table").forEach((table) => {
      if (table.closest(".doc-table-wrap, .va-table-wrap")) return;
      const wrap = mk("div", "doc-table-wrap", null, { tabindex: "0", role: "region", "aria-label": "Reference table" });
      table.parentNode.insertBefore(wrap, table);
      wrap.appendChild(table);
    });
  }

  function collectDocSections(tocList) {
    const sections = Array.from(document.querySelectorAll("[data-doc-section], .docs-chapter"));
    if (!sections.length) return { records: [], groupNodes: new Map() };
    const groupNodes = new Map();
    const existingLinks = new Map();
    if (tocList) tocList.querySelectorAll("a[href^='#']").forEach((a) => existingLinks.set(a.getAttribute("href"), a));
    let lastGroup = "";
    const records = sections.map((sec, idx) => {
      if (!sec.id) sec.id = `doc-section-${idx + 1}`;
      const slug = sec.getAttribute("data-slug") || sec.id.replace(/^doc-/, "");
      const titleEl = sec.querySelector(".docs-chapter-title, h2, h3");
      const title = sec.getAttribute("data-doc-title") || (titleEl ? titleEl.textContent.trim() : slug);
      const group = (sec.getAttribute("data-doc-group") || sec.getAttribute("data-group") || "").trim();
      const kw = sec.getAttribute("data-keywords") || "";
      let tocLink = existingLinks.get(`#${sec.id}`) || existingLinks.get(`#doc-${slug}`) || null;
      let tocItemEl = tocLink ? tocLink.closest("li") : null;
      if (tocList && !existingLinks.size) {
        if (group && group !== lastGroup) {
          lastGroup = group;
          const grpLi = mk("li", "docs-toc-group-label", group, { "aria-hidden": "true" });
          tocList.appendChild(grpLi); groupNodes.set(group, grpLi);
        }
        tocItemEl = mk("li", null, null, { "data-slug": slug });
        tocLink = mk("a", "docs-toc-link", title, { href: `#${sec.id}` });
        tocItemEl.appendChild(tocLink); tocList.appendChild(tocItemEl);
      }
      return { slug, anchorId: sec.id, title, group, sectionEl: sec, tocItemEl, tocLink, haystack: `${title} ${group} ${kw} ${slug} ${sec.textContent || ""}`.toLowerCase() };
    });
    return { records, groupNodes };
  }

  function makePagerLink(dir, label, rec) {
    const attrs = { "data-dir": dir, ...(rec ? { href: `#${rec.anchorId}` } : { "aria-disabled": "true" }) };
    const el = mk(rec ? "a" : "span", "docs-pager-link", null, attrs);
    el.append(mk("span", "docs-pager-label", label), mk("span", "docs-pager-title", rec ? rec.title : "None"));
    return el;
  }

  function syncDocsActiveUi(dom, records, state, slug) {
    if (!state.visible.length) {
      records.forEach((r) => r.tocLink?.removeAttribute("aria-current"));
      if (dom.pagerEl) dom.pagerEl.hidden = true;
      return;
    }
    const idx = Math.max(0, state.visible.findIndex((r) => r.slug === slug));
    state.activeSlug = state.visible[idx].slug;
    records.forEach((r) => {
      if (!r.tocLink) return;
      if (r.slug === state.activeSlug && !r.sectionEl.hidden) r.tocLink.setAttribute("aria-current", "true");
      else r.tocLink.removeAttribute("aria-current");
    });
    if (dom.pagerEl) {
      dom.pagerEl.hidden = false;
      dom.pagerEl.replaceChildren(
        makePagerLink("prev", "Previous chapter", idx > 0 ? state.visible[idx - 1] : null),
        makePagerLink("next", "Next chapter", idx < state.visible.length - 1 ? state.visible[idx + 1] : null),
      );
    }
  }

  function applyDocsFilter(dom, records, groupNodes, state, rawVal) {
    const raw = String(rawVal || "");
    const trimmed = raw.trim();
    const terms = trimmed ? trimmed.toLowerCase().split(/\s+/) : [];
    if (dom.clearBtn) dom.clearBtn.hidden = trimmed.length === 0;
    const activeGroups = new Set();
    state.visible = [];
    records.forEach((rec) => {
      const matched = terms.length === 0 || terms.every((t) => rec.haystack.includes(t));
      rec.sectionEl.hidden = !matched;
      if (rec.tocItemEl) rec.tocItemEl.hidden = !matched;
      if (trimmed && matched) rec.sectionEl.setAttribute("data-search-match", "true");
      else rec.sectionEl.removeAttribute("data-search-match");
      if (matched) { state.visible.push(rec); if (rec.group) activeGroups.add(rec.group); }
    });
    groupNodes.forEach((grpEl, grp) => { grpEl.hidden = !activeGroups.has(grp); });
    if (dom.statusEl) {
      dom.statusEl.textContent = trimmed ? `Showing ${state.visible.length} of ${records.length} sections for "${trimmed}"` : `Showing ${records.length} of ${records.length} sections`;
    }
    if (dom.emptyState) {
      const empty = state.visible.length === 0;
      if (empty && dom.emptyQuery) dom.emptyQuery.textContent = trimmed || raw;
      dom.emptyState.hidden = !empty; dom.emptyState.classList.toggle("hidden", !empty);
    }
    syncDocsActiveUi(dom, records, state, state.visible.some((r) => r.slug === state.activeSlug) ? state.activeSlug : (state.visible[0]?.slug || ""));
  }

  function jumpToDocAnchor(dom, records, groupNodes, state, hashStr, updateHash = true) {
    const id = String(hashStr || "").replace(/^#/, "");
    const rec = records.find((r) => r.anchorId === id || `doc-${r.slug}` === id);
    if (!rec) return;
    if (rec.sectionEl.hidden) { if (dom.searchInput) dom.searchInput.value = ""; applyDocsFilter(dom, records, groupNodes, state, ""); }
    state.lockUntil = Date.now() + 450;
    syncDocsActiveUi(dom, records, state, rec.slug);
    if (updateHash && location.hash !== `#${rec.anchorId}`) history.replaceState(null, "", `#${rec.anchorId}`);
    rec.sectionEl.scrollIntoView({ behavior: reducedMotionMql?.matches ? "auto" : "smooth", block: "start" });
    if (dom.tocToggle && dom.tocNav && !desktopMql?.matches) { dom.tocNav.classList.remove("is-open"); dom.tocToggle.setAttribute("aria-expanded", "false"); }
  }

  function bindDocsEvents(dom, records, groupNodes, state) {
    const resetSearch = () => {
      if (dom.searchInput) { dom.searchInput.value = ""; dom.searchInput.removeAttribute("aria-invalid"); dom.searchInput.focus(); }
      applyDocsFilter(dom, records, groupNodes, state, "");
    };
    if (dom.emptyState && !dom.emptyState.querySelector("[data-docs-reset]")) {
      const row = dom.emptyState.querySelector(".docs-empty-actions") || dom.emptyState.appendChild(mk("div", "docs-empty-actions"));
      const btn = mk("button", "site-btn site-btn-primary", "Clear search", { type: "button", "data-docs-reset": "1" });
      btn.addEventListener("click", resetSearch);
      row.prepend(btn);
    }
    dom.searchInput?.addEventListener("input", () => applyDocsFilter(dom, records, groupNodes, state, dom.searchInput.value));
    dom.searchInput?.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && dom.searchInput.value) { ev.preventDefault(); resetSearch(); } });
    dom.clearBtn?.addEventListener("click", resetSearch);
    document.addEventListener("click", (ev) => {
      const origin = ev.target instanceof Element ? ev.target : ev.target?.parentElement;
      if (!origin) return;
      if (origin.closest("[data-docs-reset]")) { ev.preventDefault(); resetSearch(); return; }
      const href = origin.closest('a[href^="#"]')?.getAttribute("href") || "";
      if (href && records.some((r) => `#${r.anchorId}` === href || `#doc-${r.slug}` === href)) { ev.preventDefault(); jumpToDocAnchor(dom, records, groupNodes, state, href, true); }
    });
    if (dom.tocToggle && dom.tocNav) {
      dom.tocNav.dataset.collapsible = "true"; dom.tocToggle.setAttribute("aria-expanded", "false");
      dom.tocToggle.addEventListener("click", () => {
        const nextOpen = !dom.tocNav.classList.contains("is-open");
        dom.tocNav.classList.toggle("is-open", nextOpen); dom.tocToggle.setAttribute("aria-expanded", String(nextOpen));
      });
    }
    if ("IntersectionObserver" in window && records.length) {
      const visibleSet = new Set();
      const observer = new IntersectionObserver((items) => {
        items.forEach((it) => (it.isIntersecting ? visibleSet.add(it.target) : visibleSet.delete(it.target)));
        if (Date.now() < state.lockUntil || !visibleSet.size) return;
        const hit = state.visible.find((r) => visibleSet.has(r.sectionEl));
        if (hit && hit.slug !== state.activeSlug) syncDocsActiveUi(dom, records, state, hit.slug);
      }, { rootMargin: "-18% 0px -62% 0px", threshold: [0, 0.1] });
      records.forEach((r) => observer.observe(r.sectionEl));
    }
    window.addEventListener("hashchange", () => { if (location.hash) jumpToDocAnchor(dom, records, groupNodes, state, location.hash, false); });
  }

  function initDocsController() {
    const tocList = byId("docsTocList");
    const searchInput = byId("docsSearchInput");
    const { records, groupNodes } = collectDocSections(tocList);
    if (!records.length && !searchInput) return;
    const dom = { searchInput, clearBtn: byId("docsSearchClearBtn"), statusEl: byId("docsSearchStatus"), emptyState: byId("docsEmptyState"), emptyQuery: byId("docsEmptyQuery"), tocNav: byId("docsTocNav") || tocList?.closest("nav"), tocToggle: byId("docsTocToggle"), pagerEl: byId("docsPager") };
    const state = { visible: records.slice(), activeSlug: records[0]?.slug || "", lockUntil: 0 };
    bindDocsEvents(dom, records, groupNodes, state);
    applyDocsFilter(dom, records, groupNodes, state, dom.searchInput ? dom.searchInput.value : "");
    if (location.hash) jumpToDocAnchor(dom, records, groupNodes, state, location.hash, false);
  }

  function initToolFilterBar() {
    const bar = byId("docsToolFilterBar");
    if (!bar) return;
    const statusEl = byId("docsToolFilterStatus");
    const sections = Array.from(document.querySelectorAll("#doc-tools [data-tool-section]"));
    const buttons = Array.from(bar.querySelectorAll("[data-tool-filter]"));
    const totalRows = sections.reduce((sum, sec) => sum + sec.querySelectorAll("tbody tr").length, 0) || MCP_TOOL_CATALOG_META.total;
    const applyFilter = (group) => {
      let visibleRows = 0;
      sections.forEach((sec) => {
        const show = group === "all" || sec.getAttribute("data-tool-section") === group;
        sec.hidden = !show;
        if (show) visibleRows += sec.querySelectorAll("tbody tr").length;
      });
      buttons.forEach((btn) => {
        const active = btn.getAttribute("data-tool-filter") === group;
        btn.setAttribute("aria-pressed", String(active));
        btn.classList.toggle("is-selected", active);
      });
      if (statusEl) statusEl.textContent = `Showing ${visibleRows} of ${totalRows} registered MCP tools`;
    };
    buttons.forEach((btn) => btn.addEventListener("click", () => applyFilter(btn.getAttribute("data-tool-filter") || "all")));
    byId("docsSearchInput")?.addEventListener("input", () => { if (byId("docsSearchInput")?.value.trim()) applyFilter("all"); });
    applyFilter("all");
  }

  function boot() {
    initThemeControls();
    initTopbarPopovers();
    initQuickstartSwitcher();
    initCopyCommands();
    enhanceCodeAndTables();
    initDocsController();
    initToolFilterBar();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot, { once: true });
  else boot();

  window.NetutilsSite = { setTheme, getTheme: () => currentTheme, toolCatalog: MCP_TOOL_CATALOG_META };
})();
