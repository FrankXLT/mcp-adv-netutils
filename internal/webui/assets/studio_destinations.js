(function (globalScope) {
  "use strict";

  const MAC_RE = /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i;
  const state = { mode: "locked", items: [], sweepResults: [], deps: null, lastSaveError: "", returnToManager: false };
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  };
  const progressApi = () => globalScope.NetUtilsStudioProgress || null;
  const isAborted = (err, prog) => {
    const api = progressApi();
    if (api && typeof api.isAbortError === "function" && api.isAbortError(err, prog)) return true;
    return Boolean((err && err.name === "AbortError") || (prog && prog.signal && prog.signal.aborted));
  };

  function makeChip(label, attr, val, title) {
    const chip = el("button", "va-pill", label);
    chip.type = "button"; chip.setAttribute("data-variant", "chip"); chip.setAttribute(attr, val);
    if (title) chip.title = title;
    return chip;
  }

  function populateCheckSelect() {
    const sel = $("destCheckSelect"), catalog = state.deps && state.deps.getCheckCatalog ? state.deps.getCheckCatalog() : [];
    if (!sel || !catalog.length) return;
    const groups = new Map();
    catalog.forEach((item) => {
      if (item.allowSavedDest === false) return;
      if (!groups.has(item.groupLabel)) groups.set(item.groupLabel, []);
      groups.get(item.groupLabel).push(item);
    });
    const frag = document.createDocumentFragment();
    groups.forEach((list, label) => {
      const og = document.createElement("optgroup"); og.label = label;
      list.forEach((item) => { const opt = document.createElement("option"); opt.value = item.id; opt.textContent = item.label; og.appendChild(opt); });
      frag.appendChild(og);
    });
    sel.replaceChildren(frag);
  }

  function renderPinnedBar() {
    const listEl = $("pinnedList");
    if (!listEl) return;
    const pinned = state.items.filter((d) => Boolean(d.pinned));
    if (!pinned.length) return listEl.replaceChildren(el("span", "card-meta", "Pin any saved destination below for 1-click checks."));
    const frag = document.createDocumentFragment();
    pinned.forEach((d) => frag.appendChild(makeChip(d.name, "data-dest-id", d.id, d.target + " · " + state.deps.getCheckLabel(d.default_check))));
    listEl.replaceChildren(frag);
  }

  function isVirtualMac(mac) {
    const clean = String(mac || "").trim().replace(/[:.-]/g, "");
    if (!/^[0-9a-f]{12}$/i.test(clean)) return false;
    const b = parseInt(clean.slice(0, 2), 16);
    return Number.isFinite(b) && (b & 0x02) !== 0;
  }

  function renderWakeChips() {
    const wrap = $("wakeMacChips");
    if (!wrap) return;
    const withMac = state.items.filter((d) => d.mac && String(d.mac).trim() !== "" && d.category !== "Containers" && !isVirtualMac(d.mac));
    if (!withMac.length) return wrap.replaceChildren(el("span", "card-meta", "Save a device with a MAC address to see quick wake chips here."));
    const frag = document.createDocumentFragment();
    withMac.forEach((d) => frag.appendChild(makeChip(d.name + " (" + d.mac + ")", "data-wake-id", d.id)));
    wrap.replaceChildren(frag);
  }

  function makeActionBtn(label, cls, action, id) {
    const btn = el("button", cls, label);
    btn.type = "button"; btn.setAttribute("data-dest-action", action); btn.setAttribute("data-dest-id", id);
    return btn;
  }

  function renderDestinationsTable() {
    const body = $("savedDestBody"), empty = $("savedDestEmpty"), wrap = $("savedDestTableWrap"), countEl = $("savedDestCount");
    if (!body) return;
    const list = state.items;
    if (countEl) countEl.textContent = list.length + (list.length === 1 ? " destination" : " destinations");
    if (empty) empty.hidden = list.length > 0;
    if (wrap) wrap.hidden = list.length === 0;
    if (!list.length) return body.replaceChildren();
    state.deps.renderTableRows(body, list, (d) => {
      const nameCell = el("div", "dest-name-cell"), subParts = [d.target, d.category || "Core"];
      if (d.mac) subParts.push("MAC " + d.mac);
      nameCell.append(el("strong", "", d.name), el("span", "dest-sub", subParts.join(" · ")));
      const pinBtn = makeActionBtn(d.pinned ? "Pinned" : "Pin", "va-btn va-btn-xs va-btn-ghost", "toggle-pin", d.id);
      pinBtn.setAttribute("aria-pressed", d.pinned ? "true" : "false");
      const monBtn = makeActionBtn(d.monitor_enabled ? "Every 5m" : "Paused", "va-btn va-btn-xs va-btn-ghost", "toggle-monitor", d.id);
      monBtn.setAttribute("aria-pressed", d.monitor_enabled ? "true" : "false");
      const actions = el("div", "row-actions");
      actions.append(
        makeActionBtn("Run Now", "va-btn va-btn-xs va-btn-secondary", "run", d.id),
        makeActionBtn("Edit", "va-btn va-btn-xs va-btn-ghost", "edit", d.id),
        makeActionBtn("Delete", "va-btn va-btn-xs va-btn-ghost va-btn-danger-ghost", "delete", d.id)
      );
      return { cells: [["Destination", nameCell], ["Default Check", state.deps.getCheckLabel(d.default_check)], ["Pinned", pinBtn], ["5-Min Monitor", monBtn], ["Actions", actions]] };
    });
  }

  function renderSweepSummary(results) {
    const strip = $("pinnedSweepSummary");
    if (!strip) return;
    state.sweepResults = Array.isArray(results) ? results : [];
    if (!state.sweepResults.length) {
      strip.replaceChildren(el("span", "card-meta", "No pinned destinations found to scan."));
      strip.hidden = false; return;
    }
    let okCount = 0, warnCount = 0, failCount = 0;
    const frag = document.createDocumentFragment();
    for (let i = 0; i < state.sweepResults.length; i += 1) {
      const r = state.sweepResults[i], out = r.outcome || {}, st = r.error ? "FAIL" : String(out.status || "OK").toUpperCase();
      if (st === "FAIL" || st === "ERROR") failCount += 1;
      else if (st === "WARN" || st === "WARNING") warnCount += 1;
      else okCount += 1;
      const dur = out.duration_ms ? " · " + out.duration_ms + " ms" : "";
      frag.appendChild(makeChip("[" + st + "] " + (r.destination ? r.destination.name : "Target") + dur, "data-sweep-index", String(i)));
    }
    strip.replaceChildren(el("strong", "", "Pinned Sweep: " + okCount + " OK, " + warnCount + " Warning, " + failCount + " Failed —"), frag);
    strip.hidden = false;
  }

  function renderQuickSavedList() {
    const listEl = $("quickSavedList"), emptyEl = $("quickSavedEmpty"), countEl = $("quickSavedCount");
    if (!listEl) return;
    const items = state.items;
    if (countEl) countEl.textContent = items.length + " saved";
    if (emptyEl) emptyEl.hidden = items.length > 0;
    listEl.hidden = items.length === 0;
    if (!items.length) return listEl.replaceChildren();
    const frag = document.createDocumentFragment();
    for (let i = 0; i < items.length; i += 1) {
      const d = items[i], row = el("li", "quick-saved-row"), info = el("div", "quick-saved-info");
      info.append(el("span", "quick-saved-name", d.name), el("span", "quick-saved-meta", d.target + " · " + state.deps.getCheckLabel(d.default_check)));
      const acts = el("div", "quick-saved-actions");
      acts.append(makeActionBtn("Run", "va-btn va-btn-xs va-btn-secondary", "run", d.id), makeActionBtn("Edit", "va-btn va-btn-xs va-btn-ghost", "edit", d.id));
      row.append(info, acts); frag.appendChild(row);
    }
    listEl.replaceChildren(frag);
  }

  function renderAll() {
    renderPinnedBar(); renderWakeChips(); renderQuickSavedList(); renderDestinationsTable();
    if (state.deps && state.deps.onDestinationsChanged) state.deps.onDestinationsChanged(state.items);
  }

  function setDestinations(items) { state.items = Array.isArray(items) ? items.slice() : []; renderAll(); }

  async function refresh() {
    if (state.mode !== "live") return renderAll();
    const r = await state.deps.apiFetch("./api/destinations");
    if (r.res.ok && Array.isArray(r.data.destinations)) setDestinations(r.data.destinations);
  }

  async function saveDestinationObj(payload) {
    if (!payload || !String(payload.name || "").trim() || !String(payload.target || "").trim()) {
      state.lastSaveError = "Enter a display name and target."; return false;
    }
    if (state.mode === "demo") {
      const nowSec = Math.floor(Date.now() / 1000);
      const copy = Object.assign({
        category: "Core", mac: "", default_check: "recipe_diff_ping",
        pinned: false, monitor_enabled: false, monitor_schedule: "*/5 * * * *", created_at: nowSec, updated_at: nowSec
      }, payload, { id: payload.id || ("dest_demo_" + Date.now().toString(36)) });
      const idx = state.items.findIndex((x) => x.id === copy.id);
      if (idx >= 0) state.items[idx] = Object.assign({}, state.items[idx], copy, { updated_at: nowSec });
      else state.items.unshift(copy);
      state.items.sort((a, b) => Number(b.pinned) - Number(a.pinned) || (b.updated_at || 0) - (a.updated_at || 0));
      state.lastSaveError = ""; renderAll(); return true;
    }
    const isEdit = Boolean(payload.id), url = isEdit ? "./api/destinations/" + encodeURIComponent(payload.id) : "./api/destinations";
    try {
      const r = await state.deps.apiFetch(url, { method: isEdit ? "PUT" : "POST", bodyObj: payload });
      if (!r.res.ok) { state.lastSaveError = (r.data && r.data.error) || "Unable to save destination."; return false; }
      state.lastSaveError = "";
      if (Array.isArray(r.data.destinations)) setDestinations(r.data.destinations); else await refresh();
      return true;
    } catch (_) { state.lastSaveError = "Unable to save destination."; return false; }
  }

  async function deleteDestinationById(id) {
    if (state.mode === "demo") { setDestinations(state.items.filter((x) => x.id !== id)); return state.deps.announce("Removed saved destination."); }
    try {
      const r = await state.deps.apiFetch("./api/destinations/" + encodeURIComponent(id), { method: "DELETE" });
      if (r && r.res && r.res.ok && Array.isArray(r.data && r.data.destinations)) {
        setDestinations(r.data.destinations);
        if (state.deps.onLiveWorkspaceRefresh) state.deps.onLiveWorkspaceRefresh();
        state.deps.announce("Removed saved destination.");
      } else state.deps.announce((r && r.data && r.data.error) || "Unable to remove destination.");
    } catch (_) { state.deps.announce("Unable to remove destination."); }
  }

  function reportRunError(errMsg, runSeq) {
    if (state.deps.onRunError) state.deps.onRunError(errMsg, runSeq);
    state.deps.announce(errMsg);
  }

  async function runDestinationById(id, triggerBtn) {
    const dest = state.items.find((x) => x.id === id);
    if (!dest) return;
    const inDrawer = Boolean(triggerBtn && triggerBtn.closest && triggerBtn.closest("#jobDrawer") && $("jobDrawer") && $("jobDrawer").open);
    const surface = inDrawer ? "drawer" : "main";
    const runSeq = surface === "main" && state.deps.onBeforeRun ? state.deps.onBeforeRun(dest.default_check, dest.target, state.mode === "live") : null;
    if (state.mode === "demo") {
      const out = state.deps.runDemoTool(dest.default_check, dest.target, { mac: dest.mac });
      state.deps.onShowOutcome(out, dest, runSeq);
      return state.deps.announce("Checked " + dest.name + ".");
    }
    const api = progressApi();
    const prog = api && typeof api.beginRun === "function" ? api.beginRun({
      surface, tool: dest.default_check, target: dest.target,
      label: "Checking " + dest.name, hint: api.describeCheckHint(dest.default_check, dest.target),
      triggerBtn, runningLabel: "Running…",
      onCancel: () => { if (state.deps.onRunCancelled) state.deps.onRunCancelled(runSeq, surface); }
    }) : null;
    if (!prog && triggerBtn) triggerBtn.setAttribute("aria-busy", "true");
    try {
      const r = await state.deps.apiFetch("./api/destinations/" + encodeURIComponent(id) + "/run", {
        method: "POST", bodyObj: { style: "json" }, signal: prog ? prog.signal : undefined
      });
      if (isAborted(null, prog)) return;
      if (!r || !r.res || !r.res.ok) return reportRunError((r && r.data && r.data.error) || "Destination check failed.", runSeq);
      state.deps.onShowOutcome(r.data, dest, runSeq);
      state.deps.announce("Checked " + dest.name + ".");
      if (state.deps.onLiveWorkspaceRefresh) state.deps.onLiveWorkspaceRefresh();
    } catch (err) {
      if (isAborted(err, prog)) return;
      reportRunError((err && err.message) || "Destination check failed.", runSeq);
    } finally {
      if (prog) prog.finish(); else if (triggerBtn) triggerBtn.setAttribute("aria-busy", "false");
    }
  }

  async function scanPinned() {
    const btn = $("scanPinnedBtn"), pinned = state.items.filter((d) => Boolean(d.pinned));
    if (!pinned.length) return renderSweepSummary([]);
    const runSeq = state.deps.onBeforeRun ? state.deps.onBeforeRun("recipe_diff_ping", pinned.length + " pinned targets", state.mode === "live") : null;
    state.deps.announce("Scanning " + pinned.length + " pinned destinations...");
    if (state.mode === "demo") {
      const results = pinned.map((d) => ({ destination: d, outcome: state.deps.runDemoTool(d.default_check, d.target, { mac: d.mac }) }));
      renderSweepSummary(results);
      const focus = results.find((x) => x.outcome && x.outcome.status !== "OK") || results.find((x) => x.outcome);
      if (focus && focus.outcome) state.deps.onShowOutcome(focus.outcome, focus.destination, runSeq);
      return state.deps.announce("Completed pinned destination scan.");
    }
    const api = progressApi();
    const prog = api && typeof api.beginRun === "function" ? api.beginRun({
      surface: "main", tool: "pinned_sweep", target: pinned.length + " pinned targets",
      label: "Scanning " + pinned.length + " Pinned Destinations",
      hint: "Checking " + pinned.length + " pinned targets in parallel...",
      triggerBtn: btn, runningLabel: "Scanning…",
      onCancel: () => { if (state.deps.onRunCancelled) state.deps.onRunCancelled(runSeq, "main"); }
    }) : null;
    if (!prog && btn) btn.setAttribute("aria-busy", "true");
    try {
      const r = await state.deps.apiFetch("./api/scan-pinned", {
        method: "POST", bodyObj: { style: "json" }, signal: prog ? prog.signal : undefined
      });
      if (isAborted(null, prog)) return;
      if (!r || !r.res || !r.res.ok) return reportRunError((r && r.data && r.data.error) || "Pinned scan failed.", runSeq);
      const results = Array.isArray(r.data.results) ? r.data.results : [];
      renderSweepSummary(results);
      const focus = results.find((x) => x.outcome && x.outcome.status !== "OK") || results.find((x) => x.outcome);
      if (state.deps.onLiveWorkspaceRefresh) state.deps.onLiveWorkspaceRefresh();
      if (!focus || !focus.outcome) return reportRunError((results[0] && results[0].error) || "Pinned scan failed.", runSeq);
      state.deps.onShowOutcome(focus.outcome, focus.destination, runSeq);
      state.deps.announce("Completed pinned destination scan.");
    } catch (err) {
      if (isAborted(err, prog)) return;
      reportRunError((err && err.message) || "Pinned scan failed.", runSeq);
    } finally {
      if (prog) prog.finish(); else if (btn) btn.setAttribute("aria-busy", "false");
    }
  }

  function showDialog(dlg) {
    if (!dlg) return;
    dlg.returnValue = "";
    if (typeof dlg.showModal === "function") { if (!dlg.open) dlg.showModal(); } else dlg.setAttribute("open", "");
  }

  function closeDialog(dlg, reason) {
    if (!dlg) return;
    if (typeof dlg.close === "function") dlg.close(reason);
    else { dlg.removeAttribute("open"); resetEditorState(); }
  }

  const focusById = (id) => { const n = $(id); if (n && typeof n.focus === "function") n.focus(); };
  const clearFormErrors = () => { if (state.deps && state.deps.syncValidity) ["destNameInput", "destTargetInput", "destMacInput"].forEach((id) => state.deps.syncValidity($(id), "")); };

  function resetEditorState() {
    if ($("destEditorPanel")) $("destEditorPanel").hidden = true;
    state.returnToManager = false;
    clearFormErrors();
  }

  function openManager() {
    const dlg = $("savedDestsDialog");
    if (!dlg) return;
    resetEditorState();
    showDialog(dlg);
    focusById(state.items.length ? "savedDestsCloseBtn" : "addDestinationBtn");
  }

  function finishEditor(reason) {
    if (state.returnToManager) {
      resetEditorState();
      return focusById("addDestinationBtn");
    }
    closeDialog($("savedDestsDialog"), reason);
  }

  function openEditor(prefill, opts) {
    const p = prefill || {}, dlg = $("savedDestsDialog");
    if (!dlg) return;
    populateCheckSelect();
    state.returnToManager = Boolean(opts && opts.returnToManager);
    if ($("destEditorPanel")) $("destEditorPanel").hidden = false;
    $("destDialogTitle").textContent = p.id ? "Edit Destination" : "Save Destination";
    const vals = { destIdInput: p.id || "", destNameInput: p.name || "", destTargetInput: p.target || "", destCategorySelect: p.category || "Core", destMacInput: p.mac || "" };
    Object.keys(vals).forEach((id) => { $(id).value = vals[id]; });
    const checkSel = $("destCheckSelect"), wantedCheck = p.default_check || "recipe_diff_ping";
    if (Array.from(checkSel.options).some((o) => o.value === wantedCheck)) checkSel.value = wantedCheck;
    $("destPinnedCheck").checked = Boolean(p.pinned);
    $("destMonitorCheck").checked = Boolean(p.monitor_enabled);
    clearFormErrors();
    showDialog(dlg);
    const focusName = () => focusById("destNameInput");
    if (typeof globalScope.requestAnimationFrame === "function") globalScope.requestAnimationFrame(focusName);
    else focusName();
  }

  async function handleDestFormSubmit(ev) {
    ev.preventDefault();
    const nameEl = $("destNameInput"), targetEl = $("destTargetInput"), macEl = $("destMacInput");
    const name = nameEl.value.trim(), target = targetEl.value.trim(), mac = (macEl.value || "").trim();
    if (!state.deps.syncValidity(nameEl, name ? "" : "Enter a display name.")) return nameEl.focus();
    if (!state.deps.syncValidity(targetEl, target ? "" : "Enter a host, IP, or URL.")) return targetEl.focus();
    if (!state.deps.syncValidity(macEl, !mac || MAC_RE.test(mac) ? "" : "Enter a valid MAC address (e.g. 00:00:5E:00:53:42).")) return macEl.focus();

    const saveBtn = $("destSaveBtn");
    saveBtn.setAttribute("aria-busy", "true");
    try {
      const ok = await saveDestinationObj({
        id: ($("destIdInput").value || "").trim(), name, target, mac,
        category: $("destCategorySelect").value, default_check: $("destCheckSelect").value,
        pinned: $("destPinnedCheck").checked, monitor_enabled: $("destMonitorCheck").checked,
        monitor_schedule: "*/5 * * * *"
      });
      if (!ok) return state.deps.syncValidity(targetEl, state.lastSaveError || "Unable to save destination.");
      finishEditor("saved");
      if (state.mode === "live" && state.deps.onLiveWorkspaceRefresh) state.deps.onLiveWorkspaceRefresh();
      state.deps.announce("Saved destination " + name + ".");
    } finally {
      saveBtn.setAttribute("aria-busy", "false");
    }
  }

  function handleTableAction(ev) {
    const btn = ev.target.closest("[data-dest-action]");
    if (!btn) return;
    const action = btn.getAttribute("data-dest-action"), id = btn.getAttribute("data-dest-id");
    const dest = state.items.find((x) => x.id === id);
    if (!dest) return;
    const dlg = $("savedDestsDialog");
    if (action === "run") {
      if (dlg && (dlg.open || (typeof dlg.hasAttribute === "function" && dlg.hasAttribute("open")))) closeDialog(dlg, "run");
      return runDestinationById(id, btn);
    }
    if (action === "edit") return openEditor(dest, { returnToManager: Boolean(btn.closest("#savedDestsDialog")) });
    if (action === "toggle-pin" || action === "toggle-monitor") {
      const isPin = action === "toggle-pin", nextVal = isPin ? !dest.pinned : !dest.monitor_enabled;
      return saveDestinationObj(Object.assign({}, dest, isPin ? { pinned: nextVal } : { monitor_enabled: nextVal })).then((ok) => {
        if (!ok) return state.deps.announce(state.lastSaveError || "Unable to update destination.");
        if (!isPin && state.mode === "live" && state.deps.onLiveWorkspaceRefresh) state.deps.onLiveWorkspaceRefresh();
        state.deps.announce(isPin
          ? (nextVal ? "Pinned " : "Unpinned ") + dest.name + "."
          : (nextVal ? "Enabled 5-minute monitoring for " : "Paused monitoring for ") + dest.name + ".");
      });
    }
    if (action === "delete") {
      if (btn.dataset.confirm !== "1") {
        btn.dataset.confirm = "1";
        btn.textContent = "Confirm?";
        globalScope.setTimeout(() => {
          if (btn.isConnected && btn.dataset.confirm === "1") { delete btn.dataset.confirm; btn.textContent = "Delete"; }
        }, 3500);
        return;
      }
      deleteDestinationById(id);
    }
  }

  function bindEvents() {
    const on = (id, ev, fn) => { const n = $(id); if (n) n.addEventListener(ev, fn); };
    on("pinnedList", "click", (ev) => {
      const chip = ev.target.closest("[data-dest-id]");
      const dest = chip && state.items.find((x) => x.id === chip.getAttribute("data-dest-id"));
      if (dest && state.deps.onSelectPinned) state.deps.onSelectPinned(dest);
    });
    on("pinnedSweepSummary", "click", (ev) => {
      const chip = ev.target.closest("[data-sweep-index]");
      const item = chip && state.sweepResults[Number(chip.getAttribute("data-sweep-index"))];
      if (item && item.outcome) state.deps.onShowOutcome(item.outcome, item.destination);
    });
    on("wakeMacChips", "click", (ev) => {
      const chip = ev.target.closest("[data-wake-id]");
      const dest = chip && state.items.find((x) => x.id === chip.getAttribute("data-wake-id"));
      if (dest && state.deps.onSelectWakeMac) state.deps.onSelectWakeMac(dest);
    });
    on("scanPinnedBtn", "click", scanPinned);
    on("topAddDestBtn", "click", () => openEditor({}, { returnToManager: false }));
    ["addDestinationBtn", "emptyAddDestBtn"].forEach((id) => on(id, "click", () => openEditor({}, { returnToManager: true })));
    on("enableMonitoringBtn", "click", () => openEditor({ monitor_enabled: true }, { returnToManager: false }));
    ["quickSavedManageBtn", "pinnedManageBtn"].forEach((id) => on(id, "click", openManager));
    ["quickSavedList", "savedDestBody"].forEach((id) => on(id, "click", handleTableAction));
    on("destForm", "submit", handleDestFormSubmit);
    on("savedDestsCloseBtn", "click", () => closeDialog($("savedDestsDialog"), "close"));
    on("destCancelBtn", "click", () => finishEditor("cancel"));
    state.deps.wireRequired($("destNameInput"), "Enter a display name.");
    state.deps.wireRequired($("destTargetInput"), "Enter a host, IP, or URL.");
    on("destMacInput", "input", () => {
      const val = $("destMacInput").value.trim();
      if (!val || MAC_RE.test(val)) state.deps.syncValidity($("destMacInput"), "");
    });
    const dlg = $("savedDestsDialog");
    state.deps.bindDialogDismiss(dlg);
    if (dlg) dlg.addEventListener("close", resetEditorState);
  }

  function init(deps) {
    state.deps = deps;
    populateCheckSelect();
    bindEvents();
  }

  globalScope.NetutilsDestinations = {
    init, setMode: (mode) => { state.mode = mode; }, setDestinations,
    getDestinations: () => state.items.slice(), openManager, openEditor, renderAll, refresh
  };
})(typeof window !== "undefined" ? window : globalThis);
