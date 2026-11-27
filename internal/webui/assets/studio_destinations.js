(function (globalScope) {
  "use strict";

  const MAC_RE = /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i;
  const state = { mode: "locked", items: [], sweepResults: [], deps: null, lastSaveError: "" };
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  };

  function populateCheckSelect() {
    const sel = $("destCheckSelect");
    const catalog = state.deps && state.deps.getCheckCatalog ? state.deps.getCheckCatalog() : [];
    if (!sel || !catalog.length) return;
    const groups = {};
    const groupOrder = [];
    for (let i = 0; i < catalog.length; i += 1) {
      const item = catalog[i];
      if (item.allowSavedDest === false) continue;
      if (!groups[item.groupLabel]) {
        groups[item.groupLabel] = [];
        groupOrder.push(item.groupLabel);
      }
      groups[item.groupLabel].push(item);
    }
    const frag = document.createDocumentFragment();
    for (let g = 0; g < groupOrder.length; g += 1) {
      const label = groupOrder[g];
      const og = document.createElement("optgroup");
      og.label = label;
      const list = groups[label];
      for (let j = 0; j < list.length; j += 1) {
        const opt = document.createElement("option");
        opt.value = list[j].id;
        opt.textContent = list[j].label;
        og.appendChild(opt);
      }
      frag.appendChild(og);
    }
    sel.replaceChildren(frag);
  }

  function renderPinnedBar() {
    const listEl = $("pinnedList");
    if (!listEl) return;
    const pinned = state.items.filter((d) => Boolean(d.pinned));
    if (!pinned.length) {
      listEl.replaceChildren(el("span", "card-meta", "Pin any saved destination below for 1-click checks."));
      return;
    }
    const frag = document.createDocumentFragment();
    for (let i = 0; i < pinned.length; i += 1) {
      const d = pinned[i];
      const btn = el("button", "va-pill", d.name);
      btn.type = "button";
      btn.setAttribute("data-variant", "chip");
      btn.setAttribute("data-dest-id", d.id);
      btn.title = d.target + " · " + state.deps.getCheckLabel(d.default_check);
      frag.appendChild(btn);
    }
    listEl.replaceChildren(frag);
  }

  function renderWakeChips() {
    const wrap = $("wakeMacChips");
    if (!wrap) return;
    const withMac = state.items.filter((d) => d.mac && String(d.mac).trim() !== "");
    if (!withMac.length) {
      wrap.replaceChildren(el("span", "card-meta", "Save a device with a MAC address to see quick wake chips here."));
      return;
    }
    const frag = document.createDocumentFragment();
    for (let i = 0; i < withMac.length; i += 1) {
      const d = withMac[i];
      const chip = el("button", "va-pill", d.name + " (" + d.mac + ")");
      chip.type = "button";
      chip.setAttribute("data-variant", "chip");
      chip.setAttribute("data-wake-id", d.id);
      frag.appendChild(chip);
    }
    wrap.replaceChildren(frag);
  }

  function makeActionBtn(label, cls, action, id) {
    const btn = el("button", cls, label);
    btn.type = "button";
    btn.setAttribute("data-dest-action", action);
    btn.setAttribute("data-dest-id", id);
    return btn;
  }

  function renderDestinationsTable() {
    const body = $("savedDestBody");
    const empty = $("savedDestEmpty");
    const wrap = $("savedDestTableWrap");
    const countEl = $("savedDestCount");
    if (!body) return;
    const list = state.items;
    if (countEl) countEl.textContent = list.length + (list.length === 1 ? " destination" : " destinations");
    if (empty) empty.hidden = list.length > 0;
    if (wrap) wrap.hidden = list.length === 0;
    if (!list.length) {
      body.replaceChildren();
      return;
    }
    state.deps.renderTableRows(body, list, (d) => {
      const nameCell = el("div", "dest-name-cell");
      nameCell.appendChild(el("strong", "", d.name));
      const subParts = [d.target, d.category || "Core"];
      if (d.mac) subParts.push("MAC " + d.mac);
      nameCell.appendChild(el("span", "dest-sub", subParts.join(" · ")));

      const pinBtn = makeActionBtn(d.pinned ? "Pinned" : "Pin", "va-btn va-btn-xs va-btn-ghost", "toggle-pin", d.id);
      pinBtn.setAttribute("aria-pressed", d.pinned ? "true" : "false");

      const monLabel = d.monitor_enabled ? "Every 5m" : "Paused";
      const monBtn = makeActionBtn(monLabel, "va-btn va-btn-xs va-btn-ghost", "toggle-monitor", d.id);
      monBtn.setAttribute("aria-pressed", d.monitor_enabled ? "true" : "false");

      const actions = el("div", "row-actions");
      actions.appendChild(makeActionBtn("Run Now", "va-btn va-btn-xs va-btn-secondary", "run", d.id));
      actions.appendChild(makeActionBtn("Edit", "va-btn va-btn-xs va-btn-ghost", "edit", d.id));
      actions.appendChild(makeActionBtn("Delete", "va-btn va-btn-xs va-btn-ghost va-btn-danger-ghost", "delete", d.id));

      return {
        cells: [
          ["Destination", nameCell],
          ["Default Check", state.deps.getCheckLabel(d.default_check)],
          ["Pinned", pinBtn],
          ["5-Min Monitor", monBtn],
          ["Actions", actions]
        ]
      };
    });
  }

  function renderSweepSummary(results) {
    const strip = $("pinnedSweepSummary");
    if (!strip) return;
    state.sweepResults = Array.isArray(results) ? results : [];
    if (!state.sweepResults.length) {
      strip.replaceChildren(el("span", "card-meta", "No pinned destinations found to scan."));
      strip.hidden = false;
      return;
    }
    let okCount = 0;
    let warnCount = 0;
    let failCount = 0;
    const frag = document.createDocumentFragment();
    for (let i = 0; i < state.sweepResults.length; i += 1) {
      const r = state.sweepResults[i];
      const out = r.outcome || {};
      const st = r.error ? "FAIL" : String(out.status || "OK").toUpperCase();
      if (st === "FAIL" || st === "ERROR") failCount += 1;
      else if (st === "WARN" || st === "WARNING") warnCount += 1;
      else okCount += 1;

      const dur = out.duration_ms ? " · " + out.duration_ms + " ms" : "";
      const chip = el("button", "va-pill", "[" + st + "] " + (r.destination ? r.destination.name : "Target") + dur);
      chip.type = "button";
      chip.setAttribute("data-variant", "chip");
      chip.setAttribute("data-sweep-index", String(i));
      frag.appendChild(chip);
    }
    const summaryText = el("strong", "", "Pinned Sweep: " + okCount + " OK, " + warnCount + " Warning, " + failCount + " Failed —");
    strip.replaceChildren(summaryText, frag);
    strip.hidden = false;
  }

  function renderQuickSavedList() {
    const listEl = $("quickSavedList"), emptyEl = $("quickSavedEmpty"), countEl = $("quickSavedCount");
    if (!listEl) return;
    const items = state.items;
    if (countEl) countEl.textContent = items.length + " saved";
    if (emptyEl) emptyEl.hidden = items.length > 0;
    listEl.hidden = items.length === 0;
    if (!items.length) { listEl.replaceChildren(); return; }
    const frag = document.createDocumentFragment();
    for (let i = 0; i < items.length; i += 1) {
      const d = items[i], row = el("li", "quick-saved-row"), info = el("div", "quick-saved-info");
      info.append(el("span", "quick-saved-name", d.name), el("span", "quick-saved-meta", d.target + " · " + state.deps.getCheckLabel(d.default_check)));
      const acts = el("div", "quick-saved-actions");
      acts.append(makeActionBtn("Run", "va-btn va-btn-xs va-btn-secondary", "run", d.id), makeActionBtn("Edit", "va-btn va-btn-xs va-btn-ghost", "edit", d.id));
      row.append(info, acts);
      frag.appendChild(row);
    }
    listEl.replaceChildren(frag);
  }

  function renderAll() {
    renderPinnedBar();
    renderWakeChips();
    renderQuickSavedList();
    renderDestinationsTable();
    if (state.deps && state.deps.onDestinationsChanged) state.deps.onDestinationsChanged(state.items);
  }

  function setDestinations(items) {
    state.items = Array.isArray(items) ? items.slice() : [];
    renderAll();
  }

  async function refresh() {
    if (state.mode !== "live") return renderAll();
    const r = await state.deps.apiFetch("./api/destinations");
    if (r.res.ok && Array.isArray(r.data.destinations)) {
      setDestinations(r.data.destinations);
    }
  }

  async function saveDestinationObj(payload) {
    if (!payload || !String(payload.name || "").trim() || !String(payload.target || "").trim()) {
      state.lastSaveError = "Enter a display name and target.";
      return false;
    }
    if (state.mode === "demo") {
      const copy = Object.assign({
        id: payload.id || ("dest_demo_" + Date.now().toString(36)),
        category: "Core",
        mac: "",
        default_check: "recipe_diff_ping",
        pinned: false,
        monitor_enabled: false,
        monitor_schedule: "*/5 * * * *",
        created_at: Math.floor(Date.now() / 1000),
        updated_at: Math.floor(Date.now() / 1000)
      }, payload);
      const idx = state.items.findIndex((x) => x.id === copy.id);
      if (idx >= 0) state.items[idx] = Object.assign({}, state.items[idx], copy, { updated_at: Math.floor(Date.now() / 1000) });
      else state.items.unshift(copy);
      state.items.sort((a, b) => Number(b.pinned) - Number(a.pinned) || (b.updated_at || 0) - (a.updated_at || 0));
      state.lastSaveError = "";
      renderAll();
      return true;
    }
    const isEdit = Boolean(payload.id);
    const url = isEdit ? "./api/destinations/" + encodeURIComponent(payload.id) : "./api/destinations";
    try {
      const r = await state.deps.apiFetch(url, { method: isEdit ? "PUT" : "POST", bodyObj: payload });
      if (!r.res.ok) {
        state.lastSaveError = (r.data && r.data.error) || "Unable to save destination.";
        return false;
      }
      state.lastSaveError = "";
      if (Array.isArray(r.data.destinations)) setDestinations(r.data.destinations);
      else await refresh();
      return true;
    } catch (_) {
      state.lastSaveError = "Unable to save destination.";
      return false;
    }
  }

  async function deleteDestinationById(id) {
    if (state.mode === "demo") {
      setDestinations(state.items.filter((x) => x.id !== id));
      return state.deps.announce("Removed saved destination.");
    }
    const r = await state.deps.apiFetch("./api/destinations/" + encodeURIComponent(id), { method: "DELETE" });
    if (r.res.ok && Array.isArray(r.data.destinations)) {
      setDestinations(r.data.destinations);
      state.deps.announce("Removed saved destination.");
    } else {
      state.deps.announce((r.data && r.data.error) || "Unable to remove destination.");
    }
  }

  async function runDestinationById(id, triggerBtn) {
    const dest = state.items.find((x) => x.id === id);
    if (!dest) return;
    if (triggerBtn) triggerBtn.setAttribute("aria-busy", "true");
    if (state.deps.onBeforeRun) state.deps.onBeforeRun(dest.default_check, dest.target, state.mode === "live");
    try {
      if (state.mode === "demo") {
        const out = state.deps.runDemoTool(dest.default_check, dest.target, { mac: dest.mac });
        state.deps.onShowOutcome(out, dest);
        return state.deps.announce("Checked " + dest.name + ".");
      }
      const r = await state.deps.apiFetch("./api/destinations/" + encodeURIComponent(id) + "/run", {
        method: "POST", bodyObj: { style: "json" }
      });
      if (r.res.ok) {
        state.deps.onShowOutcome(r.data, dest);
        state.deps.announce("Checked " + dest.name + ".");
        if (state.deps.onLiveWorkspaceRefresh) state.deps.onLiveWorkspaceRefresh();
      } else {
        state.deps.announce((r.data && r.data.error) || "Destination check failed.");
      }
    } finally {
      if (triggerBtn) triggerBtn.setAttribute("aria-busy", "false");
    }
  }

  async function scanPinned() {
    const btn = $("scanPinnedBtn");
    const pinned = state.items.filter((d) => Boolean(d.pinned));
    if (!pinned.length) return renderSweepSummary([]);
    if (btn) btn.setAttribute("aria-busy", "true");
    if (state.deps.onBeforeRun) state.deps.onBeforeRun("recipe_diff_ping", pinned.length + " pinned targets", state.mode === "live");
    state.deps.announce("Scanning " + pinned.length + " pinned destinations...");
    try {
      let results = [];
      if (state.mode === "demo") {
        results = pinned.map((d) => ({
          destination: d,
          outcome: state.deps.runDemoTool(d.default_check, d.target, { mac: d.mac })
        }));
      } else {
        const r = await state.deps.apiFetch("./api/scan-pinned", { method: "POST", bodyObj: { style: "json" } });
        if (!r.res.ok) return state.deps.announce((r.data && r.data.error) || "Pinned scan failed.");
        results = Array.isArray(r.data.results) ? r.data.results : [];
      }
      renderSweepSummary(results);
      const focus = results.find((x) => x.outcome && x.outcome.status !== "OK") || results[0];
      if (focus && focus.outcome) state.deps.onShowOutcome(focus.outcome, focus.destination);
      if (state.mode === "live" && state.deps.onLiveWorkspaceRefresh) state.deps.onLiveWorkspaceRefresh();
      state.deps.announce("Completed pinned destination scan.");
    } finally {
      if (btn) btn.setAttribute("aria-busy", "false");
    }
  }

  function openEditor(prefill) {
    const p = prefill || {};
    const dlg = $("destDialog");
    if (!dlg) return;
    populateCheckSelect();
    $("destDialogTitle").textContent = p.id ? "Edit Destination" : "Save Destination";
    $("destIdInput").value = p.id || "";
    $("destNameInput").value = p.name || "";
    $("destTargetInput").value = p.target || "";
    $("destCategorySelect").value = p.category || "Core";
    $("destMacInput").value = p.mac || "";
    const checkSel = $("destCheckSelect");
    const wantedCheck = p.default_check || "recipe_diff_ping";
    if (Array.from(checkSel.options).some((o) => o.value === wantedCheck)) checkSel.value = wantedCheck;
    $("destPinnedCheck").checked = Boolean(p.pinned);
    $("destMonitorCheck").checked = Boolean(p.monitor_enabled);
    state.deps.syncValidity($("destNameInput"), "");
    state.deps.syncValidity($("destTargetInput"), "");
    state.deps.syncValidity($("destMacInput"), "");
    dlg.returnValue = "";
    if (typeof dlg.showModal === "function") {
      if (!dlg.open) dlg.showModal();
    } else {
      dlg.setAttribute("open", "");
    }
  }

  async function handleDestFormSubmit(ev) {
    ev.preventDefault();
    const nameEl = $("destNameInput");
    const targetEl = $("destTargetInput");
    const macEl = $("destMacInput");
    const name = nameEl.value.trim();
    const target = targetEl.value.trim();
    const mac = (macEl.value || "").trim();
    if (!state.deps.syncValidity(nameEl, name ? "" : "Enter a display name.")) return nameEl.focus();
    if (!state.deps.syncValidity(targetEl, target ? "" : "Enter a host, IP, or URL.")) return targetEl.focus();
    if (!state.deps.syncValidity(macEl, !mac || MAC_RE.test(mac) ? "" : "Enter a valid MAC address (e.g. 00:00:5E:00:53:42).")) return macEl.focus();

    const saveBtn = $("destSaveBtn");
    saveBtn.setAttribute("aria-busy", "true");
    try {
      const ok = await saveDestinationObj({
        id: ($("destIdInput").value || "").trim(),
        name,
        target,
        mac: ($("destMacInput").value || "").trim(),
        category: $("destCategorySelect").value,
        default_check: $("destCheckSelect").value,
        pinned: $("destPinnedCheck").checked,
        monitor_enabled: $("destMonitorCheck").checked,
        monitor_schedule: "*/5 * * * *"
      });
      if (!ok) return state.deps.syncValidity(targetEl, state.lastSaveError || "Unable to save destination.");
      $("destDialog").close("saved");
      if (state.mode === "live" && state.deps.onLiveWorkspaceRefresh) state.deps.onLiveWorkspaceRefresh();
      state.deps.announce("Saved destination " + name + ".");
    } finally {
      saveBtn.setAttribute("aria-busy", "false");
    }
  }

  function handleTableAction(ev) {
    const btn = ev.target.closest("[data-dest-action]");
    if (!btn) return;
    const action = btn.getAttribute("data-dest-action");
    const id = btn.getAttribute("data-dest-id");
    const dest = state.items.find((x) => x.id === id);
    if (!dest) return;
    if (action === "run") return runDestinationById(id, btn);
    if (action === "edit") return openEditor(dest);
    if (action === "toggle-pin") {
      const nextPinned = !dest.pinned;
      return saveDestinationObj(Object.assign({}, dest, { pinned: nextPinned })).then((ok) => {
        if (ok) state.deps.announce((nextPinned ? "Pinned " : "Unpinned ") + dest.name + ".");
        else state.deps.announce(state.lastSaveError || "Unable to update destination.");
      });
    }
    if (action === "toggle-monitor") {
      const nextMon = !dest.monitor_enabled;
      return saveDestinationObj(Object.assign({}, dest, { monitor_enabled: nextMon })).then((ok) => {
        if (ok) {
          if (state.mode === "live" && state.deps.onLiveWorkspaceRefresh) state.deps.onLiveWorkspaceRefresh();
          state.deps.announce((nextMon ? "Enabled 5-minute monitoring for " : "Paused monitoring for ") + dest.name + ".");
        } else {
          state.deps.announce(state.lastSaveError || "Unable to update destination.");
        }
      });
    }
    if (action === "delete") {
      if (btn.dataset.confirm !== "1") {
        btn.dataset.confirm = "1";
        btn.textContent = "Confirm?";
        globalScope.setTimeout(() => {
          if (btn.isConnected && btn.dataset.confirm === "1") {
            delete btn.dataset.confirm;
            btn.textContent = "Delete";
          }
        }, 3500);
        return;
      }
      deleteDestinationById(id);
    }
  }

  function bindEvents() {
    $("pinnedList").addEventListener("click", (ev) => {
      const chip = ev.target.closest("[data-dest-id]");
      if (!chip) return;
      const dest = state.items.find((x) => x.id === chip.getAttribute("data-dest-id"));
      if (dest && state.deps.onSelectPinned) state.deps.onSelectPinned(dest);
    });
    $("pinnedSweepSummary").addEventListener("click", (ev) => {
      const chip = ev.target.closest("[data-sweep-index]");
      if (!chip) return;
      const item = state.sweepResults[Number(chip.getAttribute("data-sweep-index"))];
      if (item && item.outcome) state.deps.onShowOutcome(item.outcome, item.destination);
    });
    $("wakeMacChips").addEventListener("click", (ev) => {
      const chip = ev.target.closest("[data-wake-id]");
      if (!chip) return;
      const dest = state.items.find((x) => x.id === chip.getAttribute("data-wake-id"));
      if (dest && state.deps.onSelectWakeMac) state.deps.onSelectWakeMac(dest);
    });
    $("scanPinnedBtn").addEventListener("click", scanPinned);
    [$("topAddDestBtn"), $("addDestinationBtn"), $("emptyAddDestBtn")].forEach((b) => {
      if (b) b.addEventListener("click", () => openEditor({}));
    });
    if ($("enableMonitoringBtn")) $("enableMonitoringBtn").addEventListener("click", () => openEditor({ monitor_enabled: true }));
    if ($("quickSavedManageBtn")) {
      $("quickSavedManageBtn").addEventListener("click", () => {
        if (!state.items.length) openEditor({});
        else if (state.deps.onFocusSection) state.deps.onFocusSection($("savedDestinationsSection"));
      });
    }
    if ($("quickSavedList")) $("quickSavedList").addEventListener("click", handleTableAction);
    $("savedDestBody").addEventListener("click", handleTableAction);
    $("destForm").addEventListener("submit", handleDestFormSubmit);
    [$("destDialogCloseBtn"), $("destCancelBtn")].forEach((b) => {
      if (b) b.addEventListener("click", () => $("destDialog").close("cancel"));
    });
    state.deps.wireRequired($("destNameInput"), "Enter a display name.");
    state.deps.wireRequired($("destTargetInput"), "Enter a host, IP, or URL.");
    $("destMacInput").addEventListener("input", () => {
      const val = $("destMacInput").value.trim();
      if (!val || MAC_RE.test(val)) state.deps.syncValidity($("destMacInput"), "");
    });
    state.deps.bindDialogDismiss($("destDialog"));
  }

  function init(deps) {
    state.deps = deps;
    populateCheckSelect();
    bindEvents();
  }

  globalScope.NetutilsDestinations = {
    init: init,
    setMode: (mode) => { state.mode = mode; },
    setDestinations: setDestinations,
    getDestinations: () => state.items.slice(),
    openEditor: openEditor,
    renderAll: renderAll,
    refresh: refresh
  };
})(typeof window !== "undefined" ? window : globalThis);
