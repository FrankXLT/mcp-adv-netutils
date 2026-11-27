# Advanced Network Utilities (`mcp-adv-netutils`) — User Workflows & Operational Baseline

> **Baseline Metadata**: `workflow_delta=update_existing` · **Bound Workflows**: `WF-01`, `WF-02`, `WF-03`, `WF-04`, `WF-05`, `WF-06`, `WF-07`, `WF-08`

This document defines the primary user journeys, operational workflows, responsive layout contracts, and verification invariants for **Advanced Network Utilities** (`mcp-adv-netutils`). It provides a plain-language baseline so AI assistants (Gemini Web/Mobile, Antigravity, and subagents) and human operators share an exact understanding of **who uses the server, how diagnostic ladders, Saved Destinations, and cron watchlists behave, and what safety boundaries apply across devices**.

---

## The User & Multi-Surface Operating Model

- **The Operator**: Manages multi-VLAN lab and production networks (for example, LAN, container macvlan, managed switch uplinks, and mobile WireGuard split-tunnels) from a folded phone (`390px`), unfolded foldable tablet (`900px`), or desktop browser (`1440px+`), as well as via conversational MCP clients.
- **Conversational & IDE Clients**: Issue read-only or deadbolt-gated MCP tool calls (`33` registered tools) over Streamable HTTP / SSE, remote `/{PATH_SECRET}/mcp`, or local `--stdio`, receiving deterministic monospace ASCII cards (`default`, `quick`, `rich`) or compact `json` payloads (`< 18.5 KB`).
- **The Operator Studio (`/web`)**: Embedded 4-theme Quiet UI web interface compiled directly into the pure-Go binary (`//go:embed`), using self-contained interactive Apache ECharts (`renderer: 'svg'`) visuals, plain everyday copy (zero terminal ASCII boxes or jargon), and Saved Destinations persisted in `netutils_jobs.db`.

---

## Common Terms Glossary

- **Advanced Network Utilities**: The spelled-out display title used across the `46px` `OAW Projects` navigation bar, project switcher menu, documentation headings, and project cards (while `mcp-adv-netutils` stays strictly inside monospace code pills, image tags, and terminal commands).
- **Diagnostic Recipes**: Coordinated multi-probe workflows (`recipe_*`) exposed in MCP/CLI directly and grouped cleanly by operator goal inside `/web` (`Path & Ping`, `Web & DNS`, `Ports & Host`, `Wake`, plus full subnet discovery in `Local Network`), covering differential probes (`recipe_diff_ping`, `recipe_diff_dns`, `recipe_diff_http`, `recipe_diff_snapshot`) and multi-layer L2–L7 ladders (`recipe_host_card`, `recipe_lan_radar`, `recipe_path_autopsy`, `recipe_wake_verify`, plus `render_run_digest`).
- **Three-Tier ASCII Styles**: Deterministic monospace output modes (`style`) used exclusively across CLI and MCP terminal callers (`default` `72` columns exact with right-aligned status badges, `quick` `<= 40` columns borderless for `390px` mobile chat, `rich` `76` columns boxed TUI, and `json` `< 18.5 KB` wire cap with `FAIL`/`WARN` rows sorted first). (`/web` and `/demo/` replace terminal ASCII output with interactive ECharts + `Chart | Table` toggles and Markdown/TSV copy buttons.)
- **Saved Destinations**: Persistent SQLite bookmarks (`saved_destinations` table in `netutils_jobs.db`, managed via `manage_saved_destinations` or `/web`) storing a friendly name, target (`IP`, `hostname`, `CIDR`, or `URL`), category (`Core`, `Website & API`, `LAN`, `Servers & NAS`, `Containers`, `Remote`), optional MAC address, default check, pinned toggle (1-click quick bar + **Scan Pinned**), and scheduled-monitoring toggle synced with the cron watchlist.
- **Cron Watchlist**: Scheduled recurring Diagnostic Recipes and single checks defined in `watchlist.yaml` and executed in-process via pure-Go `robfig/cron/v3` (`SkipIfStillRunning`) or single-shot via `--run-watchlist-once` for `systemd` timers.
- **Retained Job Archive**: Pure-Go WAL SQLite database (`netutils_jobs.db` via `modernc.org/sqlite`, `?mode=ro` for readers) storing every manual, MCP, and cron incident run under a stable `job_id` with explicit `expires_at` timestamps (`30d` default retention re-pullable via `get_job_report`, `7d -> 30d` two-stage down-aging for healthy `*/5m` cron ticks, hourly TTL reaper + `PRAGMA incremental_vacuum`, and `--max-store-mb 256` **Saved History Size** cap).
- **Alerts After 2 Failed Checks**: Stability rule (known internally as alert hysteresis) requiring at least `2` consecutive non-OK cron ticks before flipping status alerts or webhook states, preventing single-packet jitter from triggering false alarms.
- **Thirty-Minute Passphrase Deadbolt**: Voice-normalized SHA-256 passphrase lock (`PASS_HASH`, trimmed/lowercased with whitespace collapsed and dictation punctuation stripped, verified via `crypto/subtle.ConstantTimeCompare`) keeping remote HTTP MCP and `/web` fail-closed for sensitive or mutating actions until unlocked for `30m` via `unlock_netutils` (or relocked via `lock_netutils`), while allowing optional redacted aggregate cron summaries when locked.
- **Two-Doorway Setup**: Segmented transport architecture pairing the remote Deadbolt-guarded `/{PATH_SECRET}/mcp` + `/web` doorway with the LAN-only `/lan/{LAN_MCP_TOKEN}/mcp` and backward-compatible `/sse` Streamable HTTP doorway (rejecting proxy forwarding headers and non-RFC1918 peers), plus `--stdio` container mode.
- **Operator Studio**: Embedded 4-theme Quiet UI web application (`/web` with `Pure White`, `Warm Paper`, `Dark Paper`, and `Dark` themes plus Comfortable `d2` / Compact `d3` density) compiled into the Go binary (`//go:embed`) with bundled Apache ECharts (`renderer: 'svg'`) and zero-backend `?demo=1` preview support.

---

## Workflow 1: WF-01 — Conversational & Differential Outage Triage (`recipe_diff_ping` & Core Tools)

### User Goal
The operator notices a sluggish service, dropped tunnel, or unreachable host from mobile or IDE chat and wants an immediate, deterministic answer showing *where* packets stopped and *which direction* failed—without raw log sprawl or false negatives from ICMP-filtering hosts.

### Triggers & End-to-End Steps
1. **Trigger**: User asks in chat (*"Why is `example.com` or my tunnel unreachable?"*) or runs `recipe_diff_ping` / `recipe_path_autopsy` / core L3–L7 probes (`ping`, `traceroute`, `mtu_path_probe`, `mtr_path_quality`, `tcp_port_scan`, `tls_certificate_check`, `dns_reverse_batch`).
2. **Parallel Differential Ladder (`recipe_diff_ping`)**:
   - Executes `[1] Local NIC -> [2] LAN Gateway -> [3] WireGuard/WAN Peer -> [4] Canary + Target` in parallel alongside a TCP `RST`/`SYN-ACK` check and L2 ARP neighbor check.
   - Reports explicit `probe_mode` (`icmp` vs `tcp_fallback`), recognizing that a TCP `RST` proves bidirectional L3 routing is healthy even when `100%` of ICMP echo replies are filtered.
3. **Hardened Core Tool Execution**:
   - `ping` isolates per-call Echo ID/sequence numbers and reads IPv4/IPv6 TTL control messages.
   - `traceroute` rejects leading `-` targets, inserts `"--"` before the target, and bounds concurrent hop PTR lookups.
   - `tcp_port_scan` supports named presets (`common`, `homelab`, `web`, `iot`; default `common`) with single-resolution `DialContext`.
   - `tls_certificate_check` validates against `x509.SystemCertPool()` plus wire intermediates and supports `Ed25519` keys.
   - `dns_reverse_batch` caps batches at `256` validated IPs.
4. **ASCII / JSON Formatting**: Renders `default` (`72` cols exact with right-aligned `[OK]`/`[WARN]`/`[FAIL]` status badge and full untruncated `job_id`), `quick` (`<= 40` cols), `rich` (`76` cols), or `json` (`< 18.5 KB` with `FAIL`/`WARN` rows sorted first), storing the run in `netutils_jobs.db` with a `job_id`.

### Responsive Form Factor Behavior (`390px` / `900px` / `1440px`)
- **`390px` (Folded Phone)**: Callers request `style="quick"` (`<= 40` columns borderless) so monospace cards never wrap mid-row on narrow phone screens.
- **`900px` (Unfolded Tablet)**: Standard `style="default"` (`72` columns) fits cleanly inside chat panes and side-by-side panels.
- **`1440px+` (Desktop)**: `style="default"` (`72` cols) or `style="rich"` (`76` cols boxed TUI) renders full hop ladders and latency bars without clipping.

### Verification Invariants
- Central CIDR target guard (`--allow-cidrs` / `--deny-cidrs`) runs on all resolved IPs and unconditionally blocks `169.254.0.0/16` cloud metadata addresses.
- `style="quick"` lines never exceed `40` characters; `style="default"` never exceeds `72` columns with header status badge flush to col `72`; `style="rich"` never exceeds `76` columns; `style="json"` stays `< 18.5 KB`.

---

## Workflow 2: WF-02 — Silent LAN Discovery & Before/After Snapshot Diffs (`recipe_lan_radar` & `recipe_diff_snapshot`)

### User Goal
The operator wants to audit active devices on a local subnet—or capture a clean baseline before plugging in a new appliance or spinning up containers and immediately see only what was added, removed, or changed.

### Triggers & End-to-End Steps
1. **Trigger**: User asks to sweep a subnet, identify unknown MAC addresses, or compare current LAN state against a saved baseline (`recipe_lan_radar`, `arp_neighbor_sweep`, `mdns_ssdp_discover`, `snmp_switch_port`, `recipe_diff_snapshot`, `recipe_wake_verify`).
2. **Multi-Protocol Discovery (`recipe_lan_radar`)**:
   - Combines OS/ARP neighbor discovery (`mdlayher/arp`), the embedded `39,800+` IEEE OUI registry (`//go:embed`), concurrent batch reverse DNS (`dns_reverse_batch`), bounded mDNS/SSDP discovery (`hashicorp/mdns` + SSDP), and read-only SNMP switch port correlation (`gosnmp`).
   - Separates physical hardware endpoints (`[PHYSICAL - UAA]`) from containers/VMs (`[DOCKER/VM - LAA]`, `02:42:...`).
3. **Before/After Diffing (`recipe_diff_snapshot`)**:
   - Saves named snapshots in `netutils_jobs.db` and compares subsequent sweeps, highlighting only **`[+] ADDED`**, **`[-] REMOVED`**, and **`[~] CHANGED`** entries.
4. **Wake-on-LAN Verification (`recipe_wake_verify`)**:
   - Sends a 102-byte UDP magic packet (`wol_wake`) and polls ARP/TCP/ICMP liveness to confirm wake completion.

### Responsive Form Factor Behavior (`390px` / `900px` / `1440px`)
- **`390px`**: `style="quick"` collapses Physical vs Container/VM counts and diff markers (`[+]`, `[-]`, `[~]`) to `<= 40` columns.
- **`900px` & `1440px+`**: Displays grouped Physical Hardware and Containers & VMs sections with vendor names, IPs, PTR hostnames, and switch port mappings.

### Verification Invariants
- Embedded IEEE OUI resolution requires zero outbound internet API calls.
- Snapshot diffs suppress unchanged rows and isolate `[+] ADDED`, `[-] REMOVED`, and `[~] CHANGED` deltas.
- Read-only SNMP queries never issue `SNMP SET` mutations.

---

## Workflow 3: WF-03 — Interactive ECharts Studio (`/web`) Across `390px`, `900px` & `1440px`

### User Goal
The operator opens `/web` in a browser to run everyday plain-language network checks, inspect interactive Apache ECharts diagrams or exact tables without ASCII walls or jargon, act directly on discovered LAN devices, or review historical check runs and compare them live across mobile, foldable, and desktop screens.

### Triggers & End-to-End Steps
1. **Trigger**: User navigates to `/web` (live authenticated session) or `/web?demo=1` (zero-backend static/demo preview with sanitized sample telemetry).
2. **Pre-Unlock Gate (`PASS_HASH` Active)**:
   - Displays a distraction-free passphrase unlock screen (`Locked` badge) with a 1-tap link to sanitized `?demo=1` sample mode and optional redacted aggregate cron health status.
3. **Clickable Hero KPI Triage Strip (`4` Keyboard-Accessible Cards)**:
   - Bounded gauge card strictly for **`24h Uptime %`** (`0–100%`, single-line title preventing `"%"` wrap on narrow screens; displays **`—`** with subtext **`No scheduled checks yet`** when `0 / 0` scheduled checks exist so an unconfigured store never looks like an outage). Clicking opens **`Schedule & History`** and scrolls to **`Scheduled Checks & Destination Uptime`**.
   - Trackless interactive `.va-kpi-card` shortcuts for unbounded metrics: **`Active Problems`** (opens **`Schedule & History`** -> **`Scheduled Checks & Destination Uptime`**), **`Saved Destinations`** (scrolls to the **Saved Destinations** manager or opens **`+ Add Destination`** if none exist), and **`Saved History Size`** (`X.X MB of 256 MB`, opens **`Schedule & History`** -> **`Past Check Runs`**).
4. **Three Plain-Language Workspace Tabs**:
   - **`Checks`**:
     - Top **`Pinned Destinations`** bar with **`+ Add Destination`** directly beside **`Scan Pinned`** above the fold.
     - **`Run a Check`** with **4 clean Goal Category filters** (**`Path & Ping`** · **`Web & DNS`** · **`Ports & Host`** · **`Wake`**) filtering **`Check Type`** choices and updating destination placeholder, helper text, and context-specific inputs (`Port Group` for `Ports & Host`, saved MAC-enabled device chips + MAC field for `Wake`), plus a quiet `"Scan a full subnet in Local Network →"` jump link keeping full subnet discovery in one home.
     - Desktop (`>= 820px`) left-column compact **Saved Destinations** quick-list directly beneath **`Run a Check`** so both pinned and unpinned saved destinations can be run or edited beside the check runner, while the full management table sits below.
     - Plain-sentence verdict headers across single tools (omitting meaningless `0.00 ms` averages on `100%` loss), interactive Apache ECharts (`renderer: 'svg'`) charts (`Path Latency & Packet Loss` with matching indigo `Average RTT` legend marker swatch across all 4 themes, `Response Timing Breakdown`, `DNS Resolver Comparison`), **`Chart | Table`** toggle, **`Copy Summary`** (Markdown), **`Copy Data`** (TSV), and smooth scroll/focus to the Result Card with immediate `[RUNNING]` feedback whenever started from Pinned Destinations, Saved Destinations, or Local Network rows.
   - **`Local Network`**: Searchable, filterable inventory (`All` / `Physical Hardware` / `Containers & VMs` / `Changed vs. Baseline`) with built-in baseline selector, inline RTT response-time bars, hardware vendor names, open-port badges, and 1-click row actions (**Ping**, **Check Ports**, **Wake**, **Save**) that jump to `Checks` and focus the Result Card.
   - **`Schedule & History`**: `24h` / `7d` / `30d` window switcher, Apache ECharts response-time & outage timeline (`binTimeSeries` + warmup state when `< 10` checks), **`Scheduled Checks & Destination Uptime`** (showing a Quiet UI empty state with **`+ Enable 5-Min Monitoring`** when zero targets have 5-minute monitoring enabled), and **`Past Check Runs`** with plain-sentence summaries and a native `<dialog>` Past Run Drawer offering **Run Again & Compare** side-by-side diffs.
5. **Theme & Density Controls**: Switcher supports all 4 themes (`Pure White`, `Warm Paper`, `Dark Paper`, `Dark`) and Comfortable (`d2`) / Compact (`d3`) density persisted in `localStorage`, dynamically re-skinning all active ECharts SVG plots.

### Responsive Form Factor Behavior (`390px` / `900px` / `1440px`)
- **`390px` (Folded Phone)**: KPI cards stack cleanly in 2 columns with single-line `24h Uptime %` headers (zero `"%"` wrap) and `—` on unconfigured stores; Goal Category filters wrap 2×2 at `>= 44px` touch height; left-column duplicate Saved Destinations card hides (`< 820px`) so the Result Card appears immediately below `Run a Check`; mobile bottom dock (`N4`, `< 700px`) exposes `>= 44px` tap targets with `0px` horizontal overflow.
- **`900px` (Unfolded Tablet)**: Topbar switcher displays full title without bottom dock; 2-pane Checks split places `Run a Check` + compact `Saved Destinations` quick-list beside interactive ECharts visuals.
- **`1440px+` (Desktop)**: Renders the full multi-column workspace cleanly across all 4 themes with zero horizontal overflow or clipping.

### Verification Invariants
- Zero `#asciiOutput` blocks, zero `#styleSelect` dropdowns, zero `#quickChecksBar` duplicate quick-pills, and zero UI jargon appear in `/web` or `/demo/`.
- On a fresh store (`0 / 0` scheduled checks), `24h Uptime %` renders `—` with `"No scheduled checks yet"` (never `0.0%`), and `Scheduled Checks` renders its actionable empty state with `+ Enable 5-Min Monitoring`.
- `Average RTT` legend marker swatch matches the plotted dark-indigo dots (`--chart-2`) across all 4 themes.
- `/web/api/*` enforces strict `Origin` / same-origin and `Host` allowlist validation (anti-CSRF and anti-DNS-rebinding).
- `verify_visual_contract.py` + `audit_quiet_html.py --strict-drift` pass at `390px`, `900px`, and `1440px` across locked, unlocked, and `?demo=1` states with `0` blocklist regressions.

---

## Workflow 4: WF-04 — Three-Route OAW Projects Showcase (`Overview`, `Demo`, `Docs`)

### User Goal
A visitor opens the public project portal (`https://projects.oaworkbench.org/mcp-adv-netutils/`) to understand what **Advanced Network Utilities** checks in everyday plain language, try the interactive ECharts `/demo/` without deploying a container, or consult searchable documentation and Docker/Linux setup instructions.

### Triggers & End-to-End Steps
1. **Trigger**: User visits `./` (`Overview`), `./demo/`, or `./docs/` on the OAW Projects site.
2. **Route Structure**:
   - **`./` (`Overview`)**: Written in plain everyday operator language (what it checks: LAN/Wi-Fi slowdowns, DNS mismatches, TLS expiration, Wake-on-LAN, Saved Destinations, 30-day scheduled history) without compiler or kernel internals in the hero; links straight to interactive `./demo/` and setup `./docs/`.
   - **`./demo/` (`Demo`)**: Hosts the static zero-backend interactive Studio powered by self-contained vendored `echarts.min.js`, `quiet-evidence-bundle`, and sanitized sample snapshots/Saved Destinations—including the `+ Add Destination` top-bar trigger, desktop left Saved Destinations quick-list, 4 Goal Category filters (`Path & Ping`, `Web & DNS`, `Ports & Host`, `Wake`), clickable KPI triage cards, and matching `Average RTT` legend swatches.
   - **`./docs/` (`Docs`)**: Searchable plain-language reference covering Quickstart, the `33` registered MCP tools (`manage_saved_destinations` included), Network Studio (`/web` & `./demo/`), Docker & Linux container internals (`CGO_ENABLED=0`, `cap_net_raw+ep`, SQLite `WAL`), Cron & 30d Retention, Two-Doorway Security, and Skills.
3. **Locked-In `46px` Project Bar**: Desktop bar (`>= 680px`) widens `.oaw-pill-trigger` so **`Advanced Network Utilities`** displays completely without `...` truncation; mobile bar (`<= 679px`) truncates cleanly, and mobile `<pre>` code Copy buttons sit cleanly clear of code text on `390px` and `412px` viewports.

### Responsive Form Factor Behavior (`390px` / `900px` / `1440px`)
- **`390px` / `412px`**: Single-row sticky `46px` bar; Copy buttons on code blocks never overlap code text; cards collapse cleanly with `0px` horizontal overflow.
- **`900px` & `1440px+`**: Topbar displays full `Advanced Network Utilities` label untruncated; multi-column overview and `270px` docs sidebar align cleanly.

### Verification Invariants
- Automated CI privacy checks (`scripts/build_github_showcase.py --check`) verify `0` private `.lan` hostnames, private LAN IPs, real MAC addresses, or secrets appear across `build/gh-pages/` including `demo/vendor/`.
- Public `./demo/` stays 1:1 synced with live `internal/webui/assets/` behavior and styling.
- Display headings use **`Advanced Network Utilities`** while `mcp-adv-netutils` stays inside monospace code pills and CLI snippets.

---

## Workflow 5: WF-05 — Native Go Container, GHCR, Official MCP Registry & Live Deployment

### User Goal
The operator builds, publishes, and deploys `mcp-adv-netutils` as a compact single-layer pure-Go Alpine container with zero Node.js/`supergateway` wrapper, preserving backward-compatible LAN `/sse` clients while enabling `/web`, `/healthz`, Saved Destinations, and persistent 30-day SQLite storage.

### Triggers & End-to-End Steps
1. **Trigger**: Code merges to `develop`/`main` or a version tag triggers CI/release, or the operator deploys the container stack on an appliance/NAS host (e.g., Synology `ds1821+` via `portainer-gitops`).
2. **Pure-Go Container & Registry Packaging**:
   - Multi-stage `Dockerfile` builds `CGO_ENABLED=0` static binary (`17` MB range + single-layer `RUN --mount=type=bind` + `setcap cap_net_raw+ep` so the binary is never duplicated across layers!) running as `USER netutils` with `LABEL io.modelcontextprotocol.server.name="io.github.FrankXLT/mcp-adv-netutils"`.
   - `server.json` (`2025-12-11` schema) and GitHub Actions workflows run `go test -race ./...`, `--stdio` 33-tool JSON-RPC smoke checks, multi-arch Buildx GHCR pushes (`ghcr.io/frankxlt/mcp-adv-netutils`), and Cosign-verified `mcp-publisher` OIDC registry releases.
3. **Two-Doorway Live Stack Configuration**:
   - Native Go HTTP flags expose remote `/{PATH_SECRET}/mcp` + `/web` alongside LAN-only `/lan/{LAN_MCP_TOKEN}/mcp`, backward-compatible LAN `/sse` Streamable HTTP, and unauthenticated `GET /healthz` for uptime monitors.
   - Persistent volume mount (`/data`) stores `netutils_jobs.db`, paired with `cap_add: [NET_RAW]` and zero `runc exec` container healthchecks on older NAS kernels.

### Responsive Form Factor Behavior (`390px` / `900px` / `1440px`)
- `GET /healthz` and `/web` readiness verified across `390px`/`900px`/`1440px` after container startup.

### Verification Invariants
- Single-copy `Dockerfile` binary layer verified with `cap_net_raw+ep` intact and exact measured image size documented in `README.md` / `site/docs/`.
- `go test -race ./...` and `--stdio` 33-tool JSON-RPC smoke tests pass before GHCR/Registry publication.
- Remote and LAN doorways enforce proxy-header rejection and RFC1918 source checks on `/lan/*` and `/sse`.

---

## Workflow 6: WF-06 — Saved Destinations, Pinned Quick Sweeps & Watchlist Sync (`manage_saved_destinations`)

### User Goal
The operator saves everyday hosts, routers, NAS appliances, public sites, and Wake-on-LAN targets once—pinning key targets for 1-click sweeps, launching checks without re-typing IPs/MACs, promoting newly discovered LAN devices into persistent bookmarks, and toggling scheduled cron monitoring on or off from a single place.

### Triggers & End-to-End Steps
1. **Trigger**: Operator clicks **`+ Add Destination`** in the top Pinned Destinations bar or table header, clicks **Save Destination** on the Checks form, clicks **Save** on a LAN device row, edits/toggles a row in the desktop left **Saved Destinations** quick-list or bottom management table, clicks **`+ Enable 5-Min Monitoring`** from an empty Scheduled Checks panel, clicks a Pinned button or **Scan Pinned**, or calls MCP tool `manage_saved_destinations(action="list|save|delete|run")`.
2. **Persistence & Sync (`netutils_jobs.db` + `cronmon.Scheduler`)**:
   - `saved_destinations` SQLite table stores `id`, `name`, `target`, `category` (`Core|Website & API|LAN|Servers & NAS|Containers|Remote`), optional `mac`, `default_check`, `pinned`, `monitor_enabled`, and `monitor_schedule`.
   - Validation runs target strings through central `TargetGuard` so blocked metadata CIDRs cannot be bookmarked or scanned.
   - Toggling `monitor_enabled` on a Saved Destination automatically adds, updates, resumes, or removes the corresponding deterministic entry in the cron watchlist (`Scheduler.ManageWatchlist`).
3. **One-Click Pinned Bar, Left Quick-List, Wake Picker & Smooth Result Focus**:
   - Pinned Saved Destinations and **`+ Add Destination`** appear right above the `/web` Checks form; clicking **`Scan Pinned`** executes the default check for every pinned destination and displays a consolidated verdict strip.
   - Starting any check from a Pinned Destination, the desktop left **Saved Destinations** quick-list, the full **Saved Destinations** table, or a **Local Network** device row smoothly scrolls and focuses the Result Card with an immediate `[RUNNING]` indicator.
   - Selecting the **`Wake`** Goal Category (`Wake & Confirm Online` / `Send Wake Packet`) surfaces Saved Destinations with MAC addresses as 1-click chips so no MAC needs manual re-entry.

### Responsive Form Factor Behavior (`390px` / `900px` / `1440px`)
- **`390px`**: Pinned bar with **`+ Add Destination`** and **`Scan Pinned`** wraps cleanly with `>= 44px` touch targets; the desktop left quick-list hides (`< 820px`) so the Result Card stays directly beneath `Run a Check`, while the full Saved Destinations table collapses into stacked cards with `Run`, `Edit`, `Pin`, and `Monitor` controls.
- **`900px` & `1440px+`**: Displays pinned quick-launch bar + **`+ Add Destination`** above the Checks split, the compact **Saved Destinations** quick-list directly under `Run a Check`, and the full management table below.

### Verification Invariants
- `manage_saved_destinations` is registered in both MCP (`33` total tools) and `/web/api/destinations` (guarded by `TargetGuard` + Deadbolt).
- Sanitized `?demo=1` and static `/demo/` Saved Destinations never contain RFC1918 IPs, real MACs, or `.lan` hostnames.

---

## Workflow 7: WF-07 — Scheduled Cron Watchlists, Alerts After 2 Failed Checks & 30-Day Retained Job Re-Pulls

### User Goal
The operator wants continuous background visibility into WAN/tunnel reachability, MTU black holes, split-horizon DNS drift, TLS expiration, and nightly ARP inventory changes—without noisy single-packet false alerts or unbounded SQLite growth, plus interactive visual comparison between past and live runs.

### Triggers & End-to-End Steps
1. **Trigger**: Scheduled jobs in `watchlist.yaml` (or synced monitored Saved Destinations) fire automatically via in-process `robfig/cron/v3` (`SkipIfStillRunning`) or external `--run-watchlist-once` systemd timer, or the user calls `get_cron_status`, `manage_cron_watchlist`, or `get_job_report`, clicks the **`24h Uptime %`**, **`Active Problems`**, or **`Saved History Size`** KPI cards, or opens **Schedule & History** in `/web`.
2. **Watchlist Execution, Empty States & Alerts After 2 Failed Checks**:
   - Default watchlist cadence runs `*/5m` canary `recipe_diff_ping`, `*/15m` `mtu_path_probe`, `*/6h` `recipe_diff_dns` and `recipe_diff_http`, plus nightly `tls_certificate_check` and `recipe_diff_snapshot`.
   - Status alerts flip only after **`>= 2` consecutive non-OK ticks**.
   - On a fresh store where `0 / 0` scheduled checks have run, **`24h Uptime %`** renders **`—`** with subtext **`No scheduled checks yet`** (never `0.0%`), and **`Scheduled Checks & Destination Uptime`** renders an actionable empty state with **`+ Enable 5-Min Monitoring`** opening the destination editor with 5-minute monitoring pre-selected.
3. **30-Day Retained Job Archive & Down-Aging (`netutils_jobs.db`)**:
   - Every run writes a stable `job_id`, plain-sentence `summary`, and `expires_at` (`30d` default for manual runs, recipes, and incident reports).
   - High-frequency healthy `*/5m` cron ticks undergo **`7d -> 30d` two-stage down-aging** to retain incident fidelity while keeping database footprint under `--max-store-mb 256` (`Saved History Size`).
   - An hourly TTL reaper deletes expired rows and executes `PRAGMA incremental_vacuum`.
4. **Past Run Drawer & Run Again & Compare**:
   - `get_cron_status(period="24h"|"7d"|"30d")` returns `< 5ms` cached ASCII sparklines/bars in CLI/MCP, and feeds structured time-series points to `/web` ECharts response-time timelines (`Warming up — N checks collected` when `< 10` checks).
   - Clicking any row in **`Past Check Runs`** opens a native `<dialog>` Past Run Drawer showing the chart/table, plain-sentence summary, and **Run Again & Compare** side-by-side live delta.

### Responsive Form Factor Behavior (`390px` / `900px` / `1440px`)
- **`390px`**: `get_cron_status(style="quick")` fits sparklines and alert badges inside `<= 40` cols; `/web` stacks the ECharts timeline, Scheduled Checks empty state or uptime rows, and Past Check Runs stacked cards cleanly with `0px` horizontal overflow.
- **`900px` & `1440px+`**: Renders full `24h`/`7d`/`30d` ECharts timelines, per-destination strips, and Past Run Drawer side-by-side comparisons.

### Verification Invariants
- Single transient non-OK tick increments streak without flipping alert status (`streak == 1 -> pending`, `streak >= 2 -> ALERT`).
- Fresh stores with `0 / 0` scheduled checks display `—` (`No scheduled checks yet`) on `24h Uptime %` and the `+ Enable 5-Min Monitoring` empty state on `Scheduled Checks`.
- Single-tool live verdicts and `Past Check Runs` summaries use plain everyday sentences without meaningless `0.00 ms` averages on `100%` packet loss.
- SQLite readers open with `?mode=ro` under WAL mode; hourly reaper + `--max-store-mb 256` cap prevents unbounded disk growth.

---

## Workflow 8: WF-08 — Bundled Agent Skills & Future Wave 4 Capture Roadmap

### User Goal
AI coding and operations agents need concise, deterministic behavioral playbooks so they format CLI/MCP ASCII output verbatim, interpret `icmp` vs `tcp_fallback` accurately, separate UAA vs LAA hardware, manage cron/Saved Destinations, respect the Deadbolt, and understand the upcoming passive capture roadmap.

### Triggers & End-to-End Steps
1. **Trigger**: An agent loads one of the 5 bundled skills under `skills/*/SKILL.md` before invoking `mcp-adv-netutils` tools, or an operator reviews `ROADMAP.md` for Wave 4 milestones.
2. **5 Bundled Agent Skills (`skills/`)**:
   - `skills/netutils-ascii-display/SKILL.md`: Enforces `default` (`72c`), `quick` (`<= 40c`), `rich` (`76c`), `json` (`< 18.5 KB`) formatting for terminal/MCP callers, verbatim fenced output blocks, and `render_run_digest` re-rendering.
   - `skills/netutils-differential-ping/SKILL.md`: Guides outage triage using `recipe_diff_ping`, `recipe_path_autopsy`, `mtu_path_probe`, and `mtr_path_quality`, including `icmp` vs `tcp_fallback` interpretation.
   - `skills/netutils-lan-radar/SKILL.md`: Guides `recipe_lan_radar`, ARP/mDNS/SSDP/PTR/SNMP correlation, Physical vs Container/VM separation, `recipe_diff_snapshot`, and `recipe_wake_verify`.
   - `skills/netutils-split-horizon-web/SKILL.md`: Guides `recipe_diff_dns`, `split_dns_audit`, `recipe_diff_http`, `recipe_host_card`, Deadbolt (`unlock_netutils` / `lock_netutils`), and `/web` Studio triage.
   - `skills/netutils-cron-monitor/SKILL.md`: Guides `get_cron_status` (`24h`/`7d`/`30d`), `manage_cron_watchlist`, `manage_saved_destinations`, `get_job_report` (`30d` retention / `expires_at`), alerts after 2 failed checks, and `7d -> 30d` down-aging.
3. **Wave 4 Roadmap Alignment (`ROADMAP.md`)**:
   - Documents the next milestone: Deadbolt-gated, bounded on-demand BPF `SPAN`/`ERSPAN` passive packet capture streaming via pure-Go `parquet-go` with **`72h` raw `.parquet` TTL** and **`30d` SQLite summary retention** in `netutils_jobs.db`.

### Responsive Form Factor Behavior (`390px` / `900px` / `1440px`)
- Skills explicitly instruct agents to choose `style="quick"` (`<= 40` cols) for mobile clients (`390px`) and `style="default"`/`"rich"` for tablet/desktop (`900px`/`1440px+`), keeping verbatim fenced code blocks readable without wrapping.

### Verification Invariants
- All 5 `skills/*/SKILL.md` files match implemented tool names (`33` total MCP tools), flags, and security boundaries (`PASS_HASH`, `169.254.0.0/16` block).
- Wave 4 passive capture remains cleanly scoped to `ROADMAP.md` (not claimed as active in v2.0.0 runtime).
