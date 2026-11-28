# Roadmap (`mcp-adv-netutils`)

## v2.0.0 – v2.1.0 — Shipped Capabilities

`mcp-adv-netutils` v2.0.0–v2.1.0 establishes a complete Layer 1–Layer 7 diagnostic, inventory, and continuous monitoring MCP platform across **33 registered MCP tools**, with **v2.1.0** adding fast parallel wave MTR, silent CoPP transit separation, historical window auditing, `/web` Studio live progress/appearance/multi-point ping upgrades, and 100% GitHub Community Standards + MCP Registry readiness:

- **Core L2–L7 Primitives & Smart Path Probing**:
  - Embedded IEEE OUI hardware vendor resolution (`39,800+` OUIs via `//go:embed`) with UAA physical vs. LAA (`02:42:...` Docker/VM) classification.
  - Fast parallel per-TTL wave `mtr_path_quality` (`~2–5s` with unique per-hop/per-cycle `(ID, Seq)` encoding and trailing-hop trim), smart `ICMP -> TCP 443/80 -> UDP` auto-fallback across `traceroute`, `mtr_path_quality`, and `recipe_path_autopsy`, and silent CoPP transit router separation (`silent_transit_hops`, `dest_loss_pct`).
  - `mtu_path_probe` (`1500`/`1492`/`1420`/`1280`), `tcp_port_scan`, `dns_reverse_batch`, `wol_wake`, `ping` (with `icmp` and `tcp_fallback`), `http_ping`, `tls_certificate_check`, `local_dns_query`, `remote_dns_query`, `resolve_hostname`, and `whois_query`.
- **Diagnostic Recipes & Workflows**:
  - Differential outage triage (`recipe_diff_ping`, `recipe_path_autopsy`).
  - LAN discovery & change tracking (`recipe_lan_radar`, `arp_neighbor_sweep`, `mdns_ssdp_discover`, `snmp_switch_port`, `recipe_diff_snapshot`, `recipe_wake_verify`).
  - Split-horizon & web diagnostics (`recipe_diff_dns`, `split_dns_audit`, `recipe_diff_http`, `recipe_host_card`).
- **Deterministic ASCII / TUI Display Engine & Historical Window Auditing**:
  - `style` modes: `default` (72 cols exact), `quick` (`<= 40` cols borderless for 390px mobile), `rich` (76 cols boxed TUI), and `json` (`< 18.5 KB` with `FAIL`/`WARN` sorted first).
  - `render_run_digest`: single `job_id` re-rendering plus one-call historical window auditing & trend summaries (`window`, `since`/`until`, `target`, `tool_name`, `status`, `incidents_only`, `limit`, `window_summary`).
- **Scheduled Cron Monitor, Saved Destinations & Persistence**:
  - `watchlist.yaml` scheduler with `get_cron_status` (`24h`/`7d`/`30d`), `manage_cron_watchlist`, `manage_saved_destinations` (`list` | `save` | `delete` | `run` + `dest_<id>` cron watchlist sync + `TargetGuard`), `get_job_report`, **Two-Tick Alert Hysteresis** (`>= 2` consecutive non-OK ticks), and **`7d -> 30d` healthy tick down-aging** in `netutils_jobs.db`.
- **Browser Network Studio (`/web`), 5-Layer Security & Registry Readiness**:
  - 4-theme Quiet UI Studio (`//go:embed`) featuring a live **In-Flight Progress Card** + **`Cancel`** (`AbortController`), consolidated **`Appearance ▾`** popover (themes + spacing), unified single-chart **`Multi-Point Ping`**, **Apache ECharts SVG** visualizations (with collapsed neutral gray bands for silent CoPP transit routers), **Pinned Destinations** & **Scan Pinned**, goal-grouped checks, **Chart / Table** toggle, **Summary / TSV** export, **Saved Destinations** manager, and **Past Run Drawer** (**Run Again & Compare**).
  - Protected by `Origin`/`Host` anti-CSRF & anti-DNS-rebinding guards, Thirty-Minute Passphrase Deadbolt, Two-Doorway remote/LAN routing, central CIDR Target Guard, and a single-layer Alpine image (`~41.5 MB` unpacked / `~11.4 MB` compressed, `USER netutils`, `cap_net_raw+ep` via `RUN --mount=type=bind`).
  - Ships 100% GitHub Community Standards (`CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, issue/PR templates, updated `LICENSE`) and MCP Registry ownership (`mcp-name: io.github.FrankXLT/mcp-adv-netutils`).

---

## Next Milestone: Wave 4 — On-Demand BPF `SPAN` / `ERSPAN` Capture & Parquet Telemetry

Wave 4 extends `mcp-adv-netutils` from active probing into bounded, agent-friendly passive packet telemetry without external capture databases or unbounded disk growth:

1. **On-Demand BPF `SPAN` / `ERSPAN` Packet Capture**:
   - Triggered, time- and byte-bounded packet capture over mirrored `SPAN` ports or `ERSPAN` (GRE-encapsulated) streams using strict BPF capture filters.
   - Enforces capture duration, packet-count, and CIDR guardrails under the Thirty-Minute Passphrase Deadbolt (`unlock_netutils`).
2. **Pure-Go `parquet-go` Writer**:
   - Streams decoded L2–L7 packet headers and flow metadata directly into columnar Apache Parquet (`.parquet`) files using pure-Go `parquet-go` (preserving `CGO_ENABLED=0` static binary builds).
3. **Dual-Tier Retention Lifecycle (`72h` Raw + `30d` SQLite Summaries)**:
   - **Raw `.parquet` Capture Files (`72h` TTL)**: Automatically rotated and purged after **72 hours** (`72h`) to bound disk consumption on appliance and NAS hosts.
   - **SQLite Summary Records (`30d` Retention)**: Flow aggregates, anomaly counts, and capture digests persist for **30 days** (`30d`) inside `netutils_jobs.db`, queryable alongside `get_job_report` and `render_run_digest`.
