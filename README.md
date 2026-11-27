# Advanced Network Utilities (`mcp-adv-netutils`) v2.0.0

[![Docker Image](https://img.shields.io/badge/docker-ghcr.io%2Ffrankxlt%2Fmcp--adv--netutils-blue?logo=docker)](https://github.com/FrankXLT/mcp-adv-netutils/pkgs/container/mcp-adv-netutils)
[![Project Showcase](https://img.shields.io/badge/OAW%20Projects-Overview%20%7C%20Demo%20%7C%20Docs-2563eb)](https://projects.oaworkbench.org/mcp-adv-netutils/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Advanced Network Utilities** (`mcp-adv-netutils`) is a pure-Go (`CGO_ENABLED=0`) [Model Context Protocol (MCP)](https://modelcontextprotocol.io/introduction) server, scheduled cron monitor, and embedded 4-theme **Operator Studio (`/web`)** engineered for Layer 1–Layer 7 diagnostics across home labs, multi-VLAN infrastructure, and container hosts.

> **Interactive Showcase & Guides**: Visit [**projects.oaworkbench.org/mcp-adv-netutils/**](https://projects.oaworkbench.org/mcp-adv-netutils/) for the live zero-backend `?demo=1` Operator Studio (`./demo/`) and searchable plain-language guides (`./docs/`), or read [docs/WORKFLOWS.md](docs/WORKFLOWS.md) for the complete `WF-01..WF-08` behavioral baseline.

---

## What's New in v2.0.0

- **Zero Node.js / Zero `supergateway` Runtime**: Ships as a single static `CGO_ENABLED=0` Go binary inside a single-layer Alpine container (`~41.5 MB` unpacked / `~11.4 MB` compressed, `USER netutils`, `setcap cap_net_raw+ep` via `RUN --mount=type=bind`), serving native `--stdio`, Streamable HTTP, backward-compatible `/sse`, `/web`, and `/healthz`.
- **33 Registered MCP Tools**: Combines 12 hardened core tools, 6 active L2–L7 probes, 8 coordinated Diagnostic Recipes (`recipe_*`), `render_run_digest`, 4 Cron, Saved Destinations & Archive tools (adding `manage_saved_destinations`), and `unlock_netutils`/`lock_netutils`.
- **Three-Tier ASCII Styles (`style`)**: Deterministic monospace cards across every tool and recipe—`default` (`72` columns exact), `quick` (`<= 40` columns borderless for `390px` mobile), `rich` (`76` columns boxed TUI), and `json` (`< 18.5 KB` wire cap with `FAIL`/`WARN` sorted first).
- **30-Day SQLite Job Archive, Saved Destinations & Two-Tick Cron Watchlist**: Pure-Go `robfig/cron/v3` scheduler running `watchlist.yaml` plus `dest_<id>` Saved Destination monitors into WAL SQLite (`netutils_jobs.db` via `modernc.org/sqlite`), featuring **Two-Tick Alert Hysteresis** (`>= 2` consecutive non-OK ticks), **`7d -> 30d` healthy tick down-aging**, hourly TTL reaping + `PRAGMA incremental_vacuum`, and `--max-store-mb 256` cap.
- **Thirty-Minute Passphrase Deadbolt & Two-Doorway Setup**: Voice-normalized SHA-256 lock (`PASS_HASH` + `crypto/subtle.ConstantTimeCompare`) paired with a remote `/{PATH_SECRET}/mcp` + `/web` doorway, a LAN-only `/lan/{LAN_MCP_TOKEN}/mcp` + `/sse` doorway, and central CIDR target guard blocking `169.254.0.0/16`.
- **Embedded 4-Theme Network Studio (`/web`)**: Responsive Quiet UI (`//go:embed`) across `Pure White`, `Warm Paper`, `Dark`, and `Dark Paper` themes featuring Apache ECharts SVG visualizations, Pinned Destinations & **Scan Pinned**, goal-grouped checks, Chart/Table toggle, Summary/TSV export, Saved Destinations manager, and Past Run Drawer (**Run Again & Compare**), plus `?demo=1` preview mode.
- **5 Bundled Agent Skills (`skills/`)**: Ready-to-use `SKILL.md` playbooks guiding LLM formatting, differential ping interpretation, LAN radar sweeps, split-horizon triage, and cron/destination monitoring.

---

## MCP Tool Suite

`mcp-adv-netutils` v2.0.0 provides **30 core diagnostic, recipe, destination, and archive tools** (`12` hardened core + `6` active L2–L7 + `8` Diagnostic Recipes + `4` Cron, Destinations & Archive), plus `render_run_digest` and the `unlock_netutils` / `lock_netutils` Deadbolt controls (`33` total registered MCP tools).

### 1. Hardened Core Tools (12)

| Tool | Layer | Capabilities & v2.0.0 Hardening |
| :--- | :--- | :--- |
| **`mac_vendor_lookup`** | L2 | Embedded `39,800+` IEEE OUI lookup; separates physical `[UAA]` from Docker/VM `[LAA]` (`02:42:...`) |
| **`ping`** | L3 | Per-call Echo ID/sequence isolation, IPv4/IPv6 TTL control messages, explicit `probe_mode` (`icmp` vs `tcp_fallback`) |
| **`traceroute`** | L3 | Rejects leading `-` targets, enforces `"--"`, bounds concurrent hop PTR lookups |
| **`tcp_port_scan`** | L4 | Concurrent TCP connect scan with named presets (`common`, `homelab`, `web`, `iot`; default `common`) |
| **`dns_reverse_batch`** | L7 | Concurrent reverse PTR resolution capped at `256` validated IPs per call |
| **`wol_wake`** | L2 | Sends standard 102-byte UDP Wake-on-LAN Magic Packet frames (`port` `7` or `9`) |
| **`local_dns_query`** | L7 | Queries OS-configured local resolvers (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `PTR`, `TXT`, etc.) |
| **`remote_dns_query`** | L7 | Queries Cloudflare and Google DNS-over-HTTPS (DoH) |
| **`resolve_hostname`** | L7 | Resolves IPv4, IPv6, or dual-stack host addresses |
| **`whois_query`** | L7 | Domain registration metadata lookup via WHOIS |
| **`http_ping`** | L7 | HTTP timing waterfall (`dns`, `conn`, `tls`, `ttfb`, `total`) |
| **`tls_certificate_check`** | L7 | Verifies against `x509.SystemCertPool()` + wire intermediates; supports `Ed25519` keys |

### 2. Active L2–L7 Diagnostic Probes (6)

| Tool | Layer | Description |
| :--- | :--- | :--- |
| **`arp_neighbor_sweep`** | L2 | OS/ARP neighbor discovery (`mdlayher/arp`) enriched with OUI vendors and UAA/LAA flags |
| **`mtu_path_probe`** | L3 | Probes `1500` / `1492` / `1420` / `1280` DF frames to catch tunnel and WAN fragmentation black holes |
| **`mtr_path_quality`** | L3 | Multi-cycle per-hop loss, min/avg/max RTT, and jitter path quality matrix |
| **`mdns_ssdp_discover`** | L7 | Bounded mDNS (`hashicorp/mdns`) and SSDP local service discovery |
| **`split_dns_audit`** | L7 | Side-by-side comparison of internal local DNS vs. external DoH answers |
| **`snmp_switch_port`** | L2 | Read-only SNMP (`gosnmp`) switch port, VLAN, and MAC FDB correlation |

### 3. Diagnostic Recipes, Digest, Cron, Destinations & Deadbolt Tools

| Category | Tools | Purpose |
| :--- | :--- | :--- |
| **Diagnostic Recipes (8)** | `recipe_diff_ping`, `recipe_diff_dns`, `recipe_diff_http`, `recipe_diff_snapshot`, `recipe_host_card`, `recipe_lan_radar`, `recipe_path_autopsy`, `recipe_wake_verify` | Coordinated multi-probe differential ladders, UAA/LAA LAN sweeps, before/after snapshot diffs (`[+]`, `[-]`, `[~]`), and WOL verification |
| **Digest Renderer (1)** | `render_run_digest` | Re-renders any persisted `job_id` report on demand into `default`, `quick`, `rich`, or `json` |
| **Cron, Destinations & Archive (4)** | `get_cron_status`, `manage_cron_watchlist`, `manage_saved_destinations`, `get_job_report` | `< 5ms` `24h`/`7d`/`30d` ASCII health strips, `watchlist.yaml` management, `list`/`save`/`delete`/`run` saved targets (`TargetGuard` + `dest_<id>` cron sync), and 30-day `job_id` re-pulls with `expires_at` |
| **Deadbolt Session (2)** | `unlock_netutils`, `lock_netutils` | Voice-normalized SHA-256 unlock (`30m` sliding TTL) and immediate manual relock |

---

## Three-Tier ASCII Styles & Output Budgets

Every tool, Diagnostic Recipe, and cron summary supports a `style` parameter designed for clean monospace rendering across mobile phones, IDE panes, and CI automation:

| `style` | Width / Budget | Best For |
| :--- | :--- | :--- |
| **`default`** *(default)* | `72` columns exact | Chat apps, IDE terminals, and unfolded tablets (`900px`) |
| **`quick`** | `<= 40` columns, borderless | Folded phones (`390px`) with zero line wrapping |
| **`rich`** | `76` columns, boxed TUI | Desktop (`1440px+`) hop ladders, histograms, and status badges |
| **`json`** | `< 18.5 KB` wire cap | Programmatic diffing with `FAIL` and `WARN` rows sorted first |

---

## Cron Watchlist, Saved Destinations & 30-Day Job Archive

Scheduled jobs in [`watchlist.yaml`](watchlist.yaml) and monitored Saved Destinations (`dest_<id>`) run automatically in-process via `robfig/cron/v3` (`SkipIfStillRunning`) or as a one-shot external timer (`--run-watchlist-once`):

- **Default Watchlist Cadence**: `*/5m` canary `recipe_diff_ping`, `*/15m` `mtu_path_probe`, `*/6h` `recipe_diff_dns` and `recipe_diff_http`, plus nightly `tls_certificate_check` and `recipe_diff_snapshot`.
- **Saved Destinations (`manage_saved_destinations`)**: Stores friendly targets (category, optional Wake MAC, default check, pinned toggle, and 5-minute monitor toggle) in SQLite (`saved_destinations`), validates targets via `TargetGuard`, supports `list` | `save` | `delete` | `run`, and syncs `dest_<id>` checks with the cron watchlist.
- **Two-Tick Alert Hysteresis**: Alerts flip only after **`>= 2` consecutive non-OK ticks**, preventing single-packet jitter from triggering false alarms.
- **30-Day WAL SQLite Archive (`netutils_jobs.db`)**: Pure-Go `modernc.org/sqlite` (`?mode=ro` readers) retains every manual, MCP, and incident report for `30d` (`get_job_report`), down-ages healthy `*/5m` ticks across `7d -> 30d`, and runs an hourly TTL reaper with `PRAGMA incremental_vacuum` bounded by `--max-store-mb 256`.

---

## 5-Layer Security & Two-Doorway Setup

See [SECURITY.md](SECURITY.md) for full details on the 5-layer defense-in-depth architecture:

1. **Thirty-Minute Passphrase Deadbolt (`PASS_HASH`)**: Voice-normalized SHA-256 verification via `crypto/subtle.ConstantTimeCompare` with automatic `30m` relock (and optional redacted aggregate cron summaries while locked).
2. **Two-Doorway Setup**:
   - **Remote Doorway (`/{PATH_SECRET}/mcp` + `/web`)**: High-entropy path secret + Deadbolt protection for mobile/remote clients.
   - **LAN-Only Doorway (`/lan/{LAN_MCP_TOKEN}/mcp` + `/sse`)**: Rejects `X-Forwarded-For` / `X-Real-IP` / `Forwarded` proxy headers and non-RFC1918 source IPs.
3. **`/web/api/*` Anti-CSRF & Anti-DNS-Rebinding**: Strict `Origin` and `Host` header validation.
4. **Central Target Guard & CLI `--` Prevention**: Enforces `--allow-cidrs` / `--deny-cidrs` on DNS-resolved IPs, unconditionally blocks `169.254.0.0/16` metadata endpoints, and blocks leading `-` target injection.
5. **Unprivileged Container**: Runs as `USER netutils` with minimal `cap_net_raw+ep` capability—no `root`, no `Privileged: true`.

---

## Embedded Operator Studio (`/web`)

Compiled directly into the Go binary (`//go:embed`), `/web` provides a 4-theme Quiet UI Network Studio (`Pure White`, `Warm Paper`, `Dark`, `Dark Paper`) with Comfortable (`d2`) and Compact (`d3`) density:

- **Pre-Unlock Gate**: Clean passphrase challenge when `PASS_HASH` is locked, with a 1-tap link to depersonalized `?demo=1` preview fixtures.
- **Apache ECharts SVG Visualizations & Export**: Theme-aware Apache ECharts SVG charts for path latency whiskers, HTTP timing waterfalls, DNS comparisons, and `24h`/`7d`/`30d` uptime timelines, paired with a **Chart / Table** toggle and **Copy Summary** / **Copy Data** (TSV) export.
- **Pinned Destinations & Goal-Grouped Checks**: 1-click Pinned Destinations bar + **Scan Pinned** sweep, goal-grouped check selector (`Connectivity`, `Web & TLS`, `DNS`, `Local Network`), and a full **Saved Destinations** manager (`add`, `edit`, `pin`, `monitor`, `delete`).
- **Three Integrated Tabs & Past Run Drawer**: **`Checks`**, **`Local Network`** (Physical Hardware vs. Containers & VMs with `Ping`/`Ports`/`Wake`/`Save` actions and baseline diffs), and **`Schedule & History`** (`24h`/`7d`/`30d` health timeline + 30-day Past Check Runs opening the **Past Run Drawer** with **Run Again & Compare**).
- **Responsive Breakpoints**: `>= 40px` touch targets and `>= 16px` inputs with `0px` horizontal overflow at `390px` (phone), 2-pane workspace at `900px` (tablet), and full Studio workspace at `1440px+` (desktop).

---

## Bundled Agent Skills (`skills/`)

Five ready-to-use `SKILL.md` guides ship inside [`skills/`](skills):

- [`skills/netutils-ascii-display`](skills/netutils-ascii-display/SKILL.md) — Deterministic `default`/`quick`/`rich`/`json` formatting and `render_run_digest`.
- [`skills/netutils-differential-ping`](skills/netutils-differential-ping/SKILL.md) — `recipe_diff_ping`, `recipe_path_autopsy`, `mtu_path_probe`, `mtr_path_quality`, and `icmp` vs. `tcp_fallback` triage.
- [`skills/netutils-lan-radar`](skills/netutils-lan-radar/SKILL.md) — `recipe_lan_radar`, ARP/mDNS/SSDP/PTR/SNMP correlation, UAA vs. LAA grouping, `recipe_diff_snapshot`, and `recipe_wake_verify`.
- [`skills/netutils-split-horizon-web`](skills/netutils-split-horizon-web/SKILL.md) — `recipe_diff_dns`, `split_dns_audit`, `recipe_diff_http`, `recipe_host_card`, Deadbolt, and Apache ECharts `/web` Studio.
- [`skills/netutils-cron-monitor`](skills/netutils-cron-monitor/SKILL.md) — `get_cron_status`, `manage_cron_watchlist`, `manage_saved_destinations`, `get_job_report`, Two-Tick Alert Hysteresis, and `7d -> 30d` down-aging.

---

## Deployment & Setup

### Docker Compose (Synology / Linux Docker host / Portainer GitOps Pattern)

Deploy the single-layer Alpine pure-Go image (`~41.5 MB` unpacked / `~11.4 MB` compressed, `cap_net_raw+ep` via `RUN --mount=type=bind`) with persistent 30-day SQLite storage, `NET_RAW` for ICMP/ARP probes, and native HTTP flags (zero `supergateway`, and no `runc exec` container healthchecks on Synology DSM Kernel 4.4—use external `GET /healthz` checks instead):

```yaml
services:
  mcp-netutils:
    image: ghcr.io/frankxlt/mcp-adv-netutils:latest
    container_name: mcp-netutils
    restart: unless-stopped
    init: true
    cap_add:
      - NET_RAW
    environment:
      - PASS_HASH=${PASS_HASH}
      - PATH_SECRET=${PATH_SECRET}
      - LAN_MCP_TOKEN=${LAN_MCP_TOKEN}
    command:
      - --http
      - --http-addr=:8000
      - --data-dir=/data
      - --max-store-mb=256
      - --watchlist=/app/watchlist.yaml
    volumes:
      - ./data:/data
    ports:
      - "8000:8000"
    # On Synology DSM Kernel 4.4, omit container exec healthchecks and monitor GET /healthz externally
```

### Docker CLI (`--stdio` & HTTP Modes)

```bash
# Interactive --stdio JSON-RPC mode
docker run -i --rm ghcr.io/frankxlt/mcp-adv-netutils:latest --stdio

# Native HTTP mode with persistent SQLite store and /web Studio
docker run -d \
  --name mcp-adv-netutils \
  --cap-add NET_RAW \
  -p 8000:8000 \
  -v mcp_netutils_data:/data \
  -e PASS_HASH="<sha256-hex>" \
  -e PATH_SECRET="<high-entropy-secret>" \
  -e LAN_MCP_TOKEN="<lan-token>" \
  ghcr.io/frankxlt/mcp-adv-netutils:latest \
  --http --http-addr=:8000 --data-dir=/data
```

### MCP Client Configuration

```json
{
  "mcpServers": {
    "netutils-lan": {
      "url": "http://netutils.example.internal:8000/sse"
    },
    "netutils-stdio": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "ghcr.io/frankxlt/mcp-adv-netutils:latest", "--stdio"]
    }
  }
}
```

---

## Building from Source & Testing

```bash
git clone https://github.com/FrankXLT/mcp-adv-netutils.git
cd mcp-adv-netutils

# Build static pure-Go binary (CGO_ENABLED=0)
CGO_ENABLED=0 go build -ldflags="-s -w" -o mcp-adv-netutils .

# Run offline race-enabled unit tests
go test -race ./...

# Single-shot watchlist execution (for external systemd timers)
./mcp-adv-netutils --run-watchlist-once --watchlist=./watchlist.yaml --data-dir=./data
```

---

## Documentation & Roadmap

- [**docs/WORKFLOWS.md**](docs/WORKFLOWS.md) — Common Terms Glossary and bound workflows (`WF-01`..`WF-08`) across `390px`, `900px`, and `1440px`.
- [**SECURITY.md**](SECURITY.md) — 5-Layer Security Architecture, Passphrase Deadbolt, and CIDR Target Guard.
- [**ROADMAP.md**](ROADMAP.md) — Next milestone (**Wave 4**): Deadbolt-gated on-demand BPF `SPAN`/`ERSPAN` capture -> pure-Go `parquet-go` (`72h` raw TTL + `30d` SQLite summary retention).

## Attribution & License

Originally forked from [`patrickdappollonio/mcp-netutils`](https://github.com/patrickdappollonio/mcp-netutils) and expanded into **Advanced Network Utilities** (`FrankXLT/mcp-adv-netutils`) with pure-Go single-binary transport, active L2–L7 diagnostics, Diagnostic Recipes, 30-day SQLite cron monitoring, and the embedded 4-theme Operator Studio.

Licensed under the MIT License — see [LICENSE](LICENSE).
