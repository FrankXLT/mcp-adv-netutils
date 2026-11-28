# Contributing to Advanced Network Utilities (`mcp-adv-netutils`)

Thank you for your interest in contributing to **Advanced Network Utilities** (`mcp-adv-netutils`). This guide covers the project layout, build and verification commands, coding standards, and security practices.

---

## Architecture Overview

`mcp-adv-netutils` is a pure-Go (`CGO_ENABLED=0`) MCP server, scheduled cron monitor, and embedded Operator Studio (`/web`) organized into cohesive internal packages:

| Path | Responsibility |
| :--- | :--- |
| [`main.go`](main.go) | CLI flag parsing, runtime wiring, `--stdio` / `--http` / `--run-watchlist-once` startup, and shutdown lifecycle |
| [`internal/ping`](internal/ping) | ICMP echo and TCP fallback ping probes with per-call ID/sequence isolation |
| [`internal/traceroute`](internal/traceroute) | Path tracing with strict target validation (`--` end-of-options) and bounded hop PTR lookups |
| [`internal/probe`](internal/probe) | Active L2–L7 diagnostics (`arp_neighbor_sweep`, `mtu_path_probe`, `mtr_path_quality`, `mdns_ssdp_discover`, `split_dns_audit`, `snmp_switch_port`) |
| [`internal/recipes`](internal/recipes) | Coordinated multi-probe Diagnostic Recipes (`recipe_*`) and run digest formatting (`render_run_digest`) |
| [`internal/dispatch`](internal/dispatch) | Tool execution routing, concurrency bounds, and job lifecycle integration |
| [`internal/store`](internal/store) | Pure-Go WAL SQLite archive (`netutils_jobs.db` via `modernc.org/sqlite`), Saved Destinations, TTL reaping, and size caps |
| [`internal/cronmon`](internal/cronmon) | `robfig/cron/v3` watchlist scheduler, Saved Destination monitor sync, and Two-Tick Alert Hysteresis |
| [`internal/security`](internal/security) | Passphrase Deadbolt (`PASS_HASH`), central CIDR Target Guard (`169.254.0.0/16` block), and anti-CSRF/anti-DNS-rebinding checks |
| [`internal/transport`](internal/transport) | Two-Doorway HTTP routing (`/{PATH_SECRET}/mcp`, `/lan/{LAN_MCP_TOKEN}/mcp`, `/sse`, `/healthz`) and request boundary enforcement |
| [`internal/webui`](internal/webui) | Embedded 4-theme Quiet UI Operator Studio (`//go:embed`) with Apache ECharts SVG views and `?demo=1` preview support |
| [`internal/server`](internal/server) | MCP server registration (33 tools), schema definitions, and handler wiring |

Supporting core tool and formatting packages also live under `internal/` (`ascii`, `dns`, `http_ping`, `mac_lookup`, `port_scan`, `resolver`, `response`, `tls`, `utils`, `whois`, `wol`).

---

## Development Prerequisites & Build

- **Go**: `1.26` or newer (`go.mod` targets `go 1.26.0`)
- **Python**: `3.12` (for showcase/manifest checks)
- **System dependency**: `traceroute` (required for traceroute-backed tests and runtime execution)
- **Linter**: `golangci-lint` v2 (`golangci.yaml`)

Build a static pure-Go binary with `CGO_ENABLED=0`:

```bash
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -trimpath -tags netgo .
```

---

## Verification & Quality Gates

Run the full verification suite locally before opening a pull request. Every check below mirrors the [CI workflow](.github/workflows/ci.yml):

1. **Formatting & Static Analysis**:
   ```bash
   gofmt -l .
   go vet ./...
   golangci-lint run --config=golangci.yaml
   ```
   *(CI also passes `--max-issues-per-linter=0 --max-same-issues=0`.)*

2. **Unit Tests & Coverage (`>= 80%` required)**:
   ```bash
   go test -race -coverprofile=coverage.out -covermode=atomic ./...
   go tool cover -func=coverage.out | tail -n 1
   ```
   Total statement coverage must remain **`>= 80.0%`**.

3. **Manifest, Showcase & Quiet UI Audit**:
   ```bash
   python3 -m json.tool server.json > /dev/null
   python3 scripts/build_github_showcase.py --check
   ```
   Any changes to [`internal/webui`](internal/webui) or static showcase assets must pass the Quiet UI audit against the [`.quiet-ui.md`](.quiet-ui.md) contract (respecting the deprecation blocklist, 4-theme tokens, `0px` horizontal overflow across `390px` / `900px` / `1440px+`, and clean `Chart | Table` / SVG geometry checks).

4. **Pure-Go Build Check**:
   ```bash
   CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -trimpath -tags netgo .
   ```

---

## Coding, Modularity & Documentation Standards

- **Cohesive Module Sizing**: Keep Go and frontend source files **`<= 500` lines** (`<= 650` lines hard ceiling) and functions **`<= 100` lines**. Extract cohesive helper files rather than growing monoliths.
- **No Raw Secrets or Private Network Data**: Never commit credentials, `PASS_HASH` / `PATH_SECRET` / `LAN_MCP_TOKEN` values, personal email addresses, internal hostnames, or private IP addresses in source files, tests, fixtures, or `watchlist.yaml`. Use depersonalized example data or RFC 5737 / `example.internal` placeholders in tests and `?demo=1` fixtures.
- **Keep Workflows in Sync**: Whenever a contribution alters tool behavior, CLI flags, Saved Destinations, cron behavior, or `/web` Operator Studio flows, update [`docs/WORKFLOWS.md`](docs/WORKFLOWS.md) alongside your code changes (and regenerate/verify the showcase if applicable).
- **Formatting & Lints**: Follow `golangci.yaml` (`gofmt`, `gofumpt`, `goimports`, `gocritic`, `gosec`, `revive`, `wrapcheck`, etc.) and keep existing comments and docstrings intact unless your change modifies that behavior.

---

## Pull Request Process

1. Fork or branch from `main` / `develop` with focused, well-scoped commits.
2. Ensure all verification gates (`gofmt`, `go vet`, `golangci-lint`, `go test -race` with `>= 80%` coverage, `CGO_ENABLED=0` build, `server.json` check, showcase check, and Quiet UI audit for UI edits) pass cleanly.
3. Describe the motivation, behavioral changes, and verification results in your pull request description, noting any updates to [`docs/WORKFLOWS.md`](docs/WORKFLOWS.md).

---

## Security Disclosures

See [`SECURITY.md`](SECURITY.md) for the 5-layer security architecture (Passphrase Deadbolt, Two-Doorway transport isolation, anti-CSRF/anti-DNS-rebinding guards, central Target Guard, and unprivileged container execution).

**Do not open public issues for suspected security vulnerabilities.** Report security findings privately through [GitHub Security Advisories](https://github.com/FrankXLT/mcp-adv-netutils/security).
