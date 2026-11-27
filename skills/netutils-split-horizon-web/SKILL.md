---
name: netutils-split-horizon-web
description: Diagnose split-horizon DNS, internal vs external HTTP/TLS endpoints, host cards, Thirty-Minute Passphrase Deadbolt (unlock_netutils/lock_netutils), and /web Studio workflows.
---

# `netutils-split-horizon-web`

Operational playbook for verifying split-horizon DNS resolution, comparing internal vs edge HTTP/TLS paths, inspecting host cards, and operating deadbolt-gated diagnostics and `/web` Studio.

## Core Tools

| Tool | Purpose |
| :--- | :--- |
| `recipe_diff_dns` | Compares local OS/LAN DNS resolution against external DoH resolvers |
| `split_dns_audit` | Audits record parity (`A`/`AAAA`/`CNAME`), TTLs, and split-horizon drift |
| `recipe_diff_http` | Compares internal/direct HTTP path vs external/reverse-proxy edge path |
| `tls_certificate_check` | Inspects TLS leaf + intermediate chain, expiry countdown, SANs, and issuer |
| `http_ping` | Measures granular latency breakdown (`dns`, `conn`, `tls`, `ttfb`, `total`) |
| `recipe_host_card` | Builds a unified L2–L7 diagnostic card for a single host or service |
| `unlock_netutils` | Unlocks the Thirty-Minute Passphrase Deadbolt for gated operations |
| `lock_netutils` | Immediately re-locks the Thirty-Minute Passphrase Deadbolt |

## Split-Horizon DNS & Web Triage Workflow

### 1. DNS Parity (`recipe_diff_dns` & `split_dns_audit`)
- Run `recipe_diff_dns` when a hostname works on LAN but fails externally (or routes via hairpin NAT instead of local RFC1918 IP).
- Expected split-horizon result:
  - **Local resolver**: Private LAN / reverse-proxy IP (RFC1918) with clean PTR alignment.
  - **External DoH**: Public WAN / edge IP.
- Run `split_dns_audit` across critical service FQDNs to catch stale internal overrides, unexpected `NXDOMAIN`, or missing `AAAA` records causing Happy Eyeballs stalls.

### 2. HTTP & TLS Comparison (`recipe_diff_http`, `http_ping`, `tls_certificate_check`)
- Run `recipe_diff_http` to compare direct LAN backend behavior vs public HTTPS ingress:
  - Pinpoints whether slowness is inside `dns`, `conn` (TCP), `tls` (handshake/OCSP), or `ttfb` (upstream app processing).
  - Surfaces status mismatches (e.g., `200 OK` internally vs `502 Bad Gateway` / `403` at reverse proxy).
- Run `tls_certificate_check` to catch expiring ACME/Let's Encrypt certs, missing SAN entries, or mismatched internal vs edge leaf certificates.

### 3. Single-Host Summary (`recipe_host_card`)
- Call `recipe_host_card` for an end-to-end snapshot of a single server or appliance (DNS resolution, ping/TCP status, open service ports, TLS summary, and MAC/OUI if on LAN).

## Thirty-Minute Passphrase Deadbolt (`unlock_netutils` / `lock_netutils`)

Sensitive or active-mutation operations (e.g., deadbolt-gated scans, watchlist edits, Saved Destination mutations, or privileged actions when `PASS_HASH` is configured) require an active unlock window:

1. **Unlock**: Call `unlock_netutils` with the operator passphrase (or unlock via the `/web` Pre-Unlock Gate). Input is **voice-normalized** (trimmed, case/punctuation/whitespace normalized for spoken dictation compatibility) and verified via SHA-256 + `crypto/subtle.ConstantTimeCompare` against `PASS_HASH`.
2. **Window & Locked Behavior**: Once verified, the deadbolt stays open for **30 minutes** (`TTL = 30m`, sliding window) before automatically re-locking. While locked, `/web` displays the lock gate (with 1-tap access to `?demo=1` offline fixtures) and optional redacted aggregate cron status.
3. **Manual Lock**: Call `lock_netutils` immediately after completing sensitive operations—never leave the deadbolt open unnecessarily.

## `/web` Network Studio Usage (Apache ECharts SVG)

- `/web` serves the built-in 4-theme Quiet UI **Network Studio** (`Pure White`, `Warm Paper`, `Dark`, `Dark Paper`) with **Apache ECharts SVG** visualizations for path latency whiskers, HTTP timing waterfalls, DNS resolver comparisons, and `24h`/`7d`/`30d` uptime timelines.
- **Interactive Inspection & Export**: Switch between **Chart** and **Table** views, export results via **Copy Summary** or **Copy Data** (TSV), pin targets to the **Pinned Destinations** bar (**Scan Pinned**), and open any 30-day entry in the **Past Run Drawer** to **Run Again & Compare** side-by-side.
- **CSRF & DNS-Rebinding Protection**: All `/web/api/*` endpoints enforce strict `Origin` and `Host` header validation. Access `/web` using the configured LAN/server hostname rather than mismatched or proxied `Host` headers.
