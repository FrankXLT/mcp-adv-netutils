# Security Architecture (`mcp-adv-netutils`)

`mcp-adv-netutils` operates directly on local networks, ARP tables, sockets, and diagnostic endpoints. To prevent unauthorized lateral movement, SSRF, CSRF, DNS rebinding, and privilege escalation, the server enforces a **5-Layer Security Model**.

---

## Layer 1: Thirty-Minute Passphrase Deadbolt (`PASS_HASH`)

Sensitive and state-mutating operations (such as deadbolt-gated diagnostics, watchlist mutations, and future Wave 4 capture controls) are locked behind a time-bounded deadbolt:

- **Configuration**: Set `PASS_HASH` to the SHA-256 hex digest of your passphrase (never store the plaintext passphrase in repos, compose files, or images).
- **Voice-Normalized Verification**: Input passed to `unlock_netutils` undergoes deterministic voice normalization (trimming, lowercasing, collapsing whitespace, and stripping dictation punctuation) before SHA-256 hashing so spoken/mobile voice inputs work reliably without weakening entropy.
- **Constant-Time Comparison**: Digests are compared exclusively with `crypto/subtle.ConstantTimeCompare` to eliminate timing side-channels.
- **30-Minute Auto-Relock**: Successful verification opens the deadbolt for `30m`, after which it locks automatically; `lock_netutils` closes it immediately on demand.

---

## Layer 2: Two-Doorway Setup (Remote vs. LAN-Only)

HTTP/MCP transports are segmented into two distinct authentication and network-origin doorways:

1. **Remote Doorway (`/{PATH_SECRET}/mcp`)**:
   - Designed for authenticated remote/reverse-proxy access where requests carry an unguessable, high-entropy `PATH_SECRET` prefix.
2. **LAN-Only Doorway (`/lan/{LAN_MCP_TOKEN}/mcp` and `/sse`)**:
   - Protected by `LAN_MCP_TOKEN` and strict source validation.
   - **Proxy Header Rejection**: Rejects requests carrying forwarding headers (`X-Forwarded-For`, `X-Real-IP`, `Forwarded`) so an upstream reverse proxy cannot accidentally expose the LAN doorway to the public internet.
   - **RFC1918 Source Enforcement**: Rejects any direct peer IP outside RFC1918/loopback local ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `::1`).

---

## Layer 3: `/web/api/*` Anti-CSRF & Anti-DNS-Rebinding Guards

All browser-facing `/web/api/*` endpoints used by `/web` Studio enforce strict browser boundary checks:

- **`Origin` Validation**: State-changing and API requests must present a matching `Origin` (or same-origin fetch metadata) consistent with the server's active listener/host. Cross-origin browser requests are rejected (`403 Forbidden`).
- **`Host` Header Validation**: Validates the HTTP `Host` header against an explicit allowlist / expected local hostnames to block **DNS rebinding** attacks from external malicious pages targeting `localhost` or `.lan` addresses.

---

## Layer 4: Central Target Guard & CLI `--` Injection Prevention

Every network probe, scan, DNS query, and HTTP check passes through centralized target validation before any socket or subprocess is invoked:

- **CIDR Policy (`--allow-cidrs` / `--deny-cidrs`)**: Operators can restrict probing to explicit subnets via `--allow-cidrs` and block sensitive ranges via `--deny-cidrs`.
- **Mandatory Cloud Metadata Block**: Link-local metadata space **`169.254.0.0/16`** (AWS/GCP/Azure/cloud-init IMDS) is **always blocked unconditionally**—even if not listed in `--deny-cidrs`—preventing SSRF against instance metadata endpoints.
- **DNS-Resolved IP Checking**: Hostname targets are resolved and every returned IP is checked against the CIDR guard prior to connection.
- **CLI `--` Injection Prevention**: Whenever external network binaries (e.g., `traceroute`, `ping`) are executed, user-supplied targets are validated as strict IPs/hostnames (rejecting leading `-` flags) and separated from command flags with an explicit `--` end-of-options delimiter, without invoking a shell (`sh -c`).

---

## Layer 5: Unprivileged Container & Minimal Capabilities

Runtime containers follow least-privilege hardening:

- **Unprivileged User (`USER netutils`)**: The container drops `root` and runs as the dedicated non-root `netutils` service user.
- **Minimal Linux Capabilities (`cap_net_raw+ep`)**: Only `cap_net_raw+ep` is granted to the Go binary for raw ICMP/ARP probing (`ping`, `mtu_path_probe`, `arp_neighbor_sweep`). No `CAP_SYS_ADMIN`, `CAP_NET_ADMIN` (unless explicitly required), or `Privileged: true` is used.
- **Zero Plaintext Secrets in Repos or Images**: `PASS_HASH`, `PATH_SECRET`, and `LAN_MCP_TOKEN` are injected solely at runtime via environment/secret mounts—never baked into Dockerfiles, `watchlist.yaml`, or git history.
