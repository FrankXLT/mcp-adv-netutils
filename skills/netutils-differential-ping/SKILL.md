---
name: netutils-differential-ping
description: Triage network outages, packet loss, and MTU black holes using recipe_diff_ping, recipe_path_autopsy, mtu_path_probe, and mtr_path_quality, including icmp vs tcp_fallback interpretation.
---

# `netutils-differential-ping`

Operational playbook for isolating *where* a network outage or latency spike originates across local hardware, LAN gateway, VPN/WAN uplink, and remote target.

## Core Tools

| Tool | Purpose |
| :--- | :--- |
| `recipe_diff_ping` | 4-stage differential reachability ladder + TCP RST/SYN-ACK + ARP check |
| `recipe_path_autopsy` | Combined hop-by-hop quality, route trace, and MTU path diagnosis |
| `mtu_path_probe` | DF-bit path MTU discovery across `1500`, `1492`, `1420`, and `1280` bytes |
| `mtr_path_quality` | Multi-sample per-hop loss, RTT (`min`/`avg`/`max`), and jitter analysis |

## Outage Triage Ladder (`recipe_diff_ping`)

Run `recipe_diff_ping` first on any "host unreachable" or "internet is slow" report. It evaluates 4 deterministic stages plus L2/L4 corroboration:

```text
[1] Local Adapter -> [2] LAN Gateway -> [3] WireGuard/WAN Peer -> [4] Public DNS + Target
```

Plus side-checks:
- **ARP Neighbor Check**: Verifies L2 MAC resolution for the gateway and local targets (`REACHABLE` / `STALE` / `FAILED`).
- **TCP RST / SYN-ACK Probe**: Tests L4 reachability when ICMP Echo is filtered.

### Fault Isolation Matrix

| Failing Stage | Likely Root Cause | Next Action |
| :--- | :--- | :--- |
| **[1] Local Adapter** | Container/host interface down, missing route, or namespace isolation | Inspect local link/routes; verify `cap_net_raw` or socket permissions |
| **[2] LAN Gateway** | Switch link flap, bad cable, VLAN mismatch, or ARP failure | Check ARP state; run `recipe_lan_radar` / `snmp_switch_port` |
| **[3] WireGuard/WAN Peer** | Tunnel handshake expired, ISP modem drop, or tunnel MTU mismatch | Run `mtu_path_probe` (`1420` vs `1500`) and `mtr_path_quality` |
| **[4] Public DNS OK, Target FAIL** | Remote host down, firewall drop, or target-specific port block | Compare ICMP vs TCP SYN-ACK/RST; run `recipe_path_autopsy` |
| **[4] Public DNS FAIL & Target FAIL** | Upstream ISP transit outage or DNS/egress blockage | Run `mtr_path_quality` toward reference host (`1.1.1.1`) to locate hop drop |

## Interpreting `probe_mode` (`icmp` vs `tcp_fallback`)

- **`probe_mode: "icmp"`**: Native ICMP Echo Request/Reply succeeded. RTT reflects L3 network latency without TCP handshake overhead.
- **`probe_mode: "tcp_fallback"`**: ICMP was blocked, rate-limited, or unavailable (`cap_net_raw` absent or host/WAN firewall drops Echo). The probe fell back to TCP connect timing (`SYN` -> `SYN-ACK` or `RST`):
  - `SYN-ACK` proves host + service port are alive.
  - `RST` proves the host L3/L4 stack is reachable even though the specific port is closed.
  - Timeout across both `icmp` and `tcp_fallback` indicates a silent firewall drop, dead host, or upstream routing black hole.

## MTU Black-Hole Triage (`mtu_path_probe`)

Run `mtu_path_probe` whenever small pings succeed (`64B`) but TLS handshakes, SSH sessions, or large HTTP responses stall:

- **`1500`**: Standard Ethernet / unencapsulated LAN + clean WAN path.
- **`1492`**: PPPoE WAN framing overhead (`8` bytes).
- **`1420`**: WireGuard / IPv4 tunnel overhead (`80` bytes).
- **`1280`**: Minimum IPv6 / conservative VPN fallback.

If `1500` fails with DF set while `1420` or `1280` passes, Path MTU Discovery (PMTUD) / ICMP "Fragmentation Needed" is being blocked along a tunnel or WAN edge.

## Deep Path Diagnosis (`recipe_path_autopsy` & `mtr_path_quality`)

1. Run `mtr_path_quality` to distinguish **intermediate router ICMP rate-limiting** (loss at hop `N` that disappears at hop `N+1..dst`) from **true transit loss** (loss starting at hop `N` and persisting through the destination).
2. Run `recipe_path_autopsy` when you need a single consolidated report combining differential stages, hop loss/jitter, and MTU ceiling—use `style: "quick"` (`<= 40` cols) for mobile or `style: "rich"` (`76` cols) for desktop review.
