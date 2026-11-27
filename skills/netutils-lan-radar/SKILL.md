---
name: netutils-lan-radar
description: Discover LAN hosts, correlate ARP/mDNS/SSDP/PTR/SNMP switch ports, separate physical UAA hardware from LAA Docker/VM MACs, diff snapshots, and verify Wake-on-LAN with recipe_wake_verify.
---

# `netutils-lan-radar`

Operational playbook for Layer 2/Layer 3 LAN inventory, physical-vs-virtual device classification, change detection, and Wake-on-LAN verification.

## Core Tools

| Tool | Scope | Purpose |
| :--- | :--- | :--- |
| `recipe_lan_radar` | Composite L2/L3/L7 | Full LAN discovery sweep with vendor, PTR, and UAA/LAA grouping |
| `arp_neighbor_sweep` | L2 Neighbor Table | Scans active subnet / kernel ARP cache for IP-to-MAC bindings |
| `mdns_ssdp_discover` | L7 Multicast | Discovers mDNS (`_services._dns-sd`) and SSDP/UPnP announcements |
| `dns_reverse_batch` | L7 Resolution | Concurrent reverse PTR lookup for discovered IP lists |
| `snmp_switch_port` | L2 Switch Fabric | Correlates MAC addresses to switch ports, VLANs, and LLDP neighbors |
| `recipe_diff_snapshot` | Drift Detection | Compares current LAN inventory against a saved baseline snapshot |
| `recipe_wake_verify` | Power + Readiness | Sends WOL magic packet and polls ARP/ICMP/TCP until host is online |
| `manage_saved_destinations` | Persistent Bookmarks | Saves discovered hosts (`mac`, `category`, `pinned`) for 1-click Wake & monitoring |

## Standard LAN Sweep Workflow

1. **Full Sweep**: Run `recipe_lan_radar` (with `style: "default"` or `"quick"` for mobile) to aggregate `arp_neighbor_sweep`, OUI vendor lookup, `dns_reverse_batch`, and optional `mdns_ssdp_discover` / `snmp_switch_port`.
2. **Physical Port Mapping**: When a rogue or misbehaving device is found, call `snmp_switch_port` to locate the exact physical switch interface and upstream LLDP link.
3. **`/web` Local Network Quick Actions**: In the `/web` Studio **Local Network** tab, each row in the **Physical Hardware** (`UAA`) and **Containers & VMs** (`LAA`) tables exposes 1-click **`Ping`**, **`Ports`**, **`Wake`**, and **`Save`** actions—letting operators probe ports, send WOL frames, or bookmark a discovered device directly into Saved Destinations with its Wake MAC address prefilled.

## Physical (`UAA`) vs Virtual (`LAA`) Grouping

`mcp-adv-netutils` inspects IEEE 802 MAC bit 1 (Locally Administered Address bit) to separate physical hardware from containers and virtual interfaces:

- **UAA (Universally Administered Address — Physical Hardware)**:
  - Bit 1 of the first octet is `0` (second hex nibble is `0, 1, 4, 5, 8, 9, C, D`).
  - Matched against the embedded IEEE OUI registry (e.g., Synology, Ubiquiti, Apple, Intel, Realtek).
- **LAA (Locally Administered Address — Virtual / Docker / VM)**:
  - Bit 1 of the first octet is `1` (second hex nibble is `2, 3, 6, 7, A, B, E, F`).
  - Explicitly flags Docker bridge/veth MACs (`02:42:...`) and randomized/hypervisor MACs so container churn never pollutes physical hardware alerts.

## Before / After Snapshot Diffing (`recipe_diff_snapshot`)

Use `recipe_diff_snapshot` before maintenance windows, firmware upgrades, or security audits:

1. Capture or reference a `baseline` snapshot.
2. Re-run `recipe_diff_snapshot` after the change or on a nightly schedule.
3. Inspect the 3 delta markers:
   - `[+] ADDED`: New IP/MAC appeared on the LAN (verify if expected new host vs unauthorized device).
   - `[-] REMOVED`: Previously present host is offline or moved.
   - `[~] CHANGED`: Same IP with a new MAC (DHCP lease handoff / NIC swap / ARP conflict) or same MAC with a new IP/hostname/port.

## Wake-on-LAN + Verification (`recipe_wake_verify`)

Never assume `wol_wake` succeeded just because UDP broadcast bytes left the socket. Use `recipe_wake_verify`:

1. Targets the physical **UAA** MAC address (never an LAA/Docker MAC)—either passed directly, chosen from **Saved Destinations** Wake MAC chips in `/web`, or triggered via the **Local Network** row **`Wake`** action.
2. Sends the 102-byte Magic Packet (`6x 0xFF` + `16x MAC`) on the subnet broadcast IP.
3. Polls L2 ARP, L3 ICMP/TCP fallback, and optional service port until the node reports ready or times out.
