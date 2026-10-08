# Advanced Network Utilities MCP Server (`mcp-adv-netutils`)

[![Docker Image](https://img.shields.io/badge/docker-ghcr.io%2Ffrankxlt%2Fmcp--adv--netutils-blue?logo=docker)](https://github.com/FrankXLT/mcp-adv-netutils/pkgs/container/mcp-adv-netutils)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`mcp-adv-netutils` is an advanced [Model Context Protocol (MCP)](https://modelcontextprotocol.io/introduction) server engineered for high-fidelity physical network diagnostics, entity reconciliation, and Layer 1–Layer 7 infrastructure monitoring.

Forked from [`patrickdappollonio/mcp-netutils`](https://github.com/patrickdappollonio/mcp-netutils), this enhanced edition introduces embedded IEEE OUI hardware manufacturer resolution, Layer 4 TCP port scanning, hop-by-hop route tracing, concurrent batch reverse DNS, and Wake-on-LAN (WOL) magic packet generation.

---

## Key Features & Architecture

- **Embedded High-Speed IEEE OUI Database**: Over 39,800 IEEE Organizationally Unique Identifiers (OUIs) pre-compiled and embedded directly into the Go binary (`//go:embed`) with gzip compression. Resolves hardware manufacturers in sub-millisecond time without external web API dependencies or rate limits.
- **Virtual / Docker MAC Detection**: Inspects IEEE 802 Locally Administered Address (LAA) bit 1 (`XX:X2:...`, `XX:X6:...`, `XX:XA:...`, `XX:XE:...`, including Docker bridge `02:42:...`) to reliably distinguish physical hardware from virtual interfaces and container bridges.
- **Layer 4 TCP Port Scanning**: Concurrent TCP connect handshakes against well-known ports (SSH, HTTP, HTTPS, RTSP, MQTT, Home Assistant, Portainer, etc.) or custom port ranges to determine active service listeners.
- **Hop-by-Hop Traceroute**: System route tracing measuring hop RTT, packet loss, and automatic reverse PTR lookup per hop.
- **Batch Reverse DNS**: High-concurrency reverse DNS PTR resolution for comma-separated IP address lists.
- **Wake-on-LAN (WOL)**: UDP broadcast delivery of standard 102-byte Magic Packets to wake suspended physical nodes.
- **Comprehensive DNS & HTTP Diagnostics**: Full support for local DNS, DoH (Cloudflare/Google), WHOIS, ICMP ping, HTTP ping with detailed breakdown (`dns`, `conn`, `tls`, `ttfb`, `total`), and TLS certificate chain inspection.
- **Dual Transport (stdio & SSE)**: Runs in standard CLI stdio mode or as an HTTP Server-Sent Events (SSE) server for web integrations and containerized agentic pipelines.

---

## Available MCP Tools (12 Total)

| Tool Name | Scope | Description |
| :--- | :--- | :--- |
| **`mac_vendor_lookup`** | Hardware / L2 | Resolves MAC to IEEE OUI vendor and detects locally administered (LAA/Docker) MACs |
| **`traceroute`** | Routing / L3 | Hop-by-hop route tracing isolating intermediate gateways, latency, and packet loss |
| **`tcp_port_scan`** | Transport / L4 | Concurrent TCP connect handshakes on target ports to verify active service listeners |
| **`dns_reverse_batch`**| Resolution / L7 | Batch-resolves PTR hostnames concurrently for a comma-separated list of IP addresses |
| **`wol_wake`** | Power / L2 | Sends standard 102-byte Wake-on-LAN Magic Packet broadcast frames |
| **`local_dns_query`** | Resolution / L7 | Queries local OS-configured DNS servers (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `PTR`, `TXT`) |
| **`remote_dns_query`**| Resolution / L7 | Performs secure DNS queries via Cloudflare and Google DNS-over-HTTPS |
| **`whois_query`** | Registry / L7 | Performs WHOIS queries to retrieve domain registration metadata |
| **`resolve_hostname`**| Resolution / L7 | Converts hostnames to IPv4, IPv6, or dual-stack addresses |
| **`ping`** | Connectivity / L3 | Performs ICMP ping operations measuring round-trip time and packet loss |
| **`http_ping`** | Application / L7 | Tests HTTP endpoints with microsecond timing breakdowns (`dns`, `conn`, `tls`, `ttfb`) |
| **`tls_certificate_check`** | Security / L7 | Inspects TLS certificate chains, expiry dates, SANs, and issuer authorities |

---

## Tool Usage & Schema Reference

### 1. `mac_vendor_lookup`
Resolves a MAC address to its hardware manufacturer using the embedded IEEE OUI registry and analyzes the IEEE 802 MAC address bit flags.

**Parameters:**
- `mac` (string, required): Hardware MAC address in colon, hyphen, or dot-separated format (e.g., `44:61:32:00:11:22` or `02-42-C0-A8-03-A9`).

**Example Response:**
```json
{
  "mac": "44:61:32:00:11:22",
  "normalized_mac": "44:61:32:00:11:22",
  "oui": "44:61:32",
  "vendor": "ecobee inc",
  "is_locally_administered": false,
  "address_type": "unicast_uaa"
}
```

When checking a Docker bridge or virtual container MAC:
```json
{
  "mac": "02:42:c0:a8:03:a9",
  "normalized_mac": "02:42:c0:a8:03:a9",
  "oui": "02:42:c0",
  "vendor": "Locally Administered / Virtual (Docker / VM)",
  "is_locally_administered": true,
  "address_type": "unicast_laa"
}
```

---

### 2. `traceroute`
Executes hop-by-hop network path tracing to isolate routing issues, latency spikes, and intermediate gateway hops.

**Parameters:**
- `target` (string, required): Destination hostname or IP address (e.g. `example.com` or `192.0.2.1`).
- `max_hops` (integer, optional, default: `30`): Maximum time-to-live / hop count.
- `timeout` (string, optional, default: `"2s"`): Per-probe timeout.

**Example Response:**
```json
{
  "target": "example.com",
  "ip": "93.184.215.14",
  "total_hops": 8,
  "hops": [
    { "hop": 1, "host": "gateway.homelab.local", "ip": "192.0.2.1", "rtt_ms": 0.42 },
    { "hop": 2, "host": "isp-gw.example.net", "ip": "198.51.100.1", "rtt_ms": 4.15 }
  ]
}
```

---

### 3. `tcp_port_scan`
Performs rapid Layer 4 TCP connection handshakes to detect open services and identify listening daemons.

**Parameters:**
- `target` (string, required): Destination hostname or IP address.
- `ports` (string, optional, default: `"common"`): Comma-separated list of ports (`"22,80,443,8000"`) or preset `"common"`.
  - Preset `"common"` tests: `21, 22, 53, 80, 443, 554, 1883, 3000, 5000, 8000, 8080, 8123, 8443, 9000, 9443`.
- `timeout` (string, optional, default: `"1.5s"`): Socket connection timeout per probe.

**Example Response:**
```json
{
  "target": "192.0.2.50",
  "open_ports": [
    { "port": 22, "service": "ssh" },
    { "port": 8123, "service": "homeassistant" }
  ],
  "total_scanned": 15
}
```

---

### 4. `dns_reverse_batch`
Resolves PTR hostnames concurrently across a batch of IP addresses.

**Parameters:**
- `ips` (string, required): Comma-separated list of IPv4/IPv6 addresses (e.g. `"192.0.2.1, 192.0.2.10, 192.0.2.20"`).

**Example Response:**
```json
{
  "results": {
    "192.0.2.1": "gateway.homelab.local",
    "192.0.2.10": "storage-nas.homelab.local",
    "192.0.2.20": "switch-core.homelab.local"
  },
  "unresolved": []
}
```

---

### 5. `wol_wake`
Constructs and broadcasts a 102-byte standard Wake-on-LAN Magic Packet frame (`6x 0xFF` followed by 16 iterations of the target MAC address) over UDP.

**Parameters:**
- `mac` (string, required): Hardware MAC address of the target machine.
- `broadcast_ip` (string, optional, default: `"255.255.255.255"`): Subnet broadcast address (e.g. `"192.0.2.255"`).
- `port` (integer, optional, default: `9`): Destination UDP port (`7` or `9`).

**Example Response:**
```json
{
  "success": true,
  "mac": "bc:24:11:80:a2:14",
  "broadcast": "192.0.2.255:9",
  "bytes_sent": 102
}
```

---

## Deployment & Setup

### Docker Compose / Portainer Deployment

Deploy `mcp-adv-netutils` as a standalone microservice exposing the SSE endpoint on port `8000`:

```yaml
version: '3.8'

services:
  mcp-adv-netutils:
    image: ghcr.io/frankxlt/mcp-adv-netutils:latest
    container_name: mcp-adv-netutils
    restart: unless-stopped
    command: ["-sse", "-sse-port", "8000"]
    ports:
      - "8000:8000"
    networks:
      - internal_net

networks:
  internal_net:
    driver: bridge
```

### Docker CLI Run

Run directly in SSE mode:

```bash
docker run -d \
  --name mcp-adv-netutils \
  -p 8000:8000 \
  ghcr.io/frankxlt/mcp-adv-netutils:latest \
  -sse -sse-port 8000
```

Run in interactive CLI `stdio` mode:

```bash
docker run -i --rm ghcr.io/frankxlt/mcp-adv-netutils:latest
```

### Client Configuration (`claude_desktop_config.json` / Antigravity)

#### Option A: Server-Sent Events (SSE) via Supergateway or Direct HTTP
```json
{
  "mcpServers": {
    "netutils": {
      "url": "http://mcp-adv-netutils.lan:8000/sse"
    }
  }
}
```

#### Option B: Stdio Local Execution
```json
{
  "mcpServers": {
    "netutils": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "ghcr.io/frankxlt/mcp-adv-netutils:latest"
      ]
    }
  }
}
```

---

## Building from Source

Requirements:
- Go 1.22+ installed
- Standard build toolchain (`make`, `git`)

```bash
# Clone the repository
git clone https://github.com/FrankXLT/mcp-adv-netutils.git
cd mcp-adv-netutils

# Build binary
CGO_ENABLED=0 go build -ldflags="-s -w" -o mcp-adv-netutils main.go

# Run locally
./mcp-adv-netutils -sse -sse-port 8000
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
