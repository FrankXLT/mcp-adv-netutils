package server

import (
	"slices"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/miekg/dns"
)

func getDNSRecordTypes() []string {
	recordTypes := make([]string, 0, len(dns.StringToType))
	for recordType := range dns.StringToType {
		recordTypes = append(recordTypes, recordType)
	}
	slices.Sort(recordTypes)
	return recordTypes
}

func newTool(name, description string, opts ...mcp.ToolOption) mcp.Tool {
	all := make([]mcp.ToolOption, 0, len(opts)+2)
	all = append(all, mcp.WithDescription(description))
	all = append(all, opts...)
	all = append(all, mcp.WithString("style",
		mcp.Description("Output render style (default, quick, rich, or json); defaults to default"),
		mcp.Enum("default", "quick", "rich", "json"),
		mcp.DefaultString("default"),
	))
	return mcp.NewTool(name, all...)
}

func newDNSQueryTool(name, description string, recordTypes []string) mcp.Tool {
	return newTool(name, description,
		mcp.WithString("domain", mcp.Required(), mcp.Description("The domain name to query (e.g., example.com)")),
		mcp.WithString("record_type",
			mcp.Description("The type of DNS record to query (supports all standard DNS record types); defaults to A"),
			mcp.Enum(recordTypes...),
			mcp.DefaultString("A"),
		),
	)
}

func buildAllToolSpecs() []mcp.Tool {
	dnsRecordTypes := getDNSRecordTypes()
	specs := make([]mcp.Tool, 0, 33)
	specs = append(specs, buildCoreNameAndInfoTools(dnsRecordTypes)...)
	specs = append(specs, buildCoreConnectivityTools()...)
	specs = append(specs, buildActiveProbeTools()...)
	specs = append(specs, buildDiffRecipeTools()...)
	specs = append(specs, buildStackRecipeTools()...)
	specs = append(specs, buildAdminAndDeadboltTools()...)
	return specs
}

func buildCoreNameAndInfoTools(recordTypes []string) []mcp.Tool {
	return []mcp.Tool{
		newDNSQueryTool("local_dns_query", "Perform DNS queries using local OS-defined DNS servers", recordTypes),
		newDNSQueryTool("remote_dns_query", "Perform DNS queries using remote DNS-over-HTTPS servers (Google and Cloudflare)", recordTypes),
		newTool("whois_query", "Perform WHOIS lookups to get domain registration information",
			mcp.WithString("domain", mcp.Required(), mcp.Description("The domain name to query (e.g., example.com)")),
		),
		newTool("resolve_hostname", "Convert a hostname to its corresponding IP addresses",
			mcp.WithString("hostname", mcp.Required(), mcp.Description("The hostname to resolve (e.g., example.com)")),
			mcp.WithString("ip_version",
				mcp.Description("IP version to resolve (ipv4, ipv6, or both); defaults to ipv4"),
				mcp.Enum("ipv4", "ipv6", "both"),
				mcp.DefaultString("ipv4"),
			),
		),
		newTool("mac_vendor_lookup", "Perform an IEEE OUI vendor lookup and detect locally administered (LAA / virtual / Docker) MAC addresses",
			mcp.WithString("mac", mcp.Required(), mcp.Description("The MAC address to lookup (e.g. 9C:8E:CD:0A:91:0C, 44-61-32-11-22-33, or raw hex)")),
		),
		newTool("dns_reverse_batch", "Batch-resolve PTR reverse DNS hostnames concurrently for a comma-separated list of IP addresses",
			mcp.WithString("ips", mcp.Required(), mcp.Description("Comma-separated list of IP addresses to resolve (e.g. '192.168.1.1, 192.168.1.105')")),
			mcp.WithNumber("timeout_ms", mcp.Description("Timeout per lookup in milliseconds; defaults to 3000"), mcp.DefaultNumber(3000)),
		),
	}
}

func buildCoreConnectivityTools() []mcp.Tool {
	return []mcp.Tool{
		newTool("ping", "Perform ping operations to test connectivity and measure response times to a host",
			mcp.WithString("target", mcp.Required(), mcp.Description("The hostname or IP address to ping (e.g., example.com or 8.8.8.8)")),
			mcp.WithNumber("count", mcp.Description("Number of ping packets to send; defaults to 4"), mcp.DefaultNumber(4)),
		),
		newTool("tls_certificate_check", "Check TLS certificate chain for a domain to analyze certificate validity, expiration, and chain structure",
			mcp.WithString("domain", mcp.Required(), mcp.Description("The domain name to check TLS certificate for (e.g., example.com)")),
			mcp.WithNumber("port", mcp.Description("Port to connect to for TLS check; defaults to 443"), mcp.DefaultNumber(443)),
			mcp.WithBoolean("include_chain", mcp.Description("Whether to include the full certificate chain in the response; defaults to true")),
			mcp.WithBoolean("check_expiry", mcp.Description("Whether to check certificate expiration and provide warnings; defaults to true")),
			mcp.WithString("server_name", mcp.Description("Server name for SNI (Server Name Indication); defaults to the domain name")),
		),
		newTool("http_ping", "Perform HTTP ping operations to test connectivity and measure response times to HTTP endpoints",
			mcp.WithString("url", mcp.Required(), mcp.Description("The URL to ping (e.g., https://api.example.com/users)")),
			mcp.WithString("method",
				mcp.Description("HTTP method to use; defaults to GET"),
				mcp.Enum("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"),
				mcp.DefaultString("GET"),
			),
			mcp.WithNumber("count", mcp.Description("Number of HTTP requests to send; defaults to 1"), mcp.DefaultNumber(1)),
		),
		newTool("traceroute", "Execute hop-by-hop route tracing to isolate intermediate gateways, network latency, and packet loss",
			mcp.WithString("target", mcp.Required(), mcp.Description("Destination IPv4, IPv6, or hostname (e.g. 1.1.1.1 or example.com)")),
			mcp.WithNumber("max_hops", mcp.Description("Maximum number of hops (TTL ceiling, 1-30); defaults to 15"), mcp.DefaultNumber(15)),
			mcp.WithNumber("timeout_seconds", mcp.Description("Probe timeout per hop in seconds; defaults to 2"), mcp.DefaultNumber(2)),
		),
		newTool("tcp_port_scan", "Perform fast Layer 4 TCP connect handshakes on target ports to verify active service listeners",
			mcp.WithString("target", mcp.Required(), mcp.Description("The target hostname or IP address (e.g. 192.168.1.1 or example.com)")),
			mcp.WithString("ports", mcp.Description("Comma-separated ports, range, or preset ('common'); defaults to common"), mcp.DefaultString("common")),
			mcp.WithNumber("timeout_ms", mcp.Description("Timeout per port in milliseconds; defaults to 1000"), mcp.DefaultNumber(1000)),
		),
		newTool("wol_wake", "Send a Wake-on-LAN Magic Packet broadcast frame to wake a physical machine or server",
			mcp.WithString("mac", mcp.Required(), mcp.Description("Target machine MAC address to wake (e.g. 00:11:32:XX:YY:ZZ)")),
			mcp.WithString("broadcast_ip", mcp.Description("Broadcast destination IP; defaults to 255.255.255.255"), mcp.DefaultString("255.255.255.255")),
			mcp.WithNumber("port", mcp.Description("Target UDP port; defaults to 9"), mcp.DefaultNumber(9)),
		),
	}
}

func buildActiveProbeTools() []mcp.Tool {
	return []mcp.Tool{
		newTool("arp_neighbor_sweep", "Inspect OS neighbor/ARP table and optionally execute bounded active ARP sweeps on a LAN CIDR",
			mcp.WithString("cidr", mcp.Description("Target LAN IPv4 CIDR to sweep (e.g. 192.168.1.0/24)")),
			mcp.WithString("interface", mcp.Description("Optional network interface name (e.g. eth0)")),
			mcp.WithBoolean("active_probe", mcp.Description("Send bounded active ARP requests across CIDR")),
			mcp.WithBoolean("resolve_ptr", mcp.Description("Resolve PTR reverse DNS hostnames for discovered neighbors")),
			mcp.WithNumber("timeout_ms", mcp.Description("Timeout for active ARP sweep in milliseconds")),
		),
		newTool("mtu_path_probe", "Discover path MTU and WireGuard-safe MTU along a route via binary-search DF probes",
			mcp.WithString("target", mcp.Required(), mcp.Description("Target hostname or IP address")),
			mcp.WithNumber("min_mtu", mcp.Description("Minimum MTU bound; defaults to 576"), mcp.DefaultNumber(576)),
			mcp.WithNumber("max_mtu", mcp.Description("Maximum MTU bound; defaults to 1500"), mcp.DefaultNumber(1500)),
			mcp.WithString("protocol", mcp.Description("Probe protocol (udp or icmp); defaults to udp"), mcp.Enum("udp", "icmp"), mcp.DefaultString("udp")),
		),
		newTool("mtr_path_quality", "Run multi-cycle MTR path quality measurements to quantify per-hop packet loss and jitter",
			mcp.WithString("target", mcp.Required(), mcp.Description("Target hostname or IP address")),
			mcp.WithNumber("max_hops", mcp.Description("Maximum number of hops")),
			mcp.WithNumber("cycles", mcp.Description("Number of probe cycles per hop")),
			mcp.WithNumber("timeout_ms", mcp.Description("Probe timeout per hop in milliseconds")),
		),
		newTool("mdns_ssdp_discover", "Discover local mDNS/Bonjour and SSDP/UPnP services advertised on the LAN",
			mcp.WithString("protocol", mcp.Description("Discovery protocol (both, mdns, or ssdp); defaults to both"), mcp.Enum("both", "mdns", "ssdp"), mcp.DefaultString("both")),
			mcp.WithString("service", mcp.Description("Optional mDNS service type or SSDP search target")),
			mcp.WithNumber("timeout_ms", mcp.Description("Discovery timeout in milliseconds; defaults to 2000"), mcp.DefaultNumber(2000)),
			mcp.WithNumber("max_results", mcp.Description("Maximum services to return; defaults to 100"), mcp.DefaultNumber(100)),
		),
		newTool("split_dns_audit", "Compare local DNS resolver responses against remote DNS-over-HTTPS to detect split-horizon DNS",
			mcp.WithString("domain", mcp.Required(), mcp.Description("Domain name to audit")),
			mcp.WithArray("record_types", mcp.WithStringItems(), mcp.Description("DNS record types to compare (e.g. ['A','AAAA','TXT'])")),
		),
		newTool("snmp_switch_port", "Query read-only SNMP IF-MIB, Bridge-MIB FDB, and LLDP-MIB switch/device port tables",
			mcp.WithString("target", mcp.Required(), mcp.Description("Target switch or SNMP agent IP/hostname")),
			mcp.WithNumber("port", mcp.Description("SNMP UDP port; defaults to 161"), mcp.DefaultNumber(161)),
			mcp.WithString("version", mcp.Description("SNMP version (2c or 3); defaults to 2c"), mcp.Enum("2c", "3"), mcp.DefaultString("2c")),
			mcp.WithString("community", mcp.Description("SNMPv2c read community string")),
			mcp.WithString("username", mcp.Description("SNMPv3 USM username")),
			mcp.WithString("auth_proto", mcp.Description("SNMPv3 auth protocol (MD5, SHA, SHA256, SHA512)")),
			mcp.WithString("auth_pass", mcp.Description("SNMPv3 auth passphrase")),
			mcp.WithString("priv_proto", mcp.Description("SNMPv3 privacy protocol (DES, AES, AES192, AES256)")),
			mcp.WithString("priv_pass", mcp.Description("SNMPv3 privacy passphrase")),
			mcp.WithString("mode", mcp.Description("SNMP query mode; defaults to summary"), mcp.Enum("summary", "interfaces", "fdb", "lldp", "all"), mcp.DefaultString("summary")),
			mcp.WithNumber("max_entries", mcp.Description("Maximum table rows per MIB; defaults to 128"), mcp.DefaultNumber(128)),
		),
	}
}

func buildDiffRecipeTools() []mcp.Tool {
	return []mcp.Tool{
		newTool("recipe_diff_ping", "Run a multi-stage comparative reachability ladder across gateway, WireGuard peer, target, and canary",
			mcp.WithString("target", mcp.Required(), mcp.Description("Primary target host or IP to diagnose")),
			mcp.WithString("gateway", mcp.Description("Optional gateway IP override")),
			mcp.WithString("wireguard_peer", mcp.Description("Optional WireGuard peer IP")),
			mcp.WithString("canary", mcp.Description("Optional external canary host/IP")),
			mcp.WithNumber("count", mcp.Description("Ping count per stage")),
		),
		newTool("recipe_diff_dns", "Compare local DNS, remote DoH, and OS resolver behavior for a domain",
			mcp.WithString("domain", mcp.Required(), mcp.Description("Domain name to diagnose")),
			mcp.WithArray("record_types", mcp.WithStringItems(), mcp.Description("DNS record types to audit")),
		),
		newTool("recipe_diff_http", "Compare HTTP timing breakdown and TLS certificate health side-by-side across URLs",
			mcp.WithString("url", mcp.Required(), mcp.Description("Primary URL to probe")),
			mcp.WithArray("compare_urls", mcp.WithStringItems(), mcp.Description("Additional URLs to compare side-by-side")),
			mcp.WithString("method", mcp.Description("HTTP method to use; defaults to GET"), mcp.DefaultString("GET")),
			mcp.WithNumber("count", mcp.Description("Number of HTTP requests per endpoint")),
		),
		newTool("recipe_diff_snapshot", "Diff current LAN ARP neighbors against a stored baseline snapshot and optionally save a new baseline",
			mcp.WithString("baseline", mcp.Required(), mcp.Description("Baseline snapshot name")),
			mcp.WithString("cidr", mcp.Description("Optional LAN CIDR to sweep")),
			mcp.WithString("save_as", mcp.Description("Optional snapshot name to persist current results")),
		),
	}
}

func buildStackRecipeTools() []mcp.Tool {
	return []mcp.Tool{
		newTool("recipe_host_card", "Collect an L2-L7 diagnostic dossier card for a single host (DNS, ARP, ping, ports, TLS, HTTP, optional SNMP)",
			mcp.WithString("target", mcp.Required(), mcp.Description("Target hostname or IP address")),
			mcp.WithString("port_preset", mcp.Description("Port scan preset or comma-separated port list")),
			mcp.WithBoolean("check_snmp", mcp.Description("Whether to include read-only SNMP port inspection")),
			mcp.WithObject("snmp_params", mcp.Description("Optional SNMP parameter overrides")),
		),
		newTool("recipe_lan_radar", "Discover LAN hosts separated into physical UAA vs virtual LAA groups plus optional mDNS/SSDP services",
			mcp.WithString("cidr", mcp.Description("Optional LAN CIDR to sweep")),
			mcp.WithBoolean("active_arp", mcp.Description("Send bounded active ARP requests")),
			mcp.WithBoolean("resolve_ptr", mcp.Description("Resolve PTR hostnames for discovered IPs")),
			mcp.WithBoolean("discover_services", mcp.Description("Include mDNS/SSDP service discovery")),
		),
		newTool("recipe_path_autopsy", "Run end-to-end path diagnosis combining DNS, ping, path MTU discovery, MTR quality, and traceroute",
			mcp.WithString("target", mcp.Required(), mcp.Description("Target hostname or IP address")),
			mcp.WithNumber("max_hops", mcp.Description("Maximum hop count")),
			mcp.WithNumber("cycles", mcp.Description("MTR probe cycles")),
		),
		newTool("recipe_wake_verify", "Send a Wake-on-LAN Magic Packet and poll target readiness via ping and TCP ports",
			mcp.WithString("mac", mcp.Required(), mcp.Description("Target machine MAC address to wake")),
			mcp.WithString("target", mcp.Required(), mcp.Description("Target IP or hostname to poll for readiness")),
			mcp.WithString("broadcast_ip", mcp.Description("Broadcast destination IP; defaults to 255.255.255.255"), mcp.DefaultString("255.255.255.255")),
			mcp.WithNumber("port", mcp.Description("Wake-on-LAN UDP port; defaults to 9"), mcp.DefaultNumber(9)),
			mcp.WithNumber("wait_seconds", mcp.Description("Maximum readiness wait seconds; defaults to 15"), mcp.DefaultNumber(15)),
			mcp.WithString("ports", mcp.Description("Optional TCP ports to verify readiness")),
		),
		newTool("render_run_digest", "Render a consolidated severity-sorted digest card across stored diagnostic jobs",
			mcp.WithArray("job_ids", mcp.WithStringItems(), mcp.Description("Optional explicit list of job IDs to summarize")),
			mcp.WithNumber("limit", mcp.Description("Maximum recent jobs to include when job_ids is omitted")),
		),
	}
}

func buildAdminAndDeadboltTools() []mcp.Tool {
	return []mcp.Tool{
		newTool("get_cron_status", "Retrieve scheduled cron watchlist status and historical 24h/7d/30d health rollups",
			mcp.WithString("period",
				mcp.Description("Aggregation period (24h, 7d, or 30d); defaults to 30d"),
				mcp.Enum("24h", "7d", "30d"),
				mcp.DefaultString("30d"),
			),
		),
		newTool("manage_cron_watchlist", "Inspect or mutate scheduled cron watchlist entries (list, add, update, remove, pause, resume, run_now)",
			mcp.WithString("action",
				mcp.Required(),
				mcp.Description("Watchlist action to perform"),
				mcp.Enum("list", "add", "update", "remove", "pause", "resume", "run_now"),
			),
			mcp.WithString("key", mcp.Description("Unique watchlist entry key")),
			mcp.WithString("schedule", mcp.Description("Cron expression or @every duration")),
			mcp.WithString("tool", mcp.Description("Canonical tool name to schedule")),
			mcp.WithString("target", mcp.Description("Target host, domain, URL, or CIDR")),
			mcp.WithObject("args", mcp.Description("Optional tool argument map")),
			mcp.WithBoolean("enabled", mcp.Description("Whether the watchlist entry is enabled")),
			mcp.WithNumber("timeout_seconds", mcp.Description("Execution timeout in seconds")),
		),
		newTool("manage_saved_destinations", "List, save, delete, or run persisted saved destinations with optional cron monitoring sync",
			mcp.WithString("action",
				mcp.Required(),
				mcp.Description("Destination action to perform (list, save, delete, or run)"),
				mcp.Enum("list", "save", "delete", "run"),
			),
			mcp.WithString("id", mcp.Description("Saved destination ID (required for delete; optional for save update or run)")),
			mcp.WithString("name", mcp.Description("Human-friendly destination name (required for save; usable as lookup in run)")),
			mcp.WithString("target", mcp.Description("Target host, IP, URL, or CIDR (required for save)")),
			mcp.WithString("category", mcp.Description("Destination category label (defaults to Core)")),
			mcp.WithString("mac", mcp.Description("Optional target MAC address")),
			mcp.WithString("default_check", mcp.Description("Canonical diagnostic tool name to run (defaults to recipe_diff_ping)")),
			mcp.WithBoolean("pinned", mcp.Description("Whether the destination is pinned")),
			mcp.WithBoolean("monitor_enabled", mcp.Description("Whether recurring cron watchlist monitoring is enabled")),
			mcp.WithString("monitor_schedule", mcp.Description("Cron schedule expression when monitoring is enabled (defaults to */5 * * * *)")),
		),
		newTool("get_job_report", "Retrieve an archived diagnostic job report by job_id and render it in the requested style",
			mcp.WithString("job_id", mcp.Required(), mcp.Description("Archived job identifier (e.g. job_...)")),
		),
		newTool("unlock_netutils", "Unlock Deadbolt passphrase protection for the sliding TTL window",
			mcp.WithString("passphrase", mcp.Required(), mcp.Description("Deadbolt unlock passphrase")),
		),
		newTool("lock_netutils", "Immediately re-lock Deadbolt passphrase protection"),
	}
}
