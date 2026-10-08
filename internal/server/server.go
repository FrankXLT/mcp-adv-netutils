package server

import (
	"context"
	"slices"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/miekg/dns"
	internaldns "github.com/patrickdappollonio/mcp-netutils/internal/dns"
	"github.com/patrickdappollonio/mcp-netutils/internal/http_ping"
	"github.com/patrickdappollonio/mcp-netutils/internal/mac_lookup"
	"github.com/patrickdappollonio/mcp-netutils/internal/ping"
	"github.com/patrickdappollonio/mcp-netutils/internal/port_scan"
	"github.com/patrickdappollonio/mcp-netutils/internal/resolver"
	"github.com/patrickdappollonio/mcp-netutils/internal/tls"
	"github.com/patrickdappollonio/mcp-netutils/internal/traceroute"
	"github.com/patrickdappollonio/mcp-netutils/internal/whois"
	"github.com/patrickdappollonio/mcp-netutils/internal/wol"
)

// NetUtilsConfig contains configuration for the network utilities.
type NetUtilsConfig struct {
	QueryConfig    *internaldns.QueryConfig
	WhoisConfig    *whois.Config
	ResolverConfig *resolver.Config
	PingConfig     *ping.Config
	HTTPPingConfig *http_ping.Config
	TLSConfig      *tls.Config
	Version        string
}

// getDNSRecordTypes returns a sorted slice of all DNS record type names.
func getDNSRecordTypes() []string {
	var recordTypes []string
	for recordType := range dns.StringToType {
		recordTypes = append(recordTypes, recordType)
	}
	slices.Sort(recordTypes)
	return recordTypes
}

// SetupTools creates and configures the network utility tools.
func SetupTools(config *NetUtilsConfig) (*server.MCPServer, error) {
	// Create a new MCP server
	s := server.NewMCPServer(
		"DNS and WHOIS Query Tools",
		config.Version,
		server.WithRecovery(),
	)

	// Get all available DNS record types for the enum
	dnsRecordTypes := getDNSRecordTypes()

	// Initialize resolver config if not provided
	if config.ResolverConfig == nil {
		config.ResolverConfig = &resolver.Config{
			Timeout: 5 * time.Second,
		}
	}

	// Initialize ping config if not provided
	if config.PingConfig == nil {
		config.PingConfig = &ping.Config{
			Timeout: 5 * time.Second,
			Count:   4,
		}
	}

	// Initialize HTTP ping config if not provided
	if config.HTTPPingConfig == nil {
		config.HTTPPingConfig = &http_ping.Config{
			Timeout: 10 * time.Second,
			Count:   1,
		}
	}

	// Initialize TLS config if not provided
	if config.TLSConfig == nil {
		config.TLSConfig = &tls.Config{
			Timeout: 10 * time.Second,
			Port:    443,
		}
	}

	// Add local DNS query tool
	localQueryTool := mcp.NewTool("local_dns_query",
		mcp.WithDescription("Perform DNS queries using local OS-defined DNS servers"),
		mcp.WithString("domain",
			mcp.Required(),
			mcp.Description("The domain name to query (e.g., example.com)"),
		),
		mcp.WithString("record_type",
			mcp.Required(),
			mcp.Description("The type of DNS record to query (supports all standard DNS record types); defaults to A"),
			mcp.Enum(dnsRecordTypes...),
			mcp.DefaultString("A"),
		),
	)

	// Add remote DNS query tool
	remoteQueryTool := mcp.NewTool("remote_dns_query",
		mcp.WithDescription("Perform DNS queries using remote DNS-over-HTTPS servers (Google and Cloudflare)"),
		mcp.WithString("domain",
			mcp.Required(),
			mcp.Description("The domain name to query (e.g., example.com)"),
		),
		mcp.WithString("record_type",
			mcp.Required(),
			mcp.Description("The type of DNS record to query (supports all standard DNS record types); defaults to A"),
			mcp.Enum(dnsRecordTypes...),
			mcp.DefaultString("A"),
		),
	)

	// Add WHOIS query tool
	whoisQueryTool := mcp.NewTool("whois_query",
		mcp.WithDescription("Perform WHOIS lookups to get domain registration information"),
		mcp.WithString("domain",
			mcp.Required(),
			mcp.Description("The domain name to query (e.g., example.com)"),
		),
	)

	// Add hostname to IP resolution tool
	resolveHostTool := mcp.NewTool("resolve_hostname",
		mcp.WithDescription("Convert a hostname to its corresponding IP addresses"),
		mcp.WithString("hostname",
			mcp.Required(),
			mcp.Description("The hostname to resolve (e.g., example.com)"),
		),
		mcp.WithString("ip_version",
			mcp.Description("IP version to resolve (ipv4, ipv6, or both); defaults to ipv4"),
			mcp.Enum("ipv4", "ipv6", "both"),
			mcp.DefaultString("ipv4"),
		),
	)

	// Add ping tool
	pingTool := mcp.NewTool("ping",
		mcp.WithDescription("Perform ping operations to test connectivity and measure response times to a host"),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("The hostname or IP address to ping (e.g., example.com or 8.8.8.8)"),
		),
		mcp.WithNumber("count",
			mcp.Description("Number of ping packets to send; defaults to 4"),
			mcp.DefaultNumber(4),
		),
	)

	// Add TLS certificate check tool
	tlsCheckTool := mcp.NewTool("tls_certificate_check",
		mcp.WithDescription("Check TLS certificate chain for a domain to analyze certificate validity, expiration, and chain structure"),
		mcp.WithString("domain",
			mcp.Required(),
			mcp.Description("The domain name to check TLS certificate for (e.g., example.com)"),
		),
		mcp.WithNumber("port",
			mcp.Description("Port to connect to for TLS check; defaults to 443"),
			mcp.DefaultNumber(443),
		),
		mcp.WithBoolean("include_chain",
			mcp.Description("Whether to include the full certificate chain in the response; defaults to true"),
		),
		mcp.WithBoolean("check_expiry",
			mcp.Description("Whether to check certificate expiration and provide warnings; defaults to true"),
		),
		mcp.WithString("server_name",
			mcp.Description("Server name for SNI (Server Name Indication); defaults to the domain name"),
		),
	)

	// Add HTTP ping tool
	httpPingTool := mcp.NewTool("http_ping",
		mcp.WithDescription("Perform HTTP ping operations to test connectivity and measure response times to HTTP endpoints"),
		mcp.WithString("url",
			mcp.Required(),
			mcp.Description("The URL to ping (e.g., https://api.example.com/users)"),
		),
		mcp.WithString("method",
			mcp.Description("HTTP method to use; defaults to GET"),
			mcp.Enum("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"),
			mcp.DefaultString("GET"),
		),
		mcp.WithNumber("count",
			mcp.Description("Number of HTTP requests to send; defaults to 1"),
			mcp.DefaultNumber(1),
		),
	)

	// Add MAC vendor lookup tool (IEEE OUI + LAA detection)
	macLookupTool := mcp.NewTool("mac_vendor_lookup",
		mcp.WithDescription("Perform an IEEE OUI vendor lookup and detect locally administered (LAA / virtual / Docker) MAC addresses"),
		mcp.WithString("mac",
			mcp.Required(),
			mcp.Description("The MAC address to lookup (e.g. 9C:8E:CD:0A:91:0C, 44-61-32-11-22-33, or raw hex)"),
		),
	)

	// Add traceroute tool
	tracerouteTool := mcp.NewTool("traceroute",
		mcp.WithDescription("Execute hop-by-hop route tracing to isolate intermediate gateways, network latency, and packet loss"),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("Destination IPv4, IPv6, or hostname (e.g. 1.1.1.1 or example.com)"),
		),
		mcp.WithNumber("max_hops",
			mcp.Description("Maximum number of hops (TTL ceiling, 1-30); defaults to 15"),
			mcp.DefaultNumber(15),
		),
		mcp.WithNumber("timeout_seconds",
			mcp.Description("Probe timeout per hop in seconds; defaults to 2"),
			mcp.DefaultNumber(2),
		),
	)

	// Add TCP port scan tool
	portScanTool := mcp.NewTool("tcp_port_scan",
		mcp.WithDescription("Perform fast Layer 4 TCP connect handshakes on target ports to verify active service listeners"),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("The target hostname or IP address (e.g. 192.168.1.1 or example.com)"),
		),
		mcp.WithString("ports",
			mcp.Required(),
			mcp.Description("Comma-separated ports or range to probe (e.g. '22,80,443,1883,8123' or '80-90')"),
		),
		mcp.WithNumber("timeout_ms",
			mcp.Description("Timeout per port in milliseconds; defaults to 1000"),
			mcp.DefaultNumber(1000),
		),
	)

	// Add reverse DNS batch lookup tool
	dnsBatchTool := mcp.NewTool("dns_reverse_batch",
		mcp.WithDescription("Batch-resolve PTR reverse DNS hostnames concurrently for a comma-separated list of IP addresses"),
		mcp.WithString("ips",
			mcp.Required(),
			mcp.Description("Comma-separated list of IP addresses to resolve (e.g. '192.168.1.1, 192.168.1.105')"),
		),
		mcp.WithNumber("timeout_ms",
			mcp.Description("Timeout per lookup in milliseconds; defaults to 3000"),
			mcp.DefaultNumber(3000),
		),
	)

	// Add Wake-on-LAN tool
	wolTool := mcp.NewTool("wol_wake",
		mcp.WithDescription("Send a Wake-on-LAN Magic Packet broadcast frame to wake a physical machine or server"),
		mcp.WithString("mac",
			mcp.Required(),
			mcp.Description("Target machine MAC address to wake (e.g. 00:11:32:XX:YY:ZZ)"),
		),
		mcp.WithString("broadcast_ip",
			mcp.Description("Broadcast destination IP; defaults to 255.255.255.255"),
			mcp.DefaultString("255.255.255.255"),
		),
		mcp.WithNumber("port",
			mcp.Description("Target UDP port; defaults to 9"),
			mcp.DefaultNumber(9),
		),
	)

	// Create handler wrappers
	localDNSHandler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return internaldns.HandleLocalDNSQuery(ctx, request, config.QueryConfig)
	}

	remoteDNSHandler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return internaldns.HandleRemoteDNSQuery(ctx, request, config.QueryConfig)
	}

	whoisHandler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return whois.HandleWhoisQuery(ctx, request, config.WhoisConfig)
	}

	resolveHostHandler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return resolver.HandleHostnameResolution(ctx, request, config.ResolverConfig)
	}

	pingHandler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return ping.HandlePing(ctx, request, config.PingConfig)
	}

	tlsCheckHandler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return tls.HandleTLSCheck(ctx, request, config.TLSConfig)
	}

	httpPingHandler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return http_ping.HandleHTTPPing(ctx, request, config.HTTPPingConfig)
	}

	macLookupHandler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mac_lookup.HandleMACLookup(ctx, request)
	}

	tracerouteHandler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return traceroute.HandleTraceroute(ctx, request)
	}

	portScanHandler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return port_scan.HandlePortScan(ctx, request)
	}

	dnsBatchHandler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return internaldns.HandleReverseDNSBatch(ctx, request, config.QueryConfig)
	}

	wolHandler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return wol.HandleWakeOnLAN(ctx, request)
	}

	// Add handlers for the tools
	s.AddTool(localQueryTool, localDNSHandler)
	s.AddTool(remoteQueryTool, remoteDNSHandler)
	s.AddTool(whoisQueryTool, whoisHandler)
	s.AddTool(resolveHostTool, resolveHostHandler)
	s.AddTool(pingTool, pingHandler)
	s.AddTool(tlsCheckTool, tlsCheckHandler)
	s.AddTool(httpPingTool, httpPingHandler)
	s.AddTool(macLookupTool, macLookupHandler)
	s.AddTool(tracerouteTool, tracerouteHandler)
	s.AddTool(portScanTool, portScanHandler)
	s.AddTool(dnsBatchTool, dnsBatchHandler)
	s.AddTool(wolTool, wolHandler)

	return s, nil
}
