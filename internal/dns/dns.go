package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/response"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/miekg/dns"
	doh "github.com/shynome/doh-client"
)

// QueryConfig holds DNS query configuration.
type QueryConfig struct {
	Timeout             time.Duration
	RemoteServerAddress string
	LocalServers        []string
	Guard               *security.TargetGuard
}

// DNSQueryParams represents the parameters for DNS queries.
type DNSQueryParams struct {
	Domain     string `json:"domain"`
	RecordType string `json:"record_type"`
}

// DNSQuestion represents a question entry in a DNS response.
type DNSQuestion struct {
	Name     string `json:"name"`
	Type     uint16 `json:"type"`
	TypeName string `json:"typeName,omitempty"`
}

// DNSAnswer represents an answer record in a DNS response.
type DNSAnswer struct {
	Name     string `json:"name"`
	Type     uint16 `json:"type"`
	TypeName string `json:"typeName,omitempty"`
	TTL      uint32 `json:"TTL"`
	Data     string `json:"data"`
}

// DNSResponse represents a structured DNS query response.
type DNSResponse struct {
	Status            int           `json:"status"`
	StatusMessage     string        `json:"statusMessage,omitempty"`
	Truncated         bool          `json:"truncated"`
	AuthenticatedData bool          `json:"authenticatedData"`
	CheckingDisabled  bool          `json:"checkingDisabled"`
	Question          []DNSQuestion `json:"question"`
	Answer            []DNSAnswer   `json:"answer,omitempty"`
	EDNSClientSubnet  string        `json:"ednsClientSubnet,omitempty"`
}

const (
	defaultQueryTimeout      = 5 * time.Second
	defaultPrimaryDoHServer  = "https://cloudflare-dns.com/dns-query"
	defaultFallbackDoHServer = "https://dns.google/dns-query"
	defaultResolvConfPath    = "/etc/resolv.conf"
)

var defaultDoHClient = &http.Client{
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

// HandleLocalDNSQuery processes local DNS queries using OS-defined DNS servers.
func HandleLocalDNSQuery(ctx context.Context, request mcp.CallToolRequest, config *QueryConfig) (*mcp.CallToolResult, error) { //nolint:gocritic // Exported handler mirrors mcp-go ToolHandlerFunc value parameter.
	var params DNSQueryParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	result, err := ExecuteLocal(ctx, params, config)
	if err != nil {
		return nil, err
	}
	res, err := response.JSON(result)
	if err != nil {
		return nil, fmt.Errorf("encode DNS response: %w", err)
	}
	return res, nil
}

// ExecuteLocal performs a DNS query against configured local servers or system resolvers.
func ExecuteLocal(ctx context.Context, params DNSQueryParams, config *QueryConfig) (*DNSResponse, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}

	m, err := prepareDNSQuery(params)
	if err != nil {
		return nil, err
	}

	servers, err := resolveLocalServers(ctx, config)
	if err != nil {
		return nil, err
	}

	timeout := effectiveTimeout(config)
	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	c := &dns.Client{Timeout: timeout}
	var guard *security.TargetGuard
	if config != nil {
		guard = config.Guard
	}

	var dnsResponse *dns.Msg
	var queryErr error
	for _, server := range servers {
		if ctxWithTimeout.Err() != nil {
			if queryErr == nil {
				queryErr = ctxWithTimeout.Err()
			}
			break
		}

		serverAddr := formatDNSServerAddr(server)
		if guard != nil {
			host, _, splitErr := net.SplitHostPort(serverAddr)
			if splitErr != nil {
				queryErr = fmt.Errorf("invalid DNS server address %q: %w", server, splitErr)
				continue
			}
			if valErr := validateServerHost(ctxWithTimeout, guard, host); valErr != nil {
				queryErr = valErr
				continue
			}
		}

		dnsResponse, _, queryErr = c.ExchangeContext(ctxWithTimeout, m, serverAddr)
		if queryErr == nil && dnsResponse != nil {
			break
		}
	}

	if queryErr != nil {
		return nil, fmt.Errorf("DNS query failed: %w", queryErr)
	}
	if dnsResponse == nil {
		return nil, errors.New("no response from DNS servers")
	}

	return createDNSResponse(dnsResponse), nil
}

// HandleRemoteDNSQuery processes DNS queries using DNS-over-HTTPS.
func HandleRemoteDNSQuery(ctx context.Context, request mcp.CallToolRequest, config *QueryConfig) (*mcp.CallToolResult, error) { //nolint:gocritic // Exported handler mirrors mcp-go ToolHandlerFunc value parameter.
	var params DNSQueryParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	result, err := ExecuteRemote(ctx, params, config)
	if err != nil {
		return nil, err
	}
	res, err := response.JSON(result)
	if err != nil {
		return nil, fmt.Errorf("encode DNS response: %w", err)
	}
	return res, nil
}

// ExecuteRemote performs a DNS-over-HTTPS query with optional fallback to Google Public DNS.
func ExecuteRemote(ctx context.Context, params DNSQueryParams, config *QueryConfig) (*DNSResponse, error) {
	return executeRemoteWithServers(ctx, params, config, defaultPrimaryDoHServer, defaultFallbackDoHServer)
}

func executeRemoteWithServers(ctx context.Context, params DNSQueryParams, config *QueryConfig, primaryDefault, fallbackDefault string) (*DNSResponse, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}

	m, err := prepareDNSQuery(params)
	if err != nil {
		return nil, err
	}

	timeout := effectiveTimeout(config)
	var remoteAddr string
	var guard *security.TargetGuard
	if config != nil {
		remoteAddr = strings.TrimSpace(config.RemoteServerAddress)
		guard = config.Guard
	}

	var dnsResponse *dns.Msg
	if remoteAddr != "" {
		if guard != nil {
			if valErr := validateDoHServerURL(ctx, guard, remoteAddr); valErr != nil {
				return nil, valErr
			}
		}
		dnsResponse, err = queryDoHWithTimeout(ctx, timeout, remoteAddr, m)
	} else {
		if guard != nil {
			err = validateDoHServerURL(ctx, guard, primaryDefault)
		}
		if err == nil {
			dnsResponse, err = queryDoHWithTimeout(ctx, timeout, primaryDefault, m)
		}

		if err != nil && ctx.Err() == nil && fallbackDefault != "" {
			if guard != nil {
				if valErr := validateDoHServerURL(ctx, guard, fallbackDefault); valErr != nil {
					return nil, fmt.Errorf("primary DoH failed (%w); fallback rejected: %w", err, valErr)
				}
			}
			dnsResponse, err = queryDoHWithTimeout(ctx, timeout, fallbackDefault, m)
		}
	}

	if err != nil {
		return nil, err
	}
	if dnsResponse == nil {
		return nil, errors.New("no response from DoH server")
	}
	return createDNSResponse(dnsResponse), nil
}

func queryDoHWithTimeout(ctx context.Context, timeout time.Duration, serverURL string, msg *dns.Msg) (*dns.Msg, error) {
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return queryDoHServer(queryCtx, defaultDoHClient, serverURL, msg)
}

func queryDoHServer(ctx context.Context, client *http.Client, serverURL string, msg *dns.Msg) (*dns.Msg, error) {
	conn := doh.NewConn(client, ctx, serverURL)
	defer func() {
		_ = conn.Close()
	}()

	dnsConn := &dns.Conn{Conn: conn}
	if err := dnsConn.WriteMsg(msg); err != nil {
		return nil, fmt.Errorf("DNS-over-HTTPS query failed: %w", err)
	}

	dnsResponse, err := dnsConn.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("failed to read DNS response: %w", err)
	}
	return dnsResponse, nil
}

func prepareDNSQuery(params DNSQueryParams) (*dns.Msg, error) {
	cleanDomain, err := security.SanitizeTarget(params.Domain)
	if err != nil {
		return nil, fmt.Errorf("invalid domain: %w", err)
	}
	if strings.Contains(cleanDomain, "..") || strings.HasPrefix(cleanDomain, ".") {
		return nil, fmt.Errorf("invalid domain format: %q", cleanDomain)
	}

	cleanType := strings.TrimSpace(params.RecordType)
	if cleanType == "" {
		return nil, errors.New(`parameter "record_type" is required`)
	}
	recordType, err := ConvertToQType(cleanType)
	if err != nil {
		return nil, err
	}

	fqdn := cleanDomain
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	m := new(dns.Msg)
	m.SetQuestion(fqdn, recordType)
	m.RecursionDesired = true
	return m, nil
}

func effectiveTimeout(config *QueryConfig) time.Duration {
	if config != nil && config.Timeout > 0 {
		return config.Timeout
	}
	return defaultQueryTimeout
}

func validateDoHServerURL(ctx context.Context, guard *security.TargetGuard, rawURL string) error {
	parseTarget := rawURL
	if !strings.Contains(parseTarget, "://") {
		parseTarget = "https://" + parseTarget + "/dns-query"
	}
	parsed, err := url.Parse(parseTarget)
	if err != nil || parsed.Hostname() == "" {
		return fmt.Errorf("invalid DoH server URL %q", rawURL)
	}
	return validateServerHost(ctx, guard, parsed.Hostname())
}

func resolveLocalServers(ctx context.Context, config *QueryConfig) ([]string, error) {
	if config != nil && len(config.LocalServers) > 0 {
		servers := make([]string, 0, len(config.LocalServers))
		for _, s := range config.LocalServers {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				servers = append(servers, trimmed)
			}
		}
		if len(servers) > 0 {
			return servers, nil
		}
	}
	servers, err := getSystemDNSServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS servers: %w", err)
	}
	return servers, nil
}

// getSystemDNSServers returns a list of system DNS servers in a cross-platform way.
func getSystemDNSServers(ctx context.Context) ([]string, error) {
	if servers, err := parseResolvConfServers(defaultResolvConfPath); err == nil && len(servers) > 0 {
		return servers, nil
	}

	discoveredServers := make([]string, 0)
	var mu sync.Mutex
	dialer := &net.Dialer{Timeout: 2 * time.Second}

	netResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err == nil && host != "" {
				mu.Lock()
				if !slices.Contains(discoveredServers, host) {
					discoveredServers = append(discoveredServers, host)
				}
				mu.Unlock()
			}
			return dialer.DialContext(dialCtx, network, address)
		},
	}

	_, _ = netResolver.LookupHost(ctx, "one.one.one.one")

	mu.Lock()
	defer mu.Unlock()
	if len(discoveredServers) > 0 {
		return discoveredServers, nil
	}
	return nil, errors.New("could not discover any system DNS servers")
}

func parseResolvConfServers(path string) ([]string, error) {
	dnsConfig, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	servers := make([]string, 0, len(dnsConfig.Servers))
	for _, s := range dnsConfig.Servers {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" && !slices.Contains(servers, trimmed) {
			servers = append(servers, trimmed)
		}
	}
	return servers, nil
}

// ConvertToQType converts a string record type to the corresponding DNS query type.
// This function supports all DNS record types available in the miekg/dns package.
func ConvertToQType(recordType string) (uint16, error) {
	if qtype, exists := dns.StringToType[recordType]; exists {
		return qtype, nil
	}
	return 0, fmt.Errorf("unsupported record type %q", recordType)
}

func createDNSResponse(msg *dns.Msg) *DNSResponse {
	result := &DNSResponse{
		Status:            msg.Rcode,
		Truncated:         msg.Truncated,
		AuthenticatedData: msg.AuthenticatedData,
		CheckingDisabled:  msg.CheckingDisabled,
		Question:          make([]DNSQuestion, 0, len(msg.Question)),
	}
	for _, q := range msg.Question {
		result.Question = append(result.Question, DNSQuestion{
			Name:     q.Name,
			Type:     q.Qtype,
			TypeName: dns.TypeToString[q.Qtype],
		})
	}
	if len(msg.Answer) > 0 {
		answers := make([]DNSAnswer, 0, len(msg.Answer))
		for _, a := range msg.Answer {
			if a == nil {
				continue
			}
			hdr := a.Header()
			answers = append(answers, DNSAnswer{
				Name:     hdr.Name,
				Type:     hdr.Rrtype,
				TypeName: dns.TypeToString[hdr.Rrtype],
				TTL:      hdr.Ttl,
				Data:     extractRData(a),
			})
		}
		result.Answer = answers
	}
	if msg.Rcode >= 0 && msg.Rcode < len(dns.RcodeToString) {
		result.StatusMessage = dns.RcodeToString[msg.Rcode]
	}
	for _, extra := range msg.Extra {
		opt, ok := extra.(*dns.OPT)
		if !ok {
			continue
		}
		for _, o := range opt.Option {
			if subnet, ok := o.(*dns.EDNS0_SUBNET); ok {
				result.EDNSClientSubnet = fmt.Sprintf("%s/%d", subnet.Address.String(), subnet.SourceNetmask)
				return result
			}
		}
	}
	return result
}

func extractRData(rr dns.RR) string {
	switch rr.Header().Rrtype {
	case dns.TypeA:
		if rec, ok := rr.(*dns.A); ok && rec.A != nil {
			return rec.A.String()
		}
	case dns.TypeAAAA:
		if rec, ok := rr.(*dns.AAAA); ok && rec.AAAA != nil {
			return rec.AAAA.String()
		}
	case dns.TypeCAA:
		if rec, ok := rr.(*dns.CAA); ok {
			return fmt.Sprintf("%d %s %q", rec.Flag, rec.Tag, rec.Value)
		}
	case dns.TypeCNAME:
		if rec, ok := rr.(*dns.CNAME); ok {
			return rec.Target
		}
	case dns.TypeMX:
		if rec, ok := rr.(*dns.MX); ok {
			return fmt.Sprintf("%d %s", rec.Preference, rec.Mx)
		}
	case dns.TypeNS:
		if rec, ok := rr.(*dns.NS); ok {
			return rec.Ns
		}
	case dns.TypePTR:
		if rec, ok := rr.(*dns.PTR); ok {
			return rec.Ptr
		}
	case dns.TypeSOA:
		if rec, ok := rr.(*dns.SOA); ok {
			return fmt.Sprintf("%s %s %d %d %d %d %d",
				rec.Ns, rec.Mbox, rec.Serial, rec.Refresh, rec.Retry, rec.Expire, rec.Minttl)
		}
	case dns.TypeSRV:
		if rec, ok := rr.(*dns.SRV); ok {
			return fmt.Sprintf("%d %d %d %s", rec.Priority, rec.Weight, rec.Port, rec.Target)
		}
	case dns.TypeTXT:
		if rec, ok := rr.(*dns.TXT); ok {
			return strings.Join(rec.Txt, " ")
		}
	default:
		fields := strings.Fields(rr.String())
		if len(fields) >= 5 {
			return strings.Join(fields[4:], " ")
		}
		if len(fields) > 0 {
			return strings.Join(fields, " ")
		}
	}
	return ""
}
