package probe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/hashicorp/mdns"
	"golang.org/x/sync/errgroup"
)

// DiscoverParams defines parameters for mDNS and SSDP service discovery.
type DiscoverParams struct {
	Protocol   string `json:"protocol"`
	Service    string `json:"service"`
	TimeoutMS  int    `json:"timeout_ms"`
	MaxResults int    `json:"max_results"`
}

// DiscoveredService represents a single service discovered via mDNS or SSDP.
type DiscoveredService struct {
	Protocol    string `json:"protocol"`
	Name        string `json:"name,omitempty"`
	ServiceType string `json:"service_type,omitempty"`
	Host        string `json:"host,omitempty"`
	IP          string `json:"ip,omitempty"`
	Port        int    `json:"port,omitempty"`
	Location    string `json:"location,omitempty"`
	Server      string `json:"server,omitempty"`
	Info        string `json:"info,omitempty"`
}

// DiscoverResult contains aggregated mDNS and SSDP discovery results.
type DiscoverResult struct {
	Protocol  string              `json:"protocol"`
	Count     int                 `json:"count"`
	Services  []DiscoveredService `json:"services"`
	Warnings  []string            `json:"warnings,omitempty"`
	Timestamp string              `json:"timestamp"`
}

type discoverConfig struct {
	protocol   string
	service    string
	timeout    time.Duration
	maxResults int
}

const (
	protocolBoth              = "both"
	protocolMDNS              = "mdns"
	protocolSSDP              = "ssdp"
	defaultMDNSService        = "_services._dns-sd._udp"
	defaultSSDPService        = "ssdp:all"
	defaultDiscoverTimeoutMS  = 2000
	minDiscoverTimeoutMS      = 500
	maxDiscoverTimeoutMS      = 5000
	defaultDiscoverMaxResults = 100
	minDiscoverMaxResults     = 1
	maxDiscoverMaxResults     = 256
	ssdpMulticastAddr         = "239.255.255.250:1900"
	ssdpReadBufSize           = 8192
)

var errInvalidDiscoverParams = errors.New("invalid discovery parameters")

// ExecuteMDNSSSDPDiscover runs bounded mDNS and/or SSDP discovery concurrently,
// filtering discovered IPs through guard (always blocking link-local metadata 169.254.0.0/16).
func ExecuteMDNSSSDPDiscover(
	ctx context.Context,
	params DiscoverParams,
	guard *security.TargetGuard,
) (*DiscoverResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", errInvalidDiscoverParams)
	}
	cfg, err := normalizeDiscoverParams(params)
	if err != nil {
		return nil, err
	}
	return executeDiscoverWithSSDPAddr(ctx, cfg, ssdpMulticastAddr, guard)
}

func executeDiscoverWithSSDPAddr(
	ctx context.Context,
	cfg discoverConfig,
	ssdpAddr string,
	guard *security.TargetGuard,
) (*DiscoverResult, error) {
	var (
		mu       sync.Mutex
		services []DiscoveredService
		warnings []string
		mdnsErr  error
		ssdpErr  error
	)

	runSub := func(proto string, fn func() ([]DiscoveredService, []string, error), errDst *error) func() error {
		return func() error {
			res, warns, err := fn()
			mu.Lock()
			defer mu.Unlock()
			warnings = append(warnings, warns...)
			if err != nil {
				*errDst = err
				if cfg.protocol == proto {
					return err
				}
				return nil
			}
			services = append(services, res...)
			return nil
		}
	}

	g, gCtx := errgroup.WithContext(ctx)
	if cfg.protocol == protocolBoth || cfg.protocol == protocolMDNS {
		svc := firstNonEmpty(cfg.service, defaultMDNSService)
		g.Go(runSub(protocolMDNS, func() ([]DiscoveredService, []string, error) {
			return discoverMDNS(gCtx, svc, cfg.timeout, cfg.maxResults, guard)
		}, &mdnsErr))
	}
	if cfg.protocol == protocolBoth || cfg.protocol == protocolSSDP {
		svc := firstNonEmpty(cfg.service, defaultSSDPService)
		g.Go(runSub(protocolSSDP, func() ([]DiscoveredService, []string, error) {
			return discoverSSDP(gCtx, ssdpAddr, svc, cfg.timeout, cfg.maxResults, guard)
		}, &ssdpErr))
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("discovery failed: %w", err)
	}
	if cfg.protocol == protocolBoth && mdnsErr != nil && ssdpErr != nil {
		return nil, fmt.Errorf("both mDNS (%w) and SSDP (%w) discovery failed", mdnsErr, ssdpErr)
	}
	if mdnsErr != nil {
		warnings = append(warnings, fmt.Sprintf("mdns discovery failed: %v", mdnsErr))
	}
	if ssdpErr != nil {
		warnings = append(warnings, fmt.Sprintf("ssdp discovery failed: %v", ssdpErr))
	}

	deduped, truncated := dedupeAndCapServices(services, cfg.maxResults)
	if truncated {
		warnings = append(warnings, fmt.Sprintf("results truncated to max_results=%d", cfg.maxResults))
	}

	return &DiscoverResult{
		Protocol:  cfg.protocol,
		Count:     len(deduped),
		Services:  deduped,
		Warnings:  warnings,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func normalizeDiscoverParams(params DiscoverParams) (discoverConfig, error) {
	proto := strings.ToLower(strings.TrimSpace(params.Protocol))
	if proto == "" {
		proto = protocolBoth
	}
	if proto != protocolBoth && proto != protocolMDNS && proto != protocolSSDP {
		return discoverConfig{}, fmt.Errorf("%w: unsupported protocol %q (must be both, mdns, or ssdp)", errInvalidDiscoverParams, params.Protocol)
	}

	for _, r := range params.Service {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return discoverConfig{}, fmt.Errorf("%w: service %q must not contain whitespace or control characters", errInvalidDiscoverParams, params.Service)
		}
	}

	timeoutMS := clampProbeInt(params.TimeoutMS, defaultDiscoverTimeoutMS, minDiscoverTimeoutMS, maxDiscoverTimeoutMS)
	maxResults := clampProbeInt(params.MaxResults, defaultDiscoverMaxResults, minDiscoverMaxResults, maxDiscoverMaxResults)

	return discoverConfig{
		protocol:   proto,
		service:    params.Service,
		timeout:    time.Duration(timeoutMS) * time.Millisecond,
		maxResults: maxResults,
	}, nil
}

func clampProbeInt(val, defaultVal, minVal, maxVal int) int {
	if val <= 0 {
		return defaultVal
	}
	return min(max(val, minVal), maxVal)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func discoverMDNS(
	ctx context.Context,
	service string,
	timeout time.Duration,
	maxResults int,
	guard *security.TargetGuard,
) ([]DiscoveredService, []string, error) {
	entriesCh := make(chan *mdns.ServiceEntry, 64)
	errCh := make(chan error, 1)
	qp := &mdns.QueryParam{
		Service: service,
		Domain:  "local",
		Timeout: timeout,
		Entries: entriesCh,
		Logger:  log.New(io.Discard, "", 0),
	}

	go func() {
		err := mdns.QueryContext(ctx, qp)
		close(entriesCh)
		errCh <- err
	}()

	var results []DiscoveredService
	var warnings []string
	for entry := range entriesCh {
		if entry == nil || len(results) >= maxResults {
			continue
		}
		svc, warn, ok := convertMDNSEntry(entry, service, guard)
		if warn != "" {
			warnings = append(warnings, warn)
		}
		if ok {
			results = append(results, svc)
		}
	}
	if err := <-errCh; err != nil {
		return nil, warnings, fmt.Errorf("mdns query failed: %w", err)
	}
	return results, warnings, nil
}

func convertMDNSEntry(
	entry *mdns.ServiceEntry,
	serviceType string,
	guard *security.TargetGuard,
) (DiscoveredService, string, bool) {
	ip := pickMDNSIP(entry)
	ipStr := ""
	if ip != nil {
		if err := guard.ValidateIP(ip); err != nil {
			return DiscoveredService{}, fmt.Sprintf("filtered mDNS service %q (%s): %v", entry.Name, ip.String(), err), false
		}
		ipStr = ip.String()
	}

	return DiscoveredService{
		Protocol:    protocolMDNS,
		Name:        strings.TrimSuffix(entry.Name, "."),
		ServiceType: serviceType,
		Host:        strings.TrimSuffix(entry.Host, "."),
		IP:          ipStr,
		Port:        entry.Port,
		Info:        entry.Info,
	}, "", true
}

func pickMDNSIP(entry *mdns.ServiceEntry) net.IP {
	if entry.AddrV4 != nil {
		if v4 := entry.AddrV4.To4(); v4 != nil {
			return v4
		}
	}
	if entry.AddrV6IPAddr != nil && entry.AddrV6IPAddr.IP != nil {
		return entry.AddrV6IPAddr.IP
	}
	if entry.AddrV6 != nil {
		return entry.AddrV6
	}
	return entry.Addr
}

func discoverSSDP(
	ctx context.Context,
	targetAddr string,
	service string,
	timeout time.Duration,
	maxResults int,
	guard *security.TargetGuard,
) ([]DiscoveredService, []string, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", targetAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve SSDP address %q: %w", targetAddr, err)
	}

	lc := &net.ListenConfig{}
	conn, err := lc.ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open SSDP UDP socket: %w", err)
	}
	defer func() { _ = conn.Close() }()

	stopCancel := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stopCancel()

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, fmt.Errorf("failed to set SSDP read deadline: %w", err)
	}

	mx := max(int(timeout/time.Second), 1)
	req := fmt.Sprintf("M-SEARCH * HTTP/1.1\r\nHOST: %s\r\nMAN: \"ssdp:discover\"\r\nMX: %d\r\nST: %s\r\n\r\n", targetAddr, mx, service)
	if _, err := conn.WriteTo([]byte(req), udpAddr); err != nil {
		return nil, nil, fmt.Errorf("failed to send SSDP M-SEARCH: %w", err)
	}

	buf := make([]byte, ssdpReadBufSize)
	var results []DiscoveredService
	var warnings []string
	for len(results) < maxResults {
		n, raddr, readErr := conn.ReadFrom(buf)
		if readErr != nil {
			if isTimeoutOrCancel(ctx, readErr) {
				break
			}
			return results, warnings, fmt.Errorf("ssdp read failed: %w", readErr)
		}
		svc, warn, ok := processSSDPPacket(buf[:n], raddr, guard)
		if warn != "" {
			warnings = append(warnings, warn)
		}
		if ok {
			results = append(results, svc)
		}
	}
	return results, warnings, nil
}

func isTimeoutOrCancel(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func processSSDPPacket(raw []byte, raddr net.Addr, guard *security.TargetGuard) (DiscoveredService, string, bool) {
	svc, ok := parseSSDPResponse(raw, raddr)
	if !ok {
		return DiscoveredService{}, "", false
	}

	if err := validateSSDPAddress(svc.IP, guard); err != nil {
		return DiscoveredService{}, fmt.Sprintf("filtered SSDP service from %s: %v", svc.IP, err), false
	}
	if svc.Location != "" {
		if u, err := url.Parse(svc.Location); err == nil {
			if valErr := validateSSDPAddress(u.Hostname(), guard); valErr != nil {
				return DiscoveredService{}, fmt.Sprintf("filtered SSDP location %q: %v", svc.Location, valErr), false
			}
		}
	}
	return svc, "", true
}

func validateSSDPAddress(host string, guard *security.TargetGuard) error {
	if host == "" {
		return nil
	}
	if addr, parseErr := netip.ParseAddr(host); parseErr == nil {
		if valErr := guard.ValidateIP(net.IP(addr.Unmap().AsSlice())); valErr != nil {
			return fmt.Errorf("address blocked: %w", valErr)
		}
	}
	return nil
}

func parseSSDPResponse(raw []byte, raddr net.Addr) (DiscoveredService, bool) {
	text := strings.TrimSpace(string(bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))))
	if text == "" {
		return DiscoveredService{}, false
	}
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || !strings.HasPrefix(strings.ToUpper(lines[0]), "HTTP/") {
		return DiscoveredService{}, false
	}

	headers := make(map[string]string, len(lines))
	for _, line := range lines[1:] {
		if k, v, ok := strings.Cut(line, ":"); ok {
			key := strings.ToUpper(strings.TrimSpace(k))
			val := strings.TrimSpace(v)
			if key != "" && val != "" {
				headers[key] = val
			}
		}
	}

	svc := DiscoveredService{
		Protocol:    protocolSSDP,
		Name:        firstNonEmpty(headers["USN"], headers["ST"]),
		ServiceType: headers["ST"],
		Location:    headers["LOCATION"],
		Server:      headers["SERVER"],
	}
	if udpAddr, ok := raddr.(*net.UDPAddr); ok && udpAddr.IP != nil {
		if v4 := udpAddr.IP.To4(); v4 != nil {
			svc.IP = v4.String()
		} else {
			svc.IP = udpAddr.IP.String()
		}
	}
	if svc.Location != "" {
		if u, err := url.Parse(svc.Location); err == nil {
			svc.Host = u.Hostname()
			if p, pErr := strconv.Atoi(u.Port()); pErr == nil && p > 0 && p <= 65535 {
				svc.Port = p
			}
		}
	}
	return svc, true
}

func dedupeAndCapServices(in []DiscoveredService, maxResults int) ([]DiscoveredService, bool) {
	seen := make(map[string]struct{}, len(in))
	out := make([]DiscoveredService, 0, len(in))
	for i := range in {
		svc := in[i]
		key := svc.Protocol + "|" + svc.ServiceType + "|" + svc.Name + "|" + svc.IP + "|" + strconv.Itoa(svc.Port) + "|" + svc.Location
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, svc)
	}

	sort.Slice(out, func(i, j int) bool {
		a, b := &out[i], &out[j]
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.ServiceType != b.ServiceType {
			return a.ServiceType < b.ServiceType
		}
		return a.Name < b.Name
	})

	if len(out) > maxResults {
		return out[:maxResults], true
	}
	return out, false
}
