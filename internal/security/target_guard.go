package security

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"unicode"
)

// TargetGuard enforces target string sanitization and CIDR allow/deny rules.
type TargetGuard struct {
	allowNets    []*net.IPNet
	denyNets     []*net.IPNet
	blockPrivate bool
	lookupIPAddr func(ctx context.Context, host string) ([]net.IPAddr, error)
	dialContext  func(ctx context.Context, network, addr string) (net.Conn, error)
}

const (
	metadataIPv4CIDR = "169.254.0.0/16"
	metadataIPv6CIDR = "fd00:ec2::254/128"
)

var (
	// ErrTargetInvalid indicates the target hostname, IP, or CIDR failed syntax checks.
	ErrTargetInvalid = errors.New("invalid target")
	// ErrTargetDenied indicates the target matched an explicit or mandatory deny CIDR.
	ErrTargetDenied = errors.New("target denied")
	// ErrTargetNotAllowed indicates the target did not match any configured allow CIDR.
	ErrTargetNotAllowed = errors.New("target not allowed")
)

// NewTargetGuard constructs a TargetGuard from allow and deny CIDR lists.
// Cloud metadata ranges (169.254.0.0/16 and fd00:ec2::254/128) are always denied.
func NewTargetGuard(allowCIDRs, denyCIDRs []string) (*TargetGuard, error) {
	return NewTargetGuardWithOptions(allowCIDRs, denyCIDRs, false)
}

// NewTargetGuardWithOptions constructs a TargetGuard with optional private IP blocking.
// Cloud metadata ranges (169.254.0.0/16 and fd00:ec2::254/128) are always denied.
func NewTargetGuardWithOptions(allowCIDRs, denyCIDRs []string, blockPrivate bool) (*TargetGuard, error) {
	allowNets, err := parseCIDRList(allowCIDRs)
	if err != nil {
		return nil, fmt.Errorf("invalid allow CIDRs: %w", err)
	}

	userDenyNets, err := parseCIDRList(denyCIDRs)
	if err != nil {
		return nil, fmt.Errorf("invalid deny CIDRs: %w", err)
	}

	mandatoryDenyNets, err := defaultMetadataDenyNets()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize default deny CIDRs: %w", err)
	}

	denyNets := make([]*net.IPNet, 0, len(mandatoryDenyNets)+len(userDenyNets))
	denyNets = append(denyNets, mandatoryDenyNets...)
	denyNets = append(denyNets, userDenyNets...)

	return &TargetGuard{
		allowNets:    allowNets,
		denyNets:     denyNets,
		blockPrivate: blockPrivate,
		lookupIPAddr: net.DefaultResolver.LookupIPAddr,
		dialContext:  (&net.Dialer{}).DialContext,
	}, nil
}

// BlockPrivate reports whether private/loopback/link-local IPs are blocked.
func (g *TargetGuard) BlockPrivate() bool {
	if g == nil {
		return false
	}
	return g.blockPrivate
}

// SanitizeTarget trims outer whitespace and rejects empty strings, leading '-',
// internal whitespace, control characters, and URL/path characters ('/', '\', '?', '#').
func SanitizeTarget(raw string) (string, error) {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return "", fmt.Errorf("%w: target must not be empty", ErrTargetInvalid)
	}

	if strings.HasPrefix(clean, "-") {
		return "", fmt.Errorf("%w: target %q must not start with '-'", ErrTargetInvalid, clean)
	}

	for _, r := range clean {
		if unicode.IsSpace(r) || unicode.IsControl(r) || isForbiddenTargetRune(r) {
			return "", fmt.Errorf("%w: target %q contains forbidden character %q", ErrTargetInvalid, clean, r)
		}
	}

	return clean, nil
}

// ValidateIP checks a single IP against denyNets (taking precedence), optional
// private-IP blocking, and allowNets (if configured).
func (g *TargetGuard) ValidateIP(ip net.IP) error {
	normalized := normalizeIP(ip)
	if normalized == nil {
		return fmt.Errorf("%w: invalid or empty IP address", ErrTargetInvalid)
	}

	denyNets, allowNets, blockPrivate, err := g.effectiveRules()
	if err != nil {
		return err
	}

	for _, denyNet := range denyNets {
		if denyNet.Contains(normalized) {
			return fmt.Errorf("%w: IP %s matches deny rule %s", ErrTargetDenied, normalized.String(), denyNet.String())
		}
	}

	if blockPrivate && isBlockedPrivateIP(normalized) {
		return fmt.Errorf("%w: private or link-local IP %s is blocked", ErrTargetDenied, normalized.String())
	}

	if len(allowNets) > 0 {
		allowed := false
		for _, allowNet := range allowNets {
			if allowNet.Contains(normalized) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: IP %s is not within any allowed CIDR", ErrTargetNotAllowed, normalized.String())
		}
	}

	return nil
}

// ValidateHostOrIP sanitizes target, validates an IP literal directly, or resolves
// a hostname once via LookupIPAddr and validates every resolved IP against the guard.
func (g *TargetGuard) ValidateHostOrIP(ctx context.Context, target string) ([]net.IP, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrTargetInvalid)
	}

	clean, err := SanitizeTarget(target)
	if err != nil {
		return nil, err
	}

	if addr, parseErr := netip.ParseAddr(clean); parseErr == nil {
		ip := net.IP(addr.Unmap().AsSlice())
		if valErr := g.ValidateIP(ip); valErr != nil {
			return nil, valErr
		}
		return []net.IP{ip}, nil
	}

	lookup := g.lookupFn()
	addrs, err := lookup(ctx, clean)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve host %q: %w", clean, err)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: no IP addresses resolved for %q", ErrTargetInvalid, clean)
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ip := normalizeIP(addr.IP)
		if valErr := g.ValidateIP(ip); valErr != nil {
			return nil, fmt.Errorf("resolved IP for %q blocked: %w", clean, valErr)
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

// ValidateCIDR parses cidr and rejects it if invalid, overlapping any denied network
// (including 169.254.0.0/16), or falling outside configured allowNets.
func (g *TargetGuard) ValidateCIDR(cidr string) (net.IP, *net.IPNet, error) {
	clean, err := sanitizeCIDRInput(cidr)
	if err != nil {
		return nil, nil, err
	}

	ip, ipNet, err := net.ParseCIDR(clean)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid CIDR %q: %w", ErrTargetInvalid, clean, err)
	}

	normalizedIP := normalizeIP(ip)
	if normalizedIP == nil {
		return nil, nil, fmt.Errorf("%w: invalid IP in CIDR %q", ErrTargetInvalid, clean)
	}

	denyNets, allowNets, blockPrivate, err := g.effectiveRules()
	if err != nil {
		return nil, nil, err
	}

	for _, denyNet := range denyNets {
		if netsOverlap(ipNet, denyNet) {
			return nil, nil, fmt.Errorf("%w: CIDR %s overlaps denied network %s", ErrTargetDenied, ipNet.String(), denyNet.String())
		}
	}

	if blockPrivate {
		if err := checkPrivateCIDROverlap(ipNet); err != nil {
			return nil, nil, err
		}
	}

	if len(allowNets) > 0 {
		allowed := false
		for _, allowNet := range allowNets {
			if netContainsSubnet(allowNet, ipNet) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, nil, fmt.Errorf("%w: CIDR %s is not within any allowed CIDR", ErrTargetNotAllowed, ipNet.String())
		}
	}

	return normalizedIP, ipNet, nil
}

// DialContext validates and resolves the target host once, then dials a
// validated IP address directly without performing a second DNS lookup.
//
//nolint:ireturn // Matches net.Dialer.DialContext / http.Transport.DialContext signature.
func (g *TargetGuard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrTargetInvalid)
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid address %q: %w", ErrTargetInvalid, addr, err)
	}
	if host == "" || port == "" || strings.TrimSpace(host) != host || strings.TrimSpace(port) != port {
		return nil, fmt.Errorf("%w: invalid host or port in %q", ErrTargetInvalid, addr)
	}

	guard := g
	if guard == nil {
		guard, err = NewTargetGuard(nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize default target guard: %w", err)
		}
	}

	ips, err := guard.ValidateHostOrIP(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no validated IP addresses for %q", ErrTargetInvalid, host)
	}

	ips = orderIPv4First(ips)
	dialFn := guard.dialFn()
	var lastErr error
	for _, ip := range ips {
		if ctx.Err() != nil {
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			break
		}
		conn, dialErr := dialFn(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = selectDialError(lastErr, dialErr)
	}

	return nil, fmt.Errorf("failed to dial %q: %w", addr, lastErr)
}

func (g *TargetGuard) lookupFn() func(ctx context.Context, host string) ([]net.IPAddr, error) {
	if g != nil && g.lookupIPAddr != nil {
		return g.lookupIPAddr
	}
	return net.DefaultResolver.LookupIPAddr
}

func (g *TargetGuard) dialFn() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if g != nil && g.dialContext != nil {
		return g.dialContext
	}
	return (&net.Dialer{}).DialContext
}

// orderIPv4First returns ips stably partitioned with IPv4 addresses before IPv6 addresses.
func orderIPv4First(ips []net.IP) []net.IP {
	if len(ips) <= 1 {
		return ips
	}
	ordered := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip.To4() != nil {
			ordered = append(ordered, ip)
		}
	}
	for _, ip := range ips {
		if ip.To4() == nil {
			ordered = append(ordered, ip)
		}
	}
	return ordered
}

// selectDialError preserves the first meaningful non-EADDRNOTAVAIL failure so
// trailing unconfigured-IPv6 errors do not mask earlier IPv4 dial failures.
func selectDialError(current, next error) error {
	if next == nil {
		return current
	}
	if current == nil {
		return next
	}
	if errors.Is(current, syscall.EADDRNOTAVAIL) && !errors.Is(next, syscall.EADDRNOTAVAIL) {
		return next
	}
	return current
}

func (g *TargetGuard) effectiveRules() ([]*net.IPNet, []*net.IPNet, bool, error) {
	if g != nil {
		return g.denyNets, g.allowNets, g.blockPrivate, nil
	}
	denyNets, err := defaultMetadataDenyNets()
	if err != nil {
		return nil, nil, false, err
	}
	return denyNets, nil, false, nil
}

func parseCIDRList(entries []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet

	for _, entry := range entries {
		for _, rawToken := range strings.Split(entry, ",") {
			token := strings.TrimSpace(rawToken)
			if token == "" {
				continue
			}

			_, ipNet, err := net.ParseCIDR(token)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid CIDR %q: %w", ErrTargetInvalid, token, err)
			}
			nets = append(nets, ipNet)
		}
	}

	return nets, nil
}

func defaultMetadataDenyNets() ([]*net.IPNet, error) {
	return parseCIDRList([]string{metadataIPv4CIDR, metadataIPv6CIDR})
}

func sanitizeCIDRInput(raw string) (string, error) {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return "", fmt.Errorf("%w: CIDR must not be empty", ErrTargetInvalid)
	}
	if strings.HasPrefix(clean, "-") {
		return "", fmt.Errorf("%w: CIDR %q must not start with '-'", ErrTargetInvalid, clean)
	}
	for _, r := range clean {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '\\' || r == '?' || r == '#' {
			return "", fmt.Errorf("%w: CIDR %q contains forbidden character %q", ErrTargetInvalid, clean, r)
		}
	}
	return clean, nil
}

func isForbiddenTargetRune(r rune) bool {
	switch r {
	case '/', '\\', '?', '#':
		return true
	default:
		return false
	}
}

func normalizeIP(ip net.IP) net.IP {
	if len(ip) == 0 {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	if len(ip) != net.IPv6len {
		return nil
	}
	return ip
}

func isBlockedPrivateIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil && v4[0] == 0 {
		return true
	}
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified()
}

func checkPrivateCIDROverlap(target *net.IPNet) error {
	privateCIDRs := []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"224.0.0.0/24",
		"::/128",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"ff02::/16",
	}

	privateNets, err := parseCIDRList(privateCIDRs)
	if err != nil {
		return err
	}

	for _, privNet := range privateNets {
		if netsOverlap(target, privNet) {
			return fmt.Errorf("%w: CIDR %s overlaps private or link-local range %s", ErrTargetDenied, target.String(), privNet.String())
		}
	}

	return nil
}

func netsOverlap(a, b *net.IPNet) bool {
	aV4 := a.IP.To4() != nil
	bV4 := b.IP.To4() != nil
	if aV4 != bV4 {
		return false
	}

	aBase := a.IP.Mask(a.Mask)
	bBase := b.IP.Mask(b.Mask)
	return a.Contains(bBase) || b.Contains(aBase)
}

func netContainsSubnet(outer, inner *net.IPNet) bool {
	outerV4 := outer.IP.To4() != nil
	innerV4 := inner.IP.To4() != nil
	if outerV4 != innerV4 {
		return false
	}

	outerOnes, outerBits := outer.Mask.Size()
	innerOnes, innerBits := inner.Mask.Size()
	if outerBits != innerBits || outerOnes > innerOnes {
		return false
	}

	return outer.Contains(inner.IP.Mask(inner.Mask))
}
