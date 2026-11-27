package transport

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// GuardError describes a rejected transport request and wraps ErrForbidden.
type GuardError struct {
	Reason string
}

// Error returns the human-readable guard rejection reason.
func (e *GuardError) Error() string {
	return e.Reason
}

// Unwrap returns ErrForbidden so callers can test guard rejections with errors.Is.
func (e *GuardError) Unwrap() error {
	return ErrForbidden
}

const (
	maxHostnameLen = 253
	maxLabelLen    = 63
	maxTCPPort     = 65535
)

var (
	// ErrForbidden indicates a request violated a transport origin, host, or network guard.
	ErrForbidden = errors.New("forbidden")

	lanTrustedSuffixes = []string{".lan", ".local", ".internal", ".home.arpa"}

	forbiddenProxyHeaderKeys = map[string]struct{}{
		"x-real-ip":                {},
		"forwarded":                {},
		"forwarded-for":            {},
		"cf-connecting-ip":         {},
		"true-client-ip":           {},
		"cf-ray":                   {},
		"via":                      {},
		"x-client-ip":              {},
		"x-cluster-client-ip":      {},
		"x-original-forwarded-for": {},
	}
)

// ValidateLANDoorwayRequest enforces zero-trust LAN-only origin checks:
// it rejects proxy/forwarding headers, duplicate Host/Origin headers,
// non-loopback/non-RFC1918 peer IPs, and untrusted Host or Origin headers.
func ValidateLANDoorwayRequest(r *http.Request) error {
	if r == nil {
		return newGuardError("request must not be nil")
	}
	if hasProxyHeader(r.Header) {
		return newGuardError("proxy forwarding headers are forbidden on LAN doorway")
	}

	reqHost, originRaw, err := extractHostAndOrigin(r)
	if err != nil {
		return err
	}

	peerIP, ok := parsePeerIP(r.RemoteAddr)
	if !ok || !isPrivateOrLoopbackIP(peerIP) {
		return newGuardError("remote peer IP is not loopback or private")
	}

	hostName, _, ok := splitHostAndPort(reqHost)
	if !ok || !isTrustedLANHost(hostName) {
		return newGuardError("Host header is not a trusted LAN address")
	}

	if originRaw != "" {
		originURL, validOrigin := parseOriginHeader(originRaw)
		if !validOrigin {
			return newGuardError("Origin header is invalid")
		}
		originHost, _, validHost := splitHostAndPort(originURL.Host)
		if !validHost || !isTrustedLANHost(originHost) {
			return newGuardError("Origin header is not a trusted LAN origin")
		}
	}

	return nil
}

// ValidateWebRequest enforces anti-DNS-rebinding and anti-CSRF checks for /web and /web/api/*.
func ValidateWebRequest(r *http.Request, allowedHosts []string) error {
	if r == nil {
		return newGuardError("request must not be nil")
	}

	reqHost, originRaw, err := extractHostAndOrigin(r)
	if err != nil {
		return err
	}

	secFetchSites := headerValuesIgnoreCase(r.Header, "Sec-Fetch-Site")
	if len(secFetchSites) > 1 {
		return newGuardError("duplicate Sec-Fetch-Site headers are forbidden")
	}
	xfHosts := headerValuesIgnoreCase(r.Header, "X-Forwarded-Host")
	if len(xfHosts) > 1 {
		return newGuardError("duplicate X-Forwarded-Host headers are forbidden")
	}
	xfProtos := headerValuesIgnoreCase(r.Header, "X-Forwarded-Proto")
	if len(xfProtos) > 1 {
		return newGuardError("duplicate X-Forwarded-Proto headers are forbidden")
	}

	hostName, hostPort, ok := parsePermittedHostPort(reqHost, allowedHosts)
	if !ok {
		return newGuardError("Host header is not permitted")
	}

	var xfHost, xfPort string
	if len(xfHosts) == 1 {
		xfHost, xfPort, ok = splitHostAndPort(strings.TrimSpace(xfHosts[0]))
		if !ok || !isAllowedHost(xfHost, xfPort, allowedHosts) {
			return newGuardError("X-Forwarded-Host header is not permitted")
		}
	}

	var originURL *url.URL
	var originHost, originPort string
	if originRaw != "" {
		originURL, ok = parseOriginHeader(originRaw)
		if !ok {
			return newGuardError("Origin header is invalid")
		}
		originHost, originPort, ok = parsePermittedHostPort(originURL.Host, allowedHosts)
		if !ok {
			return newGuardError("Origin host is not permitted")
		}
	}

	if isStateChangingMethod(r.Method) {
		if len(secFetchSites) == 1 && !isAllowedFetchSite(secFetchSites[0]) {
			return newGuardError("cross-site fetch metadata rejected")
		}
		allowedProxyHost := xfHost != "" || isAllowedHost(hostName, hostPort, allowedHosts)
		if originURL != nil && !isSameOrProxyOrigin(r, originURL, originHost, originPort, hostName, hostPort, xfHost, xfPort, allowedProxyHost) {
			return newGuardError("cross-origin state-changing request rejected")
		}
	}

	return nil
}

// VerifyPathToken compares got against expected in constant time using SHA-256 digests
// and crypto/subtle.ConstantTimeCompare. Empty inputs always return false.
func VerifyPathToken(got, expected string) bool {
	if got == "" || expected == "" {
		return false
	}
	gotSum := sha256.Sum256([]byte(got))
	expectedSum := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(gotSum[:], expectedSum[:]) == 1
}

func newGuardError(reason string) error {
	return &GuardError{Reason: reason}
}

func hasProxyHeader(h http.Header) bool {
	for k := range h {
		lower := strings.ToLower(strings.TrimSpace(k))
		if strings.HasPrefix(lower, "x-forwarded") {
			return true
		}
		if _, forbidden := forbiddenProxyHeaderKeys[lower]; forbidden {
			return true
		}
	}
	return false
}

func extractHostAndOrigin(r *http.Request) (string, string, error) {
	hostVals := headerValuesIgnoreCase(r.Header, "Host")
	if len(hostVals) > 1 {
		return "", "", newGuardError("duplicate Host headers are forbidden")
	}

	reqHost := strings.TrimSpace(r.Host)
	if len(hostVals) == 1 {
		hdrHost := strings.TrimSpace(hostVals[0])
		if reqHost != "" && !strings.EqualFold(reqHost, hdrHost) {
			return "", "", newGuardError("conflicting Host header values")
		}
		if reqHost == "" {
			reqHost = hdrHost
		}
	}
	if reqHost == "" {
		return "", "", newGuardError("Host header is required")
	}

	originVals := headerValuesIgnoreCase(r.Header, "Origin")
	if len(originVals) > 1 {
		return "", "", newGuardError("duplicate Origin headers are forbidden")
	}

	var originRaw string
	if len(originVals) == 1 {
		originRaw = originVals[0]
		if strings.TrimSpace(originRaw) == "" || strings.EqualFold(strings.TrimSpace(originRaw), "null") {
			return "", "", newGuardError("Origin null or empty is forbidden")
		}
	}
	return reqHost, originRaw, nil
}

func headerValuesIgnoreCase(h http.Header, target string) []string {
	var vals []string
	for k, v := range h {
		if strings.EqualFold(k, target) {
			vals = append(vals, v...)
		}
	}
	return vals
}

func parsePeerIP(remoteAddr string) (netip.Addr, bool) {
	trimmed := strings.TrimSpace(remoteAddr)
	if trimmed == "" {
		return netip.Addr{}, false
	}
	if ap, err := netip.ParseAddrPort(trimmed); err == nil {
		return ap.Addr().Unmap(), true
	}
	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		if addr, parseErr := netip.ParseAddr(host); parseErr == nil {
			return addr.Unmap(), true
		}
		return netip.Addr{}, false
	}
	if addr, parseErr := netip.ParseAddr(trimmed); parseErr == nil {
		return addr.Unmap(), true
	}
	return netip.Addr{}, false
}

func isPrivateOrLoopbackIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	unmapped := addr.Unmap()
	return unmapped.IsLoopback() || unmapped.IsPrivate()
}

func parsePermittedHostPort(raw string, allowedHosts []string) (string, string, bool) {
	host, port, ok := splitHostAndPort(raw)
	if !ok {
		return "", "", false
	}
	if !isTrustedLANHost(host) && !isAllowedHost(host, port, allowedHosts) {
		return "", "", false
	}
	return host, port, true
}

func splitHostAndPort(hostPort string) (string, string, bool) {
	if hostPort == "" || strings.ContainsAny(hostPort, " \t\r\n@/?#\\") {
		return "", "", false
	}

	if strings.HasPrefix(hostPort, "[") {
		var host, port string
		if len(hostPort) >= 2 && strings.HasSuffix(hostPort, "]") {
			host = hostPort[1 : len(hostPort)-1]
		} else {
			var err error
			host, port, err = net.SplitHostPort(hostPort)
			if err != nil || !isValidTCPPort(port) {
				return "", "", false
			}
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return "", "", false
		}
		return addr.String(), port, true
	}

	switch strings.Count(hostPort, ":") {
	case 0:
		return hostPort, "", true
	case 1:
		host, port, err := net.SplitHostPort(hostPort)
		if err != nil || host == "" || !isValidTCPPort(port) {
			return "", "", false
		}
		return host, port, true
	default:
		return "", "", false
	}
}

func isValidTCPPort(port string) bool {
	if !isASCIIAllDigits(port) {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= maxTCPPort
}

func isTrustedLANHost(host string) bool {
	if host == "" {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return isPrivateOrLoopbackIP(addr)
	}
	if !isValidDNSName(host) {
		return false
	}

	lower := strings.ToLower(host)
	if lower == "localhost" {
		return true
	}
	if !strings.Contains(lower, ".") {
		return !isASCIIAllDigits(lower) && !isASCIIHexLiteral(lower)
	}
	for _, suffix := range lanTrustedSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func isValidDNSName(host string) bool {
	if host == "" || len(host) > maxHostnameLen || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !isValidDNSLabel(label) {
			return false
		}
	}
	return true
}

func isValidDNSLabel(label string) bool {
	if label == "" || len(label) > maxLabelLen || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := range len(label) {
		ch := label[i]
		if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '-' {
			return false
		}
	}
	return true
}

func isASCIIAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isASCIIHexLiteral(s string) bool {
	if len(s) < 3 || !strings.HasPrefix(s, "0x") {
		return false
	}
	for i := 2; i < len(s); i++ {
		ch := s[i]
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func parseOriginHeader(raw string) (*url.URL, bool) {
	if raw == "" || strings.ContainsAny(raw, " \t\r\n@\\") || strings.EqualFold(raw, "null") {
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" {
		return nil, false
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return nil, false
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, false
	}
	return u, true
}

func isAllowedHost(host, port string, allowedHosts []string) bool {
	for _, entry := range allowedHosts {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" || trimmed == "*" {
			continue
		}
		if strings.HasPrefix(trimmed, "*.") {
			suffix := strings.ToLower(trimmed[1:])
			if isValidDNSName(suffix[1:]) && isValidDNSName(host) && strings.HasSuffix(strings.ToLower(host), suffix) && len(host) > len(suffix) {
				return true
			}
			continue
		}
		allowedName, allowedPort, ok := splitHostAndPort(trimmed)
		if ok && hostsEqual(host, allowedName) && (allowedPort == "" || allowedPort == port) {
			return true
		}
	}
	return false
}

func hostsEqual(a, b string) bool {
	addrA, errA := netip.ParseAddr(a)
	addrB, errB := netip.ParseAddr(b)
	if errA == nil && errB == nil {
		return addrA.Unmap() == addrB.Unmap()
	}
	return strings.EqualFold(a, b)
}

func isStateChangingMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func isAllowedFetchSite(val string) bool {
	trimmed := strings.TrimSpace(val)
	return strings.EqualFold(trimmed, "same-origin") || strings.EqualFold(trimmed, "none")
}

func isSameOrProxyOrigin(
	r *http.Request,
	originURL *url.URL,
	originHost, originPort, hostName, hostPort, xfHost, xfPort string,
	allowedProxyHost bool,
) bool {
	httpsReq := isHTTPSRequest(r, allowedProxyHost)
	if xfHost != "" {
		return originMatchesHostPort(originURL.Scheme, originHost, originPort, xfHost, xfPort, httpsReq)
	}
	return originMatchesHostPort(originURL.Scheme, originHost, originPort, hostName, hostPort, httpsReq)
}

func originMatchesHostPort(originScheme, originHost, originPort, reqHost, reqPort string, httpsReq bool) bool {
	if !hostsEqual(originHost, reqHost) {
		return false
	}
	expectedScheme := "http"
	if httpsReq {
		expectedScheme = "https"
	}
	if !strings.EqualFold(originScheme, expectedScheme) {
		return false
	}
	if originPort == "" && reqPort == "" {
		return true
	}
	effOriginPort := originPort
	if effOriginPort == "" {
		effOriginPort = defaultSchemePort(originScheme)
	}
	effReqPort := reqPort
	if effReqPort == "" {
		effReqPort = defaultSchemePort(expectedScheme)
	}
	return effOriginPort == effReqPort
}

func defaultSchemePort(scheme string) string {
	if strings.EqualFold(scheme, "https") {
		return "443"
	}
	return "80"
}

func isHTTPSRequest(r *http.Request, allowedProxyHost bool) bool {
	if r.TLS != nil {
		return true
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		return false
	}
	if allowedProxyHost {
		return true
	}
	if strings.TrimSpace(r.Header.Get("X-Forwarded-Host")) == "" {
		peerIP, ok := parsePeerIP(r.RemoteAddr)
		return ok && isPrivateOrLoopbackIP(peerIP)
	}
	return false
}
