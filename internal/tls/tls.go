package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	resp "github.com/FrankXLT/mcp-adv-netutils/internal/response"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/utils"
	"github.com/mark3labs/mcp-go/mcp"
)

// Config holds TLS certificate checking configuration.
type Config struct {
	Timeout time.Duration
	Port    int
	Guard   *security.TargetGuard
	RootCAs *x509.CertPool
}

// TLSCheckParams represents the parameters for TLS certificate checks.
type TLSCheckParams struct {
	Domain       string `json:"domain"`
	Port         int    `json:"port,omitempty"`
	IncludeChain *bool  `json:"include_chain,omitempty"`
	CheckExpiry  *bool  `json:"check_expiry,omitempty"`
	ServerName   string `json:"server_name,omitempty"`
}

// CertificateInfo represents detailed information about a certificate.
type CertificateInfo struct {
	Subject            string            `json:"subject"`
	Issuer             string            `json:"issuer"`
	SerialNumber       string            `json:"serial_number"`
	NotBefore          time.Time         `json:"not_before"`
	NotAfter           time.Time         `json:"not_after"`
	IsExpired          bool              `json:"is_expired"`
	ExpiresInDays      int               `json:"expires_in_days"`
	DNSNames           []string          `json:"dns_names"`
	IPAddresses        []string          `json:"ip_addresses"`
	EmailAddresses     []string          `json:"email_addresses"`
	URIs               []string          `json:"uris"`
	KeyUsage           []string          `json:"key_usage"`
	ExtKeyUsage        []string          `json:"ext_key_usage"`
	SignatureAlgorithm string            `json:"signature_algorithm"`
	PublicKeyAlgorithm string            `json:"public_key_algorithm"`
	PublicKeySize      int               `json:"public_key_size"`
	Version            int               `json:"version"`
	IsCA               bool              `json:"is_ca"`
	IsSelfSigned       bool              `json:"is_self_signed"`
	Extensions         map[string]string `json:"extensions"`
}

// CheckResult represents the result of a TLS certificate check.
type CheckResult struct {
	Domain           string            `json:"domain"`
	Port             int               `json:"port"`
	ServerName       string            `json:"server_name"`
	TLSVersion       string            `json:"tls_version"`
	CipherSuite      string            `json:"cipher_suite"`
	PeerCertificates []CertificateInfo `json:"peer_certificates"`
	ChainValid       bool              `json:"chain_valid"`
	ChainErrors      []string          `json:"chain_errors,omitempty"`
	ConnectionInfo   map[string]string `json:"connection_info"`
	Warnings         []string          `json:"warnings,omitempty"`
	CheckedAt        time.Time         `json:"checked_at"`
}

const (
	defaultTimeout    = 10 * time.Second
	defaultPort       = 443
	minPort           = 1
	maxPort           = 65535
	expiryWarningDays = 30
	hoursPerDay       = 24
)

// HandleTLSCheck processes TLS certificate check MCP tool requests.
//
//nolint:gocritic // Exported handler mirrors mcp-go ToolHandlerFunc value parameter.
func HandleTLSCheck(ctx context.Context, request mcp.CallToolRequest, config *Config) (*mcp.CallToolResult, error) {
	var params TLSCheckParams
	if err := request.BindArguments(&params); err != nil {
		return nil, fmt.Errorf("failed to parse tool input: %w", utils.ParseJSONUnmarshalError(err))
	}

	result, err := Execute(ctx, params, config)
	if err != nil {
		return nil, err
	}

	out, err := resp.JSON(result)
	if err != nil {
		return nil, fmt.Errorf("failed to encode TLS check result: %w", err)
	}

	return out, nil
}

// Execute validates parameters, enforces TargetGuard if configured, and inspects the target TLS certificate chain.
func Execute(ctx context.Context, params TLSCheckParams, cfg *Config) (*CheckResult, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("request context error: %w", err)
	}

	domain := strings.TrimSpace(params.Domain)
	if domain == "" {
		return nil, errors.New("parameter \"domain\" is required")
	}
	if strings.Contains(domain, "..") || strings.HasPrefix(domain, ".") {
		return nil, fmt.Errorf("invalid domain format: %q", domain)
	}

	port := resolvePort(params.Port, cfg)
	if port < minPort || port > maxPort {
		return nil, fmt.Errorf("invalid port %d: must be between %d and %d", port, minPort, maxPort)
	}

	serverName := strings.TrimSpace(params.ServerName)
	if serverName == "" {
		serverName = domain
	}

	includeChain := true
	if params.IncludeChain != nil {
		includeChain = *params.IncludeChain
	}

	checkExpiry := true
	if params.CheckExpiry != nil {
		checkExpiry = *params.CheckExpiry
	}

	timeout := defaultTimeout
	if cfg != nil && cfg.Timeout > 0 {
		timeout = cfg.Timeout
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	guard, err := resolveGuard(cfg)
	if err != nil {
		return nil, err
	}
	if _, err := guard.ValidateHostOrIP(execCtx, domain); err != nil {
		return nil, fmt.Errorf("target validation failed: %w", err)
	}

	result, err := checkTLSCertificate(execCtx, domain, port, serverName, cfg, timeout, includeChain, checkExpiry)
	if err != nil {
		return nil, fmt.Errorf("TLS check failed: %w", err)
	}

	return result, nil
}

func resolveGuard(cfg *Config) (*security.TargetGuard, error) {
	if cfg != nil && cfg.Guard != nil {
		return cfg.Guard, nil
	}
	guard, err := security.NewTargetGuard(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize target guard: %w", err)
	}
	return guard, nil
}

func resolvePort(paramPort int, cfg *Config) int {
	if paramPort != 0 {
		return paramPort
	}
	if cfg != nil && cfg.Port > 0 {
		return cfg.Port
	}
	return defaultPort
}

// checkTLSCertificate performs strict TLS inspection first and falls back to metadata extraction on cert validation failure.
func checkTLSCertificate(
	ctx context.Context,
	domain string,
	port int,
	serverName string,
	cfg *Config,
	timeout time.Duration,
	includeChain bool,
	checkExpiry bool,
) (*CheckResult, error) {
	result, err := attemptTLSConnection(ctx, domain, port, serverName, cfg, timeout, includeChain, checkExpiry, false)
	if err == nil {
		return result, nil
	}

	if !isCertificateValidationError(err) {
		return nil, err
	}

	debugResult, debugErr := attemptTLSConnection(ctx, domain, port, serverName, cfg, timeout, includeChain, checkExpiry, true)
	if debugErr != nil {
		return nil, err
	}

	debugResult.ChainValid = false
	if len(debugResult.ChainErrors) == 0 {
		debugResult.ChainErrors = []string{err.Error()}
	}
	debugResult.Warnings = append(debugResult.Warnings, "Certificate validation failed - details retrieved with verification disabled")

	return debugResult, nil
}

// attemptTLSConnection connects via TargetGuard.DialContext, performs a TLS handshake with ServerName preserved, verifies peer certificates, and builds CheckResult.
func attemptTLSConnection(
	ctx context.Context,
	domain string,
	port int,
	serverName string,
	cfg *Config,
	timeout time.Duration,
	includeChain bool,
	checkExpiry bool,
	forceSkipVerify bool,
) (*CheckResult, error) {
	roots, rootWarnings := resolveRootCAs(cfg)
	guard, err := resolveGuard(cfg)
	if err != nil {
		return nil, err
	}

	dialCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	tlsConfig := &tls.Config{
		ServerName: serverName,
		// #nosec G402 -- forceSkipVerify is only enabled in diagnostic fallback after strict validation fails; ChainValid stays false.
		InsecureSkipVerify: forceSkipVerify,
	}
	if !forceSkipVerify {
		tlsConfig.RootCAs = roots
	}

	addr := net.JoinHostPort(domain, strconv.Itoa(port))
	rawConn, err := guard.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	defer func() {
		_ = tlsConn.Close()
	}()

	state := tlsConn.ConnectionState()
	peerCerts, warnings := collectPeerCertInfo(state.PeerCertificates, includeChain, checkExpiry)
	warnings = append(rootWarnings, warnings...)

	chainValid, chainErrors := verifyCertificateChain(state.PeerCertificates, roots, serverName, forceSkipVerify)

	connectionInfo := map[string]string{
		"negotiated_protocol": state.NegotiatedProtocol,
		"handshake_complete":  strconv.FormatBool(state.HandshakeComplete),
		"mutual_tls":          strconv.FormatBool(false),
	}

	return &CheckResult{
		Domain:           domain,
		Port:             port,
		ServerName:       serverName,
		TLSVersion:       getTLSVersion(state.Version),
		CipherSuite:      getCipherSuite(state.CipherSuite),
		PeerCertificates: peerCerts,
		ChainValid:       chainValid,
		ChainErrors:      chainErrors,
		ConnectionInfo:   connectionInfo,
		Warnings:         warnings,
		CheckedAt:        time.Now(),
	}, nil
}

func resolveRootCAs(cfg *Config) (*x509.CertPool, []string) {
	if cfg != nil && cfg.RootCAs != nil {
		return cfg.RootCAs, nil
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return x509.NewCertPool(), []string{
			fmt.Sprintf("Failed to load system root certificates: %v", err),
		}
	}

	if roots == nil {
		return x509.NewCertPool(), []string{
			"System root certificate pool was empty",
		}
	}

	return roots, nil
}

func collectPeerCertInfo(certs []*x509.Certificate, includeChain, checkExpiry bool) ([]CertificateInfo, []string) {
	if len(certs) == 0 {
		return []CertificateInfo{}, nil
	}

	limit := 1
	if includeChain {
		limit = len(certs)
	}

	peerCerts := make([]CertificateInfo, 0, limit)
	var warnings []string

	for i := range limit {
		certInfo := processCertificate(certs[i])
		peerCerts = append(peerCerts, certInfo)

		if i == 0 && checkExpiry {
			warnings = append(warnings, leafCertificateWarnings(&certInfo)...)
		}
	}

	return peerCerts, warnings
}

func leafCertificateWarnings(certInfo *CertificateInfo) []string {
	var warnings []string
	if certInfo.IsExpired {
		warnings = append(warnings, "Server certificate is expired")
	} else if certInfo.ExpiresInDays <= expiryWarningDays {
		warnings = append(warnings, fmt.Sprintf("Server certificate expires in %d days", certInfo.ExpiresInDays))
	}

	if certInfo.IsSelfSigned {
		warnings = append(warnings, "Server certificate is self-signed")
	}

	return warnings
}

func verifyCertificateChain(certs []*x509.Certificate, roots *x509.CertPool, serverName string, forceSkipVerify bool) (bool, []string) {
	if len(certs) == 0 {
		return false, []string{"no peer certificates presented by server"}
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		DNSName:       serverName,
		Intermediates: intermediates,
	}

	if _, err := certs[0].Verify(opts); err != nil {
		return false, []string{err.Error()}
	}

	if forceSkipVerify {
		return false, nil
	}

	return true, nil
}

// isCertificateValidationError checks if the error is related to certificate validation.
func isCertificateValidationError(err error) bool {
	if err == nil {
		return false
	}

	var (
		tlsVerifyErr   *tls.CertificateVerificationError
		invalidErr     x509.CertificateInvalidError
		unknownAuthErr x509.UnknownAuthorityError
		hostnameErr    x509.HostnameError
		sysRootsErr    x509.SystemRootsError
	)
	if errors.As(err, &tlsVerifyErr) ||
		errors.As(err, &invalidErr) ||
		errors.As(err, &unknownAuthErr) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &sysRootsErr) {
		return true
	}

	errStr := err.Error()
	return strings.Contains(errStr, "certificate has expired") ||
		strings.Contains(errStr, "certificate is not yet valid") ||
		strings.Contains(errStr, "certificate signed by unknown authority") ||
		strings.Contains(errStr, "certificate is not valid for") ||
		strings.Contains(errStr, "failed to verify certificate") ||
		strings.Contains(errStr, "x509:")
}

// processCertificate extracts detailed information from a certificate.
func processCertificate(cert *x509.Certificate) CertificateInfo {
	if cert == nil {
		return CertificateInfo{}
	}

	now := time.Now()
	expiresInDays := int(cert.NotAfter.Sub(now).Hours() / hoursPerDay)

	ipAddresses := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ipAddresses = append(ipAddresses, ip.String())
	}

	uris := make([]string, 0, len(cert.URIs))
	for _, uri := range cert.URIs {
		uris = append(uris, uri.String())
	}

	extensions := make(map[string]string, len(cert.Extensions))
	for i := range cert.Extensions {
		ext := &cert.Extensions[i]
		extensions[ext.Id.String()] = fmt.Sprintf("Critical: %v", ext.Critical)
	}

	serial := ""
	if cert.SerialNumber != nil {
		serial = cert.SerialNumber.String()
	}

	isSelfSigned := cert.Subject.String() == cert.Issuer.String() && cert.CheckSignatureFrom(cert) == nil

	return CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       serial,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		IsExpired:          now.After(cert.NotAfter),
		ExpiresInDays:      expiresInDays,
		DNSNames:           cert.DNSNames,
		IPAddresses:        ipAddresses,
		EmailAddresses:     cert.EmailAddresses,
		URIs:               uris,
		KeyUsage:           extractKeyUsage(cert.KeyUsage),
		ExtKeyUsage:        extractExtKeyUsage(cert.ExtKeyUsage),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeySize:      getPublicKeySize(cert.PublicKey),
		Version:            cert.Version,
		IsCA:               cert.IsCA,
		IsSelfSigned:       isSelfSigned,
		Extensions:         extensions,
	}
}
