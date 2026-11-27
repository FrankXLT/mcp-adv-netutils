package tls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startLoopbackTLSServer(t *testing.T, certs []tls.Certificate) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: certs, MinVersion: tls.VersionTLS12})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, acceptErr := tlsLn.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				if tlsConn, ok := c.(*tls.Conn); ok {
					_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
					_ = tlsConn.Handshake()
				}
			}(conn)
		}
	}()

	t.Cleanup(func() {
		_ = tlsLn.Close()
		wg.Wait()
	})

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	require.True(t, ok)
	return tcpAddr.Port
}

func startHTTPTestTLSServer(t *testing.T) (*httptest.Server, string, int) {
	t.Helper()

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	parsedURL, err := url.Parse(srv.URL)
	require.NoError(t, err)
	host, portStr, err := net.SplitHostPort(parsedURL.Host)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return srv, host, port
}

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func createTestCert(
	t *testing.T,
	subject pkix.Name,
	key crypto.Signer,
	parent *x509.Certificate,
	parentKey crypto.Signer,
	isCA bool,
	ips []net.IP,
	dnsNames []string,
) (*x509.Certificate, []byte) {
	t.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	require.NoError(t, err)

	now := time.Now().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              now.Add(48 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		IPAddresses:           ips,
		DNSNames:              dnsNames,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	signingCert, signingKey := tmpl, key
	if parent != nil && parentKey != nil {
		signingCert, signingKey = parent, parentKey
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, signingCert, key.Public(), signingKey)
	require.NoError(t, err)

	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return parsed, der
}

func TestExecute_TrustedCAAndIntermediateChain(t *testing.T) {
	t.Parallel()

	rootKey := newECDSAKey(t)
	rootCert, _ := createTestCert(t, pkix.Name{CommonName: "Test Root CA"}, rootKey, nil, nil, true, nil, nil)

	interKey := newECDSAKey(t)
	interCert, interDER := createTestCert(t, pkix.Name{CommonName: "Test Intermediate CA"}, interKey, rootCert, rootKey, true, nil, nil)

	leafKey := newECDSAKey(t)
	leafCert, leafDER := createTestCert(t, pkix.Name{CommonName: "127.0.0.1"}, leafKey, interCert, interKey, false, []net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"})

	port := startLoopbackTLSServer(t, []tls.Certificate{{Certificate: [][]byte{leafDER, interDER}, PrivateKey: leafKey, Leaf: leafCert}})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	cfg := &Config{Timeout: 5 * time.Second, RootCAs: rootPool}

	result, err := Execute(context.Background(), TLSCheckParams{Domain: "127.0.0.1", Port: port}, cfg)
	require.NoError(t, err)
	assert.True(t, result.ChainValid)
	assert.Empty(t, result.ChainErrors)
	require.Len(t, result.PeerCertificates, 2)
	assert.Equal(t, 256, result.PeerCertificates[0].PublicKeySize)
	assert.False(t, result.PeerCertificates[0].IsSelfSigned)
	assert.False(t, result.PeerCertificates[0].IsCA)
	assert.True(t, result.PeerCertificates[1].IsCA)
	assert.False(t, result.PeerCertificates[1].IsSelfSigned)

	includeChain := false
	leafOnly, err := Execute(context.Background(), TLSCheckParams{Domain: "127.0.0.1", Port: port, IncludeChain: &includeChain}, cfg)
	require.NoError(t, err)
	assert.True(t, leafOnly.ChainValid)
	assert.Len(t, leafOnly.PeerCertificates, 1)
}

func TestExecute_UntrustedIntermediateNotAddedToRoots(t *testing.T) {
	t.Parallel()

	trustedRootKey := newECDSAKey(t)
	trustedRoot, _ := createTestCert(t, pkix.Name{CommonName: "Trusted Root"}, trustedRootKey, nil, nil, true, nil, nil)

	rogueInterKey := newECDSAKey(t)
	rogueInter, rogueInterDER := createTestCert(t, pkix.Name{CommonName: "Rogue Intermediate"}, rogueInterKey, nil, nil, true, nil, nil)

	leafKey := newECDSAKey(t)
	leafCert, leafDER := createTestCert(t, pkix.Name{CommonName: "127.0.0.1"}, leafKey, rogueInter, rogueInterKey, false, []net.IP{net.ParseIP("127.0.0.1")}, nil)

	port := startLoopbackTLSServer(t, []tls.Certificate{{Certificate: [][]byte{leafDER, rogueInterDER}, PrivateKey: leafKey, Leaf: leafCert}})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(trustedRoot)

	result, err := Execute(context.Background(), TLSCheckParams{Domain: "127.0.0.1", Port: port}, &Config{Timeout: 5 * time.Second, RootCAs: rootPool})
	require.NoError(t, err)
	assert.False(t, result.ChainValid)
	assert.NotEmpty(t, result.ChainErrors)
	assert.Len(t, result.PeerCertificates, 2)
}

func TestExecute_SelfSignedUntrustedCert(t *testing.T) {
	t.Parallel()

	t.Run("custom self-signed cert reports IsSelfSigned and invalid chain", func(t *testing.T) {
		t.Parallel()

		key := newECDSAKey(t)
		cert, der := createTestCert(t, pkix.Name{CommonName: "self.example.local"}, key, nil, nil, true, []net.IP{net.ParseIP("127.0.0.1")}, nil)
		port := startLoopbackTLSServer(t, []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}})

		result, err := Execute(context.Background(), TLSCheckParams{Domain: "127.0.0.1", Port: port}, &Config{
			Timeout: 5 * time.Second,
			RootCAs: x509.NewCertPool(),
		})
		require.NoError(t, err)
		assert.False(t, result.ChainValid)
		require.NotEmpty(t, result.ChainErrors)
		assert.Contains(t, result.ChainErrors[0], "x509:")
		require.Len(t, result.PeerCertificates, 1)
		assert.True(t, result.PeerCertificates[0].IsSelfSigned)
		assert.Contains(t, result.Warnings, "Server certificate is self-signed")
		assert.Contains(t, result.Warnings, "Certificate validation failed - details retrieved with verification disabled")
	})

	t.Run("httptest TLS server untrusted vs trusted", func(t *testing.T) {
		t.Parallel()

		srv, host, port := startHTTPTestTLSServer(t)

		untrustedRes, err := Execute(context.Background(), TLSCheckParams{Domain: host, Port: port}, &Config{
			Timeout: 5 * time.Second,
			RootCAs: x509.NewCertPool(),
		})
		require.NoError(t, err)
		assert.False(t, untrustedRes.ChainValid)
		assert.NotEmpty(t, untrustedRes.ChainErrors)

		trustedPool := x509.NewCertPool()
		trustedPool.AddCert(srv.Certificate())
		trustedRes, err := Execute(context.Background(), TLSCheckParams{Domain: host, Port: port}, &Config{
			Timeout: 5 * time.Second,
			RootCAs: trustedPool,
		})
		require.NoError(t, err)
		assert.True(t, trustedRes.ChainValid)
		assert.Empty(t, trustedRes.ChainErrors)
	})
}

func TestExecute_Ed25519CertificateKeySize(t *testing.T) {
	t.Parallel()

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cert, der := createTestCert(t, pkix.Name{CommonName: "ed25519.local"}, privKey, nil, nil, true, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	port := startLoopbackTLSServer(t, []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privKey, Leaf: cert}})

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	result, err := Execute(context.Background(), TLSCheckParams{Domain: "127.0.0.1", Port: port}, &Config{Timeout: 5 * time.Second, RootCAs: pool})
	require.NoError(t, err)
	assert.True(t, result.ChainValid)
	require.Len(t, result.PeerCertificates, 1)
	assert.Equal(t, 256, result.PeerCertificates[0].PublicKeySize)
	assert.Equal(t, "Ed25519", result.PeerCertificates[0].PublicKeyAlgorithm)
}

func TestExecute_TargetGuardBlocks(t *testing.T) {
	t.Parallel()

	defaultGuard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)

	_, err = Execute(context.Background(), TLSCheckParams{Domain: "169.254.169.254", Port: 443}, &Config{Timeout: 2 * time.Second, Guard: defaultGuard})
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrTargetDenied)

	key := newECDSAKey(t)
	cert, der := createTestCert(t, pkix.Name{CommonName: "loopback"}, key, nil, nil, true, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	port := startLoopbackTLSServer(t, []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}})

	privateGuard, err := security.NewTargetGuardWithOptions(nil, nil, true)
	require.NoError(t, err)

	_, err = Execute(context.Background(), TLSCheckParams{Domain: "127.0.0.1", Port: port}, &Config{Timeout: 2 * time.Second, Guard: privateGuard})
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrTargetDenied)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	allowedRes, err := Execute(context.Background(), TLSCheckParams{Domain: "127.0.0.1", Port: port}, &Config{
		Timeout: 2 * time.Second,
		Guard:   defaultGuard,
		RootCAs: pool,
	})
	require.NoError(t, err)
	assert.True(t, allowedRes.ChainValid)
}

func TestExecute_ContextCancellationAndTimeout(t *testing.T) {
	t.Parallel()

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Execute(cancelledCtx, TLSCheckParams{Domain: "127.0.0.1", Port: 443}, &Config{Timeout: time.Second})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	stalledDone := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				defer func() { _ = conn.Close() }()
				<-stalledDone
			}(c)
		}
	}()
	t.Cleanup(func() {
		close(stalledDone)
		_ = ln.Close()
		wg.Wait()
	})

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	require.True(t, ok)

	shortCtx, shortCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer shortCancel()

	_, err = Execute(shortCtx, TLSCheckParams{Domain: "127.0.0.1", Port: tcpAddr.Port}, &Config{Timeout: 5 * time.Second})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestProcessCertificate_SpoofedIssuerNotSelfSigned(t *testing.T) {
	t.Parallel()

	caKey := newECDSAKey(t)
	caName := pkix.Name{CommonName: "Shared CN"}
	caCert, _ := createTestCert(t, caName, caKey, nil, nil, true, nil, nil)

	leafKey := newECDSAKey(t)
	spoofedLeaf, _ := createTestCert(t, caName, leafKey, caCert, caKey, false, []net.IP{net.ParseIP("127.0.0.1")}, nil)

	info := processCertificate(spoofedLeaf)
	assert.Equal(t, info.Subject, info.Issuer)
	assert.False(t, info.IsSelfSigned)
}

func TestVerifyCertificateChain_EmptyAndForceSkipVerify(t *testing.T) {
	t.Parallel()

	valid, errs := verifyCertificateChain(nil, x509.NewCertPool(), "localhost", false)
	assert.False(t, valid)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0], "no peer certificates")

	key := newECDSAKey(t)
	cert, der := createTestCert(t, pkix.Name{CommonName: "skipverify.local"}, key, nil, nil, true, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	port := startLoopbackTLSServer(t, []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}})

	res, err := attemptTLSConnection(
		context.Background(),
		"127.0.0.1",
		port,
		"127.0.0.1",
		&Config{Timeout: 2 * time.Second, RootCAs: x509.NewCertPool()},
		2*time.Second,
		true,
		true,
		true,
	)
	require.NoError(t, err)
	assert.False(t, res.ChainValid)
	assert.NotEmpty(t, res.ChainErrors)
}

func TestGetPublicKeySize(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ec256Key := newECDSAKey(t)
	ec384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	assert.Equal(t, 2048, getPublicKeySize(&rsaKey.PublicKey))
	assert.Equal(t, 256, getPublicKeySize(&ec256Key.PublicKey))
	assert.Equal(t, 384, getPublicKeySize(&ec384Key.PublicKey))
	assert.Equal(t, 256, getPublicKeySize(edPub))
	assert.Equal(t, 256, getPublicKeySize(&edPub))
	assert.Equal(t, 0, getPublicKeySize((*rsa.PublicKey)(nil)))
	assert.Equal(t, 0, getPublicKeySize((*ecdsa.PublicKey)(nil)))
	assert.Equal(t, 0, getPublicKeySize((*ed25519.PublicKey)(nil)))
	assert.Equal(t, 0, getPublicKeySize("unsupported"))
}

func TestHandleTLSCheck_MCPAndValidation(t *testing.T) {
	t.Parallel()

	srv, host, port := startHTTPTestTLSServer(t)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{Arguments: map[string]any{"domain": host, "port": port}},
	}

	toolRes, err := HandleTLSCheck(context.Background(), req, &Config{Timeout: 5 * time.Second, RootCAs: pool})
	require.NoError(t, err)
	require.NotNil(t, toolRes)
	require.Len(t, toolRes.Content, 1)

	textContent, ok := toolRes.Content[0].(mcp.TextContent)
	require.True(t, ok)

	var checkRes CheckResult
	require.NoError(t, json.Unmarshal([]byte(textContent.Text), &checkRes))
	assert.Equal(t, host, checkRes.Domain)
	assert.Equal(t, port, checkRes.Port)
	assert.True(t, checkRes.ChainValid)
	assert.NotEmpty(t, checkRes.PeerCertificates)

	_, err = Execute(context.Background(), TLSCheckParams{}, nil)
	require.Error(t, err)
	_, err = Execute(context.Background(), TLSCheckParams{Domain: "..bad.example"}, nil)
	require.Error(t, err)
	_, err = Execute(context.Background(), TLSCheckParams{Domain: "example.com", Port: 70000}, nil)
	require.Error(t, err)
	//nolint:staticcheck // Intentionally testing nil context guard.
	_, err = Execute(nil, TLSCheckParams{Domain: "example.com"}, nil)
	require.Error(t, err)
}
