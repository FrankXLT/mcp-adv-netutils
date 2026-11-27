package tls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

type keyUsageMapping struct {
	flag x509.KeyUsage
	name string
}

const ed25519KeyBits = ed25519.PublicKeySize * 8

var (
	keyUsageMappings = []keyUsageMapping{
		{flag: x509.KeyUsageDigitalSignature, name: "DigitalSignature"},
		{flag: x509.KeyUsageKeyEncipherment, name: "KeyEncipherment"},
		{flag: x509.KeyUsageKeyAgreement, name: "KeyAgreement"},
		{flag: x509.KeyUsageCertSign, name: "CertSign"},
		{flag: x509.KeyUsageCRLSign, name: "CRLSign"},
		{flag: x509.KeyUsageDataEncipherment, name: "DataEncipherment"},
		{flag: x509.KeyUsageContentCommitment, name: "ContentCommitment"},
	}

	extKeyUsageNames = map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "Any",
		x509.ExtKeyUsageServerAuth:                     "ServerAuth",
		x509.ExtKeyUsageClientAuth:                     "ClientAuth",
		x509.ExtKeyUsageCodeSigning:                    "CodeSigning",
		x509.ExtKeyUsageEmailProtection:                "EmailProtection",
		x509.ExtKeyUsageTimeStamping:                   "TimeStamping",
		x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
		x509.ExtKeyUsageIPSECEndSystem:                 "IPSECEndSystem",
		x509.ExtKeyUsageIPSECTunnel:                    "IPSECTunnel",
		x509.ExtKeyUsageIPSECUser:                      "IPSECUser",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "MicrosoftServerGatedCrypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "NetscapeServerGatedCrypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "MicrosoftCommercialCodeSigning",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "MicrosoftKernelCodeSigning",
	}

	cipherSuiteNames = map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:                      "TLS_RSA_WITH_RC4_128_SHA",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:                 "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:                  "TLS_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:                  "TLS_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256:               "TLS_RSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256:               "TLS_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384:               "TLS_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:              "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:          "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:          "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:                "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:           "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:       "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:         "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		tls.TLS_AES_128_GCM_SHA256:                        "TLS_AES_128_GCM_SHA256",
		tls.TLS_AES_256_GCM_SHA384:                        "TLS_AES_256_GCM_SHA384",
		tls.TLS_CHACHA20_POLY1305_SHA256:                  "TLS_CHACHA20_POLY1305_SHA256",
	}
)

func extractKeyUsage(ku x509.KeyUsage) []string {
	var keyUsage []string
	for _, mapping := range keyUsageMappings {
		if ku&mapping.flag != 0 {
			keyUsage = append(keyUsage, mapping.name)
		}
	}
	return keyUsage
}

func extractExtKeyUsage(usages []x509.ExtKeyUsage) []string {
	if len(usages) == 0 {
		return nil
	}
	extKeyUsage := make([]string, 0, len(usages))
	for _, usage := range usages {
		if name, ok := extKeyUsageNames[usage]; ok {
			extKeyUsage = append(extKeyUsage, name)
		} else {
			extKeyUsage = append(extKeyUsage, fmt.Sprintf("Unknown(%d)", usage))
		}
	}
	return extKeyUsage
}

func getTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%d)", version)
	}
}

func getCipherSuite(cipherSuite uint16) string {
	if name, ok := cipherSuiteNames[cipherSuite]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (%#x)", cipherSuite)
}

func getPublicKeySize(publicKey any) int {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if key == nil || key.N == nil {
			return 0
		}
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		if key == nil || key.Curve == nil {
			return 0
		}
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return ed25519KeyBits
	case *ed25519.PublicKey:
		if key == nil {
			return 0
		}
		return ed25519KeyBits
	default:
		return 0
	}
}
