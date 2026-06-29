package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// CA represents a Certificate Authority that issues short-lived client certificates.
type CA struct {
	caCert       *x509.Certificate
	caKey        *rsa.PrivateKey
	serialNumber *big.Int
	mu           sync.Mutex
	revokedCerts map[string]time.Time
}

// CertificatePair contains a certificate and its corresponding private key.
type CertificatePair struct {
	CertPEM []byte
	KeyPEM  []byte
	Cert    *x509.Certificate
}

// New creates a new Certificate Authority.
func New(validityDays int) (*CA, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	caCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Zero-Trust Auth CA",
			Organization: []string{"Zero-Trust Auth"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validityDays),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return &CA{
		caCert:       parsedCert,
		caKey:        caKey,
		serialNumber: big.NewInt(2),
		revokedCerts: make(map[string]time.Time),
	}, nil
}

// IssueClientCert issues a short-lived client certificate (default 15 minutes).
func (ca *CA) IssueClientCert(clientID string, validityMinutes int) (*CertificatePair, error) {
	return ca.IssueCert(clientID, validityMinutes, false, nil)
}

// IssueCert issues a certificate with optional server usage and SANs.
func (ca *CA) IssueCert(clientID string, validityMinutes int, isServer bool, dnsNames []string) (*CertificatePair, error) {
	ca.mu.Lock()
	serialNum := new(big.Int).Set(ca.serialNumber)
	ca.serialNumber.Add(ca.serialNumber, big.NewInt(1))
	ca.mu.Unlock()

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	now := time.Now()
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if isServer {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	// Separate DNS names and IP addresses
	var dnsNamesList []string
	var ipAddresses []net.IP

	for _, name := range dnsNames {
		if ip := net.ParseIP(name); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNamesList = append(dnsNamesList, name)
		}
	}

	clientCert := &x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			CommonName: clientID,
		},
		NotBefore:   now,
		NotAfter:    now.Add(time.Duration(validityMinutes) * time.Minute),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: extKeyUsage,
		DNSNames:    dnsNamesList,
		IPAddresses: ipAddresses,
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientCert, ca.caCert, &clientKey.PublicKey, ca.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	parsedClientCert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCertDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clientKey),
	})

	return &CertificatePair{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		Cert:    parsedClientCert,
	}, nil
}

// RevokeCert adds a certificate to the revocation list.
func (ca *CA) RevokeCert(certSerial string) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.revokedCerts[certSerial] = time.Now()
}

// IsRevoked checks if a certificate serial number is revoked.
func (ca *CA) IsRevoked(certSerial string) bool {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	_, revoked := ca.revokedCerts[certSerial]
	return revoked
}

// VerifyClientCert verifies a client certificate against this CA.
func (ca *CA) VerifyClientCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check expiry
	if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("certificate has expired or not yet valid")
	}

	// Check revocation first (fail fast)
	if ca.IsRevoked(cert.SerialNumber.String()) {
		return nil, fmt.Errorf("certificate is revoked")
	}

	// Verify signature by attempting to verify with the CA cert
	opts := x509.VerifyOptions{
		Roots:       x509.NewCertPool(),
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	opts.Roots.AddCert(ca.caCert)

	if _, err := cert.Verify(opts); err != nil {
		return nil, fmt.Errorf("certificate signature verification failed: %w", err)
	}

	return cert, nil
}

// GetCACertPEM returns the CA certificate in PEM format.
func (ca *CA) GetCACertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.caCert.Raw,
	})
}

// GetCertFingerprint returns the SHA256 fingerprint of a certificate.
func GetCertFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", hash)
}

// RevokedCertsCount returns the number of revoked certificates.
func (ca *CA) RevokedCertsCount() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return len(ca.revokedCerts)
}

// GetCACert returns the CA certificate.
func (ca *CA) GetCACert() *x509.Certificate {
	return ca.caCert
}
