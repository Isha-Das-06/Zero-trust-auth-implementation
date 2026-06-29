package ca

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCACreation(t *testing.T) {
	ca, err := New(365)
	require.NoError(t, err)
	assert.NotNil(t, ca.caCert)
	assert.NotNil(t, ca.caKey)
}

func TestIssueClientCert(t *testing.T) {
	ca, err := New(365)
	require.NoError(t, err)

	certPair, err := ca.IssueClientCert("client-1", 15)
	require.NoError(t, err)

	assert.NotNil(t, certPair.CertPEM)
	assert.NotNil(t, certPair.KeyPEM)
	assert.NotNil(t, certPair.Cert)
	assert.Equal(t, "client-1", certPair.Cert.Subject.CommonName)
}

func TestCertificateExpiry(t *testing.T) {
	ca, err := New(365)
	require.NoError(t, err)

	certPair, err := ca.IssueClientCert("client-exp", 1)
	require.NoError(t, err)

	assert.True(t, time.Now().Before(certPair.Cert.NotAfter))
	assert.True(t, time.Now().After(certPair.Cert.NotBefore))
}

func TestCertificateRevocation(t *testing.T) {
	ca, err := New(365)
	require.NoError(t, err)

	certPair, err := ca.IssueClientCert("client-revoke", 15)
	require.NoError(t, err)

	serialNum := certPair.Cert.SerialNumber.String()
	assert.False(t, ca.IsRevoked(serialNum))

	ca.RevokeCert(serialNum)
	assert.True(t, ca.IsRevoked(serialNum))
}

func TestVerifyClientCert_Valid(t *testing.T) {
	ca, err := New(365)
	require.NoError(t, err)

	certPair, err := ca.IssueClientCert("client-valid", 15)
	require.NoError(t, err)

	verified, err := ca.VerifyClientCert(certPair.CertPEM)
	require.NoError(t, err)
	assert.Equal(t, "client-valid", verified.Subject.CommonName)
}

func TestVerifyClientCert_Revoked(t *testing.T) {
	ca, err := New(365)
	require.NoError(t, err)

	certPair, err := ca.IssueClientCert("client-revoked", 15)
	require.NoError(t, err)

	ca.RevokeCert(certPair.Cert.SerialNumber.String())

	_, err = ca.VerifyClientCert(certPair.CertPEM)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestVerifyClientCert_InvalidPEM(t *testing.T) {
	ca, err := New(365)
	require.NoError(t, err)

	_, err = ca.VerifyClientCert([]byte("invalid pem"))
	require.Error(t, err)
}

func TestCertFingerprint(t *testing.T) {
	ca, err := New(365)
	require.NoError(t, err)

	certPair, err := ca.IssueClientCert("client-fp", 15)
	require.NoError(t, err)

	fp := GetCertFingerprint(certPair.Cert)
	assert.Len(t, fp, 64)
	assert.NotEmpty(t, fp)
}

func TestMultipleCertificates(t *testing.T) {
	ca, err := New(365)
	require.NoError(t, err)

	certs := make([]*CertificatePair, 5)
	for i := 0; i < 5; i++ {
		c, err := ca.IssueClientCert("client-multi", 15)
		require.NoError(t, err)
		certs[i] = c
	}

	for i := 0; i < 5; i++ {
		for j := i + 1; j < 5; j++ {
			assert.NotEqual(t, certs[i].Cert.SerialNumber, certs[j].Cert.SerialNumber)
		}
	}
}

func TestRevokedCertsCount(t *testing.T) {
	ca, err := New(365)
	require.NoError(t, err)

	assert.Equal(t, 0, ca.RevokedCertsCount())

	cert1, _ := ca.IssueClientCert("client-1", 15)
	cert2, _ := ca.IssueClientCert("client-2", 15)

	ca.RevokeCert(cert1.Cert.SerialNumber.String())
	assert.Equal(t, 1, ca.RevokedCertsCount())

	ca.RevokeCert(cert2.Cert.SerialNumber.String())
	assert.Equal(t, 2, ca.RevokedCertsCount())
}

func TestGetCACertPEM(t *testing.T) {
	ca, err := New(365)
	require.NoError(t, err)

	pem := ca.GetCACertPEM()
	assert.Contains(t, string(pem), "BEGIN CERTIFICATE")
	assert.Contains(t, string(pem), "END CERTIFICATE")
}

func TestCertificateChain(t *testing.T) {
	ca, err := New(365)
	require.NoError(t, err)

	clientCert, err := ca.IssueClientCert("client-chain", 15)
	require.NoError(t, err)

	assert.Greater(t, len(clientCert.Cert.Issuer.CommonName), 0)
}

func TestVerifyClientCert_RejectsUnauthorizedCA(t *testing.T) {
	// Create legitimate CA
	legitCA, err := New(365)
	require.NoError(t, err)

	// Create attacker's independent CA
	attackerCA, err := New(365)
	require.NoError(t, err)

	// Attacker issues a certificate for "admin"
	attackerCert, err := attackerCA.IssueClientCert("admin", 15)
	require.NoError(t, err)

	// Legitimate CA should reject the attacker's cert (even though it's valid from the attacker's perspective)
	_, err = legitCA.VerifyClientCert(attackerCert.CertPEM)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}
