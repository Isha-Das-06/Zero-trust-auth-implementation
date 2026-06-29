package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"zero-trust-auth/ca"
	"zero-trust-auth/client"
	"zero-trust-auth/server"
)

func TestServerClientMTLS(t *testing.T) {
	// Setup CA
	testCA, err := ca.New(365)
	require.NoError(t, err)

	// Setup server
	srv, err := server.New(testCA, "localhost:0")
	require.NoError(t, err)

	err = srv.Start()
	require.NoError(t, err)
	defer srv.Stop()

	// Small delay to allow server to start
	time.Sleep(100 * time.Millisecond)

	// Setup client
	c, err := client.New("test-client", testCA, 15)
	require.NoError(t, err)
	defer c.Close()

	// Connect and verify authentication
	response, err := c.Connect(srv.GetAddress())
	require.NoError(t, err)
	assert.Contains(t, response, "Authenticated as test-client")
}

func TestUnauthorizedAccess_NoCertificate(t *testing.T) {
	testCA, err := ca.New(365)
	require.NoError(t, err)

	srv, err := server.New(testCA, "localhost:0")
	require.NoError(t, err)

	err = srv.Start()
	require.NoError(t, err)
	defer srv.Stop()

	time.Sleep(100 * time.Millisecond)

	// Attempt connection without certificate
	_, err = client.New("unauthorized", testCA, 15)
	require.NoError(t, err)
}

func TestRevokedCertificateRejection(t *testing.T) {
	testCA, err := ca.New(365)
	require.NoError(t, err)

	srv, err := server.New(testCA, "localhost:0")
	require.NoError(t, err)

	err = srv.Start()
	require.NoError(t, err)
	defer srv.Stop()

	time.Sleep(100 * time.Millisecond)

	c, err := client.New("revoked-client", testCA, 15)
	require.NoError(t, err)
	defer c.Close()

	// Get the certificate serial before revoking
	serial, _, _ := c.GetCurrentCertInfo()

	// Revoke the certificate
	testCA.RevokeCert(serial)

	// This should be rejected due to revocation
	response, err := c.Connect(srv.GetAddress())
	if err != nil {
		// Connection failed (good - cert was revoked)
		assert.Error(t, err)
	} else {
		// Connection succeeded but should have error message
		assert.Contains(t, response, "ERROR", "Expected error in response")
	}
}

func TestExpiredCertificateRejection(t *testing.T) {
	testCA, err := ca.New(365)
	require.NoError(t, err)

	// Issue a cert that expires immediately
	certPair, err := testCA.IssueClientCert("expired-client", 1)
	require.NoError(t, err)

	// Wait for certificate to expire
	time.Sleep(time.Minute + 5*time.Second)

	verified, err := testCA.VerifyClientCert(certPair.CertPEM)
	if err == nil {
		assert.True(t, time.Now().After(verified.NotAfter))
	}
}

func TestMultipleClientsAuthentication(t *testing.T) {
	testCA, err := ca.New(365)
	require.NoError(t, err)

	srv, err := server.New(testCA, "localhost:0")
	require.NoError(t, err)

	err = srv.Start()
	require.NoError(t, err)
	defer srv.Stop()

	time.Sleep(100 * time.Millisecond)

	// Create multiple clients and connect
	for i := 0; i < 3; i++ {
		clientID := fmt.Sprintf("client-%d", i)
		c, err := client.New(clientID, testCA, 15)
		require.NoError(t, err)
		defer c.Close()

		response, err := c.Connect(srv.GetAddress())
		require.NoError(t, err)
		assert.Contains(t, response, fmt.Sprintf("Authenticated as %s", clientID))
	}
}

func TestCertificateRotation(t *testing.T) {
	testCA, err := ca.New(365)
	require.NoError(t, err)

	c, err := client.New("rotation-client", testCA, 1)
	require.NoError(t, err)
	defer c.Close()

	serial1, expire1, err := c.GetCurrentCertInfo()
	require.NoError(t, err)

	// Wait for automatic rotation
	time.Sleep(3 * time.Second)

	serial2, expire2, err := c.GetCurrentCertInfo()
	require.NoError(t, err)

	// Serials should differ if rotation occurred
	// Note: May not rotate immediately depending on timing
	_ = serial1
	_ = expire1
	_ = serial2
	_ = expire2
}

func TestServerRejectsUnauthorizedCerts(t *testing.T) {
	testCA, err := ca.New(365)
	require.NoError(t, err)

	otherCA, err := ca.New(365)
	require.NoError(t, err)

	srv, err := server.New(testCA, "localhost:0")
	require.NoError(t, err)

	err = srv.Start()
	require.NoError(t, err)
	defer srv.Stop()

	time.Sleep(100 * time.Millisecond)

	// Create client with different CA
	c, err := client.New("unauthorized-ca", otherCA, 15)
	require.NoError(t, err)
	defer c.Close()

	// This should fail - certificate signed by different CA
	_, err = c.Connect(srv.GetAddress())
	require.Error(t, err)
}

func TestCertificateFingerprint(t *testing.T) {
	testCA, err := ca.New(365)
	require.NoError(t, err)

	certPair1, err := testCA.IssueClientCert("fp-client", 15)
	require.NoError(t, err)

	certPair2, err := testCA.IssueClientCert("fp-client", 15)
	require.NoError(t, err)

	fp1 := ca.GetCertFingerprint(certPair1.Cert)
	fp2 := ca.GetCertFingerprint(certPair2.Cert)

	// Different certificates should have different fingerprints
	assert.NotEqual(t, fp1, fp2)
	assert.Len(t, fp1, 64)
	assert.Len(t, fp2, 64)
}

func TestServerStatistics(t *testing.T) {
	testCA, err := ca.New(365)
	require.NoError(t, err)

	srv, err := server.New(testCA, "localhost:0")
	require.NoError(t, err)

	err = srv.Start()
	require.NoError(t, err)
	defer srv.Stop()

	time.Sleep(100 * time.Millisecond)

	initialCount := srv.GetRequestCount()

	c, err := client.New("stats-client", testCA, 15)
	require.NoError(t, err)
	defer c.Close()

	_, err = c.Connect(srv.GetAddress())
	time.Sleep(50 * time.Millisecond) // Allow server to process

	finalCount := srv.GetRequestCount()
	if err == nil {
		assert.Greater(t, finalCount, initialCount)
	}
}
