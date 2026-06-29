package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"zero-trust-auth/ca"
)

// Client represents a zero-trust authenticated client with automatic cert rotation.
type Client struct {
	clientID          string
	ca                *ca.CA
	currentCert       *ca.CertificatePair
	certTTL           int
	renewalBuffer     time.Duration
	mu                sync.RWMutex
	stopChan          chan struct{}
	done              chan struct{}
	lastConnectionErr error
}

// New creates a new zero-trust authenticated client.
func New(clientID string, ca *ca.CA, certTTLMinutes int) (*Client, error) {
	if certTTLMinutes <= 0 {
		return nil, fmt.Errorf("cert TTL must be positive")
	}

	// Scale renewal buffer with TTL: use min(2 minutes, TTL/2) to avoid spinning on short TTLs
	ttlDuration := time.Duration(certTTLMinutes) * time.Minute
	renewalBuffer := 2 * time.Minute
	if ttlDuration/2 < renewalBuffer {
		renewalBuffer = ttlDuration / 2
	}

	client := &Client{
		clientID:      clientID,
		ca:            ca,
		certTTL:       certTTLMinutes,
		renewalBuffer: renewalBuffer,
		stopChan:      make(chan struct{}),
		done:          make(chan struct{}),
	}

	if err := client.rotateNewCert(); err != nil {
		return nil, fmt.Errorf("failed to issue initial certificate: %w", err)
	}

	go client.maintainCertRotation()

	return client, nil
}

// rotateNewCert obtains a new certificate from the CA.
func (c *Client) rotateNewCert() error {
	certPair, err := c.ca.IssueClientCert(c.clientID, c.certTTL)
	if err != nil {
		return fmt.Errorf("failed to issue certificate: %w", err)
	}

	c.mu.Lock()
	c.currentCert = certPair
	c.mu.Unlock()

	return nil
}

// maintainCertRotation automatically rotates certificates before expiry.
func (c *Client) maintainCertRotation() {
	defer close(c.done)

	for {
		c.mu.RLock()
		if c.currentCert == nil {
			c.mu.RUnlock()
			time.Sleep(1 * time.Second)
			continue
		}

		expiryTime := c.currentCert.Cert.NotAfter
		timeUntilExpiry := time.Until(expiryTime)
		c.mu.RUnlock()

		renewAt := timeUntilExpiry - c.renewalBuffer

		select {
		case <-c.stopChan:
			return
		case <-time.After(renewAt):
			fmt.Printf("[Client %s] Renewing certificate...\n", c.clientID)
			if err := c.rotateNewCert(); err != nil {
				fmt.Printf("[Client %s] Certificate rotation failed: %v\n", c.clientID, err)
				c.mu.Lock()
				c.lastConnectionErr = err
				c.mu.Unlock()
			} else {
				fmt.Printf("[Client %s] Certificate rotated successfully\n", c.clientID)
			}
		}
	}
}

// Connect establishes a secure mTLS connection to the server.
func (c *Client) Connect(serverAddr string) (string, error) {
	c.mu.RLock()
	if c.currentCert == nil {
		c.mu.RUnlock()
		return "", fmt.Errorf("no valid certificate available")
	}

	certPEM := c.currentCert.CertPEM
	keyPEM := c.currentCert.KeyPEM
	c.mu.RUnlock()

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Add CA certificate to root pool for server verification
	caCertPEM := c.ca.GetCACertPEM()
	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCert)

	// Extract hostname for server name indication
	host, _, _ := net.SplitHostPort(serverAddr)
	if host == "" {
		host = serverAddr
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootPool,
		ServerName:   host,
		MinVersion:   tls.VersionTLS13,
	}

	conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		c.mu.Lock()
		c.lastConnectionErr = err
		c.mu.Unlock()
		return "", fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	response, err := io.ReadAll(conn)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	c.mu.Lock()
	c.lastConnectionErr = nil
	c.mu.Unlock()

	return string(response), nil
}

// GetCurrentCertInfo returns information about the current certificate.
func (c *Client) GetCurrentCertInfo() (string, time.Time, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.currentCert == nil {
		return "", time.Time{}, fmt.Errorf("no certificate available")
	}

	return c.currentCert.Cert.SerialNumber.String(), c.currentCert.Cert.NotAfter, nil
}

// Close stops the certificate rotation goroutine and cleans up.
func (c *Client) Close() error {
	close(c.stopChan)

	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
		return fmt.Errorf("client shutdown timeout")
	}

	return nil
}

// GetLastError returns the last connection error encountered.
func (c *Client) GetLastError() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastConnectionErr
}

// TLSConfig returns a configured TLS config for this client.
func (c *Client) TLSConfig() (*tls.Config, error) {
	c.mu.RLock()
	if c.currentCert == nil {
		c.mu.RUnlock()
		return nil, fmt.Errorf("no valid certificate available")
	}

	certPEM := c.currentCert.CertPEM
	keyPEM := c.currentCert.KeyPEM
	c.mu.RUnlock()

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	// Add CA certificate to root pool for server verification
	caCertPEM := c.ca.GetCACertPEM()
	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
