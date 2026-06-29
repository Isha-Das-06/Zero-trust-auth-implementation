package server

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

// Server represents a zero-trust authentication service using mTLS.
type Server struct {
	listener       net.Listener
	ca             *ca.CA
	tlsConfig      *tls.Config
	addr           string
	shutdownChan   chan struct{}
	done           chan struct{}
	mu             sync.RWMutex
	activeClients  map[string]*ClientSession
	requestCounter int64
}

// ClientSession represents an authenticated client session.
type ClientSession struct {
	ClientID  string
	CertSerial string
	Cert      *x509.Certificate
	ConnTime  time.Time
	LastSeen  time.Time
}

// New creates a new zero-trust authentication server.
func New(ca *ca.CA, addr string) (*Server, error) {
	caCertPEM := ca.GetCACertPEM()
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Issue a server certificate with localhost SANs
	serverCert, err := ca.IssueCert("auth-server", 24*60, true, []string{"localhost", "127.0.0.1", "::1"})
	if err != nil {
		return nil, fmt.Errorf("failed to issue server certificate: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(serverCert.CertPEM, serverCert.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS13,
	}

	return &Server{
		ca:            ca,
		tlsConfig:     tlsConfig,
		addr:          addr,
		shutdownChan:  make(chan struct{}),
		done:          make(chan struct{}),
		activeClients: make(map[string]*ClientSession),
	}, nil
}

// Start starts the mTLS server and begins accepting connections.
func (s *Server) Start() error {
	listener, err := tls.Listen("tcp", s.addr, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to create TLS listener: %w", err)
	}

	s.listener = listener
	fmt.Printf("[Server] Listening on %s with mTLS\n", s.addr)

	go s.acceptConnections()
	return nil
}

// acceptConnections accepts incoming client connections.
func (s *Server) acceptConnections() {
	defer close(s.done)

	for {
		select {
		case <-s.shutdownChan:
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.shutdownChan:
				return
			default:
				fmt.Printf("[Server] Accept error: %v\n", err)
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

// handleConnection handles a single client connection.
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		fmt.Printf("[Server] Connection is not TLS\n")
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		fmt.Printf("[Server] TLS handshake failed: %v\n", err)
		return
	}

	clientCerts := tlsConn.ConnectionState().PeerCertificates
	if len(clientCerts) == 0 {
		fmt.Printf("[Server] No client certificate presented\n")
		return
	}

	clientCert := clientCerts[0]
	clientID := clientCert.Subject.CommonName

	if s.ca.IsRevoked(clientCert.SerialNumber.String()) {
		fmt.Printf("[Server] Rejecting revoked certificate: %s\n", clientID)
		io.WriteString(conn, "ERROR: Certificate is revoked\n")
		return
	}

	if time.Now().After(clientCert.NotAfter) {
		fmt.Printf("[Server] Rejecting expired certificate: %s\n", clientID)
		io.WriteString(conn, "ERROR: Certificate has expired\n")
		return
	}

	session := &ClientSession{
		ClientID:   clientID,
		CertSerial: clientCert.SerialNumber.String(),
		Cert:       clientCert,
		ConnTime:   time.Now(),
		LastSeen:   time.Now(),
	}

	s.mu.Lock()
	s.activeClients[clientID] = session
	s.requestCounter++
	s.mu.Unlock()

	fmt.Printf("[Server] Accepted connection from: %s (Serial: %s)\n", clientID, clientCert.SerialNumber.String())

	io.WriteString(conn, fmt.Sprintf("OK: Authenticated as %s\nCertificate expires at: %s\n", clientID, clientCert.NotAfter.Format(time.RFC3339)))

	s.mu.Lock()
	delete(s.activeClients, clientID)
	s.mu.Unlock()
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() error {
	close(s.shutdownChan)

	if s.listener != nil {
		s.listener.Close()
	}

	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("server shutdown timeout")
	}

	return nil
}

// GetActiveClients returns the currently active client sessions.
func (s *Server) GetActiveClients() map[string]*ClientSession {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]*ClientSession)
	for k, v := range s.activeClients {
		result[k] = v
	}
	return result
}

// GetRequestCount returns the total number of requests processed.
func (s *Server) GetRequestCount() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.requestCounter
}

// GetAddress returns the server's listening address.
func (s *Server) GetAddress() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.addr
}
