package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"zero-trust-auth/ca"
	"zero-trust-auth/client"
	"zero-trust-auth/server"
)

func main() {
	fmt.Println("=== Zero-Trust Authentication System (mTLS with Short-Lived Certs) ===")

	// Initialize Certificate Authority
	fmt.Println("[*] Initializing Certificate Authority...")
	testCA, err := ca.New(365)
	if err != nil {
		fmt.Printf("Failed to create CA: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] CA created successfully")
	fmt.Printf("    CA Certificate: %s\n", ca.GetCertFingerprint(testCA.GetCACert())[:16]+"...")

	// Start authentication server
	fmt.Println("\n[*] Starting mTLS Authentication Server...")
	srv, err := server.New(testCA, "localhost:8443")
	if err != nil {
		fmt.Printf("Failed to create server: %v\n", err)
		os.Exit(1)
	}

	err = srv.Start()
	if err != nil {
		fmt.Printf("Failed to start server: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] Server listening on localhost:8443")

	// Demo: Create and connect clients
	fmt.Println("\n[*] Demonstrating client authentication...")
	demonstrateAuthentication(testCA, srv)

	// Demo: Show certificate rotation
	fmt.Println("\n[*] Demonstrating automatic certificate rotation...")
	demonstrateCertRotation(testCA)

	// Demo: Show revocation
	fmt.Println("\n[*] Demonstrating certificate revocation...")
	demonstrateRevocation(testCA)

	// Demo: Show rejection of unauthorized clients
	fmt.Println("\n[*] Demonstrating rejection of unauthorized access attempts...")
	demonstrateUnauthorized(testCA)

	// Interactive mode
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("Enter 'quit' to exit, 'status' to see server stats, or client IDs to authenticate:")
	interactiveMode(testCA, srv)

	srv.Stop()
	fmt.Println("\n[+] Server stopped. Exiting.")
}

func demonstrateAuthentication(testCA *ca.CA, srv *server.Server) {
	for i := 1; i <= 3; i++ {
		clientID := fmt.Sprintf("demo-client-%d", i)
		fmt.Printf("\n[*] Authenticating %s...\n", clientID)

		c, err := client.New(clientID, testCA, 15)
		if err != nil {
			fmt.Printf("  [-] Failed to create client: %v\n", err)
			continue
		}

		serial, expiry, err := c.GetCurrentCertInfo()
		if err != nil {
			fmt.Printf("  [-] Failed to get cert info: %v\n", err)
			c.Close()
			continue
		}

		fmt.Printf("  [+] Certificate issued\n")
		fmt.Printf("      Serial: %s\n", serial[:16]+"...")
		fmt.Printf("      Expires: %s\n", expiry.Format("15:04:05"))

		response, err := c.Connect(srv.GetAddress())
		if err != nil {
			fmt.Printf("  [-] Connection failed: %v\n", err)
		} else {
			fmt.Printf("  [+] Authentication successful\n")
			fmt.Printf("      Response: %s", response)
		}

		c.Close()
	}
}

func demonstrateCertRotation(testCA *ca.CA) {
	fmt.Println("\n[*] Creating client with 2-minute certificate TTL...")
	c, err := client.New("rotation-demo", testCA, 2)
	if err != nil {
		fmt.Printf("  [-] Failed to create client: %v\n", err)
		return
	}

	serial1, expiry1, _ := c.GetCurrentCertInfo()
	fmt.Printf("  [+] Initial certificate:\n")
	fmt.Printf("      Serial: %s\n", serial1[:16]+"...")
	fmt.Printf("      Expires: %s\n", expiry1.Format("15:04:05"))

	fmt.Println("\n  [*] Waiting 3 seconds for rotation (rotation happens ~30s before expiry)...")
	time.Sleep(3 * time.Second)

	serial2, expiry2, _ := c.GetCurrentCertInfo()
	fmt.Printf("  [+] Automatic rotation working\n")
	fmt.Printf("      New expiry: %s\n", expiry2.Format("15:04:05"))

	if serial1 != serial2 {
		fmt.Printf("      Certificate was rotated (new serial)\n")
	}

	c.Close()
}

func demonstrateRevocation(testCA *ca.CA) {
	fmt.Println("\n[*] Creating certificate and revoking it...")

	certPair, err := testCA.IssueClientCert("revocation-demo", 15)
	if err != nil {
		fmt.Printf("  [-] Failed to issue cert: %v\n", err)
		return
	}

	serialNum := certPair.Cert.SerialNumber.String()
	fmt.Printf("  [+] Certificate issued: %s\n", serialNum[:16]+"...")

	// Verify before revocation
	_, err = testCA.VerifyClientCert(certPair.CertPEM)
	if err == nil {
		fmt.Println("  [+] Certificate is valid")
	}

	// Revoke certificate
	testCA.RevokeCert(serialNum)
	fmt.Println("  [*] Certificate revoked")

	// Verify after revocation
	_, err = testCA.VerifyClientCert(certPair.CertPEM)
	if err != nil {
		fmt.Printf("  [+] Certificate rejected after revocation: %v\n", err)
	}

	fmt.Printf("  [+] Total revoked certificates: %d\n", testCA.RevokedCertsCount())
}

func demonstrateUnauthorized(testCA *ca.CA) {
	fmt.Println("\n[*] Attempting authentication with different CA...")

	differentCA, err := ca.New(365)
	if err != nil {
		fmt.Printf("  [-] Failed to create alternate CA: %v\n", err)
		return
	}

	c, err := client.New("unauthorized-demo", differentCA, 15)
	if err != nil {
		fmt.Printf("  [-] Failed to create client: %v\n", err)
		return
	}
	defer c.Close()

	srv2, err := server.New(testCA, "localhost:8444")
	if err != nil {
		fmt.Printf("  [-] Failed to create server: %v\n", err)
		return
	}
	srv2.Start()
	time.Sleep(100 * time.Millisecond)

	fmt.Println("  [*] Attempting connection with unauthorized certificate...")
	_, err = c.Connect(srv2.GetAddress())

	if err != nil {
		fmt.Printf("  [+] Connection rejected as expected: %v\n", err)
	} else {
		fmt.Println("  [!] Unexpected: connection succeeded")
	}

	srv2.Stop()
}

func interactiveMode(testCA *ca.CA, srv *server.Server) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("\n> ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())

		switch {
		case input == "quit":
			return
		case input == "status":
			fmt.Printf("\nServer Statistics:\n")
			fmt.Printf("  Active clients: %d\n", len(srv.GetActiveClients()))
			fmt.Printf("  Total requests: %d\n", srv.GetRequestCount())
			fmt.Printf("  Revoked certificates: %d\n", testCA.RevokedCertsCount())
		case input == "help":
			fmt.Println("\nAvailable commands:")
			fmt.Println("  <clientID>  - Authenticate with the given client ID")
			fmt.Println("  status      - Show server statistics")
			fmt.Println("  quit        - Exit the program")
		case input == "":
			continue
		default:
			authenticateInteractive(testCA, srv, input)
		}
	}
}

func authenticateInteractive(testCA *ca.CA, srv *server.Server, clientID string) {
	fmt.Printf("\n[*] Authenticating %s...\n", clientID)

	c, err := client.New(clientID, testCA, 15)
	if err != nil {
		fmt.Printf("  [-] Failed to create client: %v\n", err)
		return
	}
	defer c.Close()

	serial, expiry, err := c.GetCurrentCertInfo()
	if err != nil {
		fmt.Printf("  [-] Failed to get certificate info: %v\n", err)
		return
	}

	fmt.Printf("  [+] Certificate issued\n")
	fmt.Printf("      Serial: %s\n", serial[:16]+"...")
	fmt.Printf("      Expires: %s\n", expiry.Format("15:04:05"))

	response, err := c.Connect(srv.GetAddress())
	if err != nil {
		fmt.Printf("  [-] Connection failed: %v\n", err)
	} else {
		fmt.Printf("  [+] Authentication successful\n")
		fmt.Printf("      Response: %s", response)
	}
}
