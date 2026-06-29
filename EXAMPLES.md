# Zero-Trust Authentication - Usage Examples

## Table of Contents
1. [Basic Setup](#basic-setup)
2. [Single Service](#single-service)
3. [Service Mesh](#service-mesh)
4. [High-Security Operations](#high-security-operations)
5. [Emergency Revocation](#emergency-revocation)
6. [Monitoring & Metrics](#monitoring--metrics)

---

## Basic Setup

### Creating a CA and Server

```go
package main

import (
    "fmt"
    "zero-trust-auth/ca"
    "zero-trust-auth/server"
)

func main() {
    // Step 1: Create Certificate Authority
    auth, err := ca.New(365)  // CA valid for 1 year
    if err != nil {
        panic(err)
    }
    fmt.Println("CA created")

    // Step 2: Start authentication server
    srv, err := server.New(auth, "localhost:8443")
    if err != nil {
        panic(err)
    }
    
    if err := srv.Start(); err != nil {
        panic(err)
    }
    fmt.Println("Server listening on localhost:8443")

    // Keep running
    select {}
}
```

---

## Single Service

### Authenticating a Microservice

```go
package main

import (
    "fmt"
    "zero-trust-auth/ca"
    "zero-trust-auth/client"
    "zero-trust-auth/server"
)

func main() {
    // Setup
    auth, _ := ca.New(365)
    srv, _ := server.New(auth, "auth.internal:8443")
    srv.Start()

    // Create client for payment service
    paymentService, err := client.New("payment-service", auth, 15)
    if err != nil {
        panic(err)
    }

    // Connect and authenticate
    response, err := paymentService.Connect("auth.internal:8443")
    if err != nil {
        panic(fmt.Sprintf("Auth failed: %v", err))
    }
    fmt.Printf("Payment service authenticated: %s\n", response)

    // Certificate rotates automatically every 15 minutes
    // No manual credential rotation needed
}
```

---

## Service Mesh

### Multiple Services with Automatic Rotation

Scenario: 5 microservices that need to authenticate to each other

```go
package main

import (
    "fmt"
    "sync"
    "time"
    "zero-trust-auth/ca"
    "zero-trust-auth/client"
    "zero-trust-auth/server"
)

type Service struct {
    Name   string
    Auth   *client.Client
    Server *server.Server
}

func main() {
    // Shared CA for all services
    sharedCA, _ := ca.New(365)

    // Create 5 services
    services := []string{"api", "payment", "order", "inventory", "shipping"}
    serviceMap := make(map[string]*Service)

    for _, name := range services {
        // Each service runs its own server
        srv, _ := server.New(sharedCA, fmt.Sprintf("%s:8443", name))
        srv.Start()

        // Each service has a client for calling others
        auth, _ := client.New(name, sharedCA, 15)

        serviceMap[name] = &Service{
            Name:   name,
            Auth:   auth,
            Server: srv,
        }

        fmt.Printf("Started service: %s\n", name)
    }

    // Simulate service-to-service communication
    // API service calls payment service
    paymentClient := serviceMap["payment"]
    response, err := paymentClient.Auth.Connect("payment:8443")
    
    if err != nil {
        fmt.Printf("Error: %v\n", err)
    } else {
        fmt.Printf("Service auth successful: %s\n", response)
    }

    // Certificates rotate automatically for all services
    fmt.Println("\nAll services running with auto-rotating certificates...")
    time.Sleep(30 * time.Second)

    // Cleanup
    for _, svc := range serviceMap {
        svc.Server.Stop()
        svc.Auth.Close()
    }
}
```

---

## High-Security Operations

### Admin Operations with Short Lifespan

```go
package main

import (
    "fmt"
    "time"
    "zero-trust-auth/ca"
    "zero-trust-auth/client"
    "zero-trust-auth/server"
)

func main() {
    auth, _ := ca.New(365)
    srv, _ := server.New(auth, "admin:8443")
    srv.Start()

    // Scenario: Admin needs to perform sensitive operation
    // Use very short-lived certificate (5 minutes)
    admin, err := client.New("admin-session-12345", auth, 5)
    if err != nil {
        panic(err)
    }

    cert, expiry, _ := admin.GetCurrentCertInfo()
    fmt.Printf("Admin session created\n")
    fmt.Printf("  Serial: %s\n", cert)
    fmt.Printf("  Expires: %s (in 5 minutes)\n", expiry.Format("15:04:05"))

    // Perform sensitive operation
    response, _ := admin.Connect("admin:8443")
    fmt.Printf("  Operation result: %s\n", response)

    // Certificate automatically expires after 5 minutes
    // No need to manually revoke or logout
    fmt.Println("  Certificate will expire in 5 minutes - session ends automatically")

    admin.Close()
    srv.Stop()
}
```

---

## Emergency Revocation

### Detecting and Revoking Compromised Credentials

```go
package main

import (
    "fmt"
    "zero-trust-auth/ca"
)

func main() {
    auth, _ := ca.New(365)

    // Issue certificate to service
    cert, _ := auth.IssueClientCert("api-service", 15)
    fmt.Printf("Issued certificate: %s\n", cert.Cert.SerialNumber)

    // Scenario: Certificate is compromised
    // (found in logs, exposed in GitHub commit, detected via monitoring, etc.)
    fmt.Println("\n[ALERT] Certificate compromise detected!")

    // Immediately revoke
    auth.RevokeCert(cert.Cert.SerialNumber.String())
    fmt.Println("[ACTION] Certificate revoked in CA")

    // Verify revocation
    _, err := auth.VerifyClientCert(cert.CertPEM)
    if err != nil {
        fmt.Printf("[CONFIRM] Certificate is now rejected: %v\n", err)
    }

    // Effects of revocation:
    // ✓ Immediate - no propagation delay
    // ✓ All servers will reject this certificate
    // ✓ Client will request new cert on next renewal
    // ✓ Damage window limited to 15 minutes max
}
```

---

## Monitoring & Metrics

### Tracking Certificate Usage and Health

```go
package main

import (
    "fmt"
    "time"
    "zero-trust-auth/ca"
    "zero-trust-auth/client"
    "zero-trust-auth/server"
)

func main() {
    auth, _ := ca.New(365)
    srv, _ := server.New(auth, "secure:8443")
    srv.Start()

    // Create several clients
    for i := 0; i < 3; i++ {
        client, _ := client.New(fmt.Sprintf("service-%d", i), auth, 15)
        client.Connect(srv.listener.Addr().String())
        client.Close()
        time.Sleep(100 * time.Millisecond)
    }

    // Metrics collection
    fmt.Println("=== Server Metrics ===")
    fmt.Printf("Total requests: %d\n", srv.GetRequestCount())
    fmt.Printf("Active clients: %d\n", len(srv.GetActiveClients()))
    fmt.Printf("Revoked certificates: %d\n", auth.RevokedCertsCount())

    // Revoke a few certs (simulating incidents)
    for i := 0; i < 2; i++ {
        cert, _ := auth.IssueClientCert(fmt.Sprintf("test-%d", i), 15)
        auth.RevokeCert(cert.Cert.SerialNumber.String())
    }

    fmt.Println("\n=== After Revocation ===")
    fmt.Printf("Revoked certificates: %d\n", auth.RevokedCertsCount())

    // Monitoring recommendations:
    // - Track certificate issue rate (should be ~1 per service per 13 min)
    // - Track revocation rate (should be low)
    // - Track failed authentications (should be 0 for authorized clients)
    // - Alert if rotation latency exceeds threshold
}
```

---

## Advanced: Custom Certificate TTLs

### Different lifetimes for different services

```go
package main

import (
    "fmt"
    "zero-trust-auth/ca"
)

func main() {
    auth, _ := ca.New(365)

    // Batch processing service - long-lived cert ok
    batch, _ := auth.IssueClientCert("batch-processor", 120)  // 2 hours
    fmt.Printf("Batch processor cert expires: %s\n", batch.Cert.NotAfter.Format("15:04:05"))

    // High-risk operation - very short cert
    admin, _ := auth.IssueClientCert("admin-action", 3)  // 3 minutes
    fmt.Printf("Admin action cert expires: %s\n", admin.Cert.NotAfter.Format("15:04:05"))

    // Regular service - default
    service, _ := auth.IssueClientCert("api-service", 15)  // 15 minutes
    fmt.Printf("API service cert expires: %s\n", service.Cert.NotAfter.Format("15:04:05"))

    // Web client - longer for batch operations
    web, _ := auth.IssueClientCert("web-client", 60)  // 1 hour
    fmt.Printf("Web client cert expires: %s\n", web.Cert.NotAfter.Format("15:04:05"))

    // Use cases for different TTLs:
    // - 3-5 min: Admin operations, sensitive actions
    // - 15 min: Default for microservices
    // - 30-60 min: Batch jobs, background workers
    // - 2+ hours: Long-running processes (with rotation)
}
```

---

## Error Handling

### Robust Client with Retry Logic

```go
package main

import (
    "fmt"
    "time"
    "zero-trust-auth/ca"
    "zero-trust-auth/client"
    "zero-trust-auth/server"
)

func authenticateWithRetry(c *client.Client, serverAddr string, maxRetries int) error {
    for attempt := 1; attempt <= maxRetries; attempt++ {
        response, err := c.Connect(serverAddr)
        if err == nil {
            fmt.Printf("Authentication successful: %s\n", response)
            return nil
        }

        fmt.Printf("Attempt %d failed: %v\n", attempt, err)

        if attempt < maxRetries {
            // Exponential backoff
            backoff := time.Duration(1<<uint(attempt-1)) * time.Second
            fmt.Printf("Retrying in %v...\n", backoff)
            time.Sleep(backoff)
        }
    }

    return fmt.Errorf("authentication failed after %d attempts", maxRetries)
}

func main() {
    auth, _ := ca.New(365)
    srv, _ := server.New(auth, "service:8443")
    srv.Start()

    c, _ := client.New("resilient-service", auth, 15)

    err := authenticateWithRetry(c, srv.listener.Addr().String(), 3)
    if err != nil {
        fmt.Printf("Final error: %v\n", err)
    }

    c.Close()
    srv.Stop()
}
```

---

## Summary of Examples

| Example | Use Case | TTL | Notes |
|---------|----------|-----|-------|
| Basic Setup | Learning | N/A | Foundation |
| Single Service | Microservice auth | 15 min | Standard pattern |
| Service Mesh | Multi-service | 15 min | Scalable |
| High-Security | Admin operations | 5 min | Very short-lived |
| Emergency Revocation | Incident response | Immediate | Critical security |
| Monitoring | Observability | N/A | Track certificate lifecycle |
| Custom TTLs | Optimization | Variable | Tuned for workload |
| Error Handling | Resilience | N/A | Production-ready |

All examples follow zero-trust principles:
- ✓ No passwords or static secrets
- ✓ Mutual authentication
- ✓ Automatic rotation
- ✓ Cryptographic binding
- ✓ Revocation capability
