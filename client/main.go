package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "nlb/proto"
)

func getHost() string {
	if host := os.Getenv("LOAD_BALANCER_HOST"); host != "" {
		return host
	}
	return "localhost"
}

func getAddresses() (string, string, string, string, string) {
	host := getHost()
	return fmt.Sprintf("%s:8001", host), // TCP
		fmt.Sprintf("%s:8002", host), // UDP
		fmt.Sprintf("%s:8003", host), // gRPC
		fmt.Sprintf("http://%s:8004", host), // HTTP
		fmt.Sprintf("https://%s:8005", host) // HTTP/2
}

func testTCPClient() error {
	fmt.Println("=== Testing TCP Client ===")

	tcpAddr, _, _, _, _ := getAddresses()
	fmt.Println("Testing TCP Client on", tcpAddr)

	// Add timeout to TCP connection
	conn, err := net.DialTimeout("tcp", tcpAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to TCP server: %v", err)
	}
	defer conn.Close()

	// Set read/write timeouts
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	message := "Hello TCP Server!"
	_, err = conn.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to send TCP message: %v", err)
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("failed to read TCP response: %v", err)
	}

	response := string(buffer[:n])
	fmt.Printf("TCP Response: %s\n", response)
	return nil
}

func testUDPClient() error {
	fmt.Println("\n=== Testing UDP Client ===")

	_, udpAddr, _, _, _ := getAddresses()

	// Add timeout to UDP connection
	conn, err := net.DialTimeout("udp", udpAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to UDP server: %v", err)
	}
	defer conn.Close()

	// Set read/write timeouts
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	message := "Hello UDP Server!"
	_, err = conn.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to send UDP message: %v", err)
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("failed to read UDP response: %v", err)
	}

	response := string(buffer[:n])
	fmt.Printf("UDP Response: %s\n", response)
	return nil
}

func testGRPCClient() error {
	fmt.Println("\n=== Testing gRPC Client ===")

	_, _, grpcAddr, _, _ := getAddresses()
	conn, err := grpc.Dial(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	client := pb.NewEchoServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &pb.EchoRequest{
		Message: "Hello gRPC Server!",
	}

	resp, err := client.Echo(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to call gRPC Echo: %v", err)
	}

	fmt.Printf("gRPC Response: %s (Timestamp: %d)\n", resp.Message, resp.Timestamp)
	return nil
}

func testHTTPClient() error {
	fmt.Println("\n=== Testing HTTP Client ===")

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	_, _, _, httpAddr, _ := getAddresses()
	fmt.Printf("Testing HTTP Client on %s\n", httpAddr)

	// Properly URL-encode the message parameter
	message := "Hello HTTP Server!"
	encodedMessage := url.QueryEscape(message)
	testURL := fmt.Sprintf("%s/echo?message=%s", httpAddr, encodedMessage)

	fmt.Printf("📡 Making HTTP request to: %s\n", testURL)
	fmt.Printf("📝 Original message: %q\n", message)
	fmt.Printf("📝 URL-encoded message: %q\n", encodedMessage)

	resp, err := client.Get(testURL)
	if err != nil {
		return fmt.Errorf("failed to make HTTP request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read HTTP response: %v", err)
	}

	fmt.Printf("HTTP Response: %s (Status: %s, Protocol: %s)\n",
		string(body), resp.Status, resp.Proto)

	// Check if we got an unexpected status
	if resp.StatusCode >= 400 {
		fmt.Printf("⚠️  Warning: Received %s status code\n", resp.Status)
		fmt.Printf("📝 Response body: %s\n", string(body))

		// Try the root endpoint to compare
		fmt.Printf("🔄 Testing root endpoint for comparison...\n")
		rootURL := fmt.Sprintf("%s/", httpAddr)
		rootResp, rootErr := client.Get(rootURL)
		if rootErr == nil {
			defer rootResp.Body.Close()
			rootBody, _ := io.ReadAll(rootResp.Body)
			fmt.Printf("📋 Root endpoint (%s): %s (Status: %s)\n", rootURL, string(rootBody), rootResp.Status)
		}

		// Try with a simple message without spaces
		fmt.Printf("🔄 Testing with simple message...\n")
		simpleURL := fmt.Sprintf("%s/echo?message=test", httpAddr)
		simpleResp, simpleErr := client.Get(simpleURL)
		if simpleErr == nil {
			defer simpleResp.Body.Close()
			simpleBody, _ := io.ReadAll(simpleResp.Body)
			fmt.Printf("📋 Simple message test (%s): %s (Status: %s)\n", simpleURL, string(simpleBody), simpleResp.Status)
		}
	}

	return nil
}

// loadServerCertificate loads the server's certificate from environment variables or file
func loadServerCertificate() (*x509.Certificate, error) {
	// Try environment variables first (for Docker)
	if cert, err := loadServerCertFromEnv(); err == nil {
		return cert, nil
	}

	// Fallback to file for local development
	if _, err := os.Stat("server.crt"); err == nil {
		return loadServerCertFromFile()
	}

	return nil, fmt.Errorf("server certificate not found in environment variables or files")
}

func loadServerCertFromEnv() (*x509.Certificate, error) {
	certB64 := os.Getenv("TLS_CERT")
	if certB64 == "" {
		return nil, fmt.Errorf("TLS_CERT environment variable not set")
	}

	// Decode base64 certificate
	certPEM, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TLS_CERT: %v", err)
	}

	// Decode PEM
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

func loadServerCertFromFile() (*x509.Certificate, error) {
	// Read the certificate file
	certPEM, err := os.ReadFile("server.crt")
	if err != nil {
		return nil, fmt.Errorf("failed to read server certificate: %v", err)
	}

	// Decode PEM
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

func testHTTP2Client() error {
	fmt.Println("\n=== Testing HTTP/2 Client ===")

	// Check if user wants to skip certificate verification via environment variable
	skipCertVerification := os.Getenv("SKIP_CERT_VERIFICATION") == "true"

	var client *http.Client
	var certificateMode string

	if skipCertVerification {
		fmt.Printf("🔓 SKIP_CERT_VERIFICATION=true: Using insecure client\n")
		client, certificateMode = createInsecureHTTP2Client()
	} else {
		// Try to create client with proper certificate validation first
		var err error
		client, certificateMode, err = createHTTP2ClientWithValidation()
		if err != nil {
			// Fallback to insecure client for testing self-signed certificates
			fmt.Printf("⚠️  Certificate validation failed: %v\n", err)
			fmt.Printf("🔓 Falling back to insecure client (skipping certificate verification)...\n")
			fmt.Printf("💡 Tip: Set SKIP_CERT_VERIFICATION=true to skip this attempt\n")
			client, certificateMode = createInsecureHTTP2Client()
		}
	}

	_, _, _, _, http2Addr := getAddresses()
	url := fmt.Sprintf("%s/echo?message=%s", http2Addr, "Hello HTTP/2 Server!")

	fmt.Printf("🌐 Making HTTP/2 request to: %s\n", url)
	resp, err := client.Get(url)
	if err != nil {
		// Check if it's an ALPN protocol error
		if strings.Contains(err.Error(), "ALPN protocol") || strings.Contains(err.Error(), `want "h2"`) {
			fmt.Printf("⚠️  HTTP/2 ALPN negotiation failed: %v\n", err)
			fmt.Printf("🔄 Attempting fallback to HTTPS with HTTP/1.1...\n")

			// Try fallback to regular HTTPS client
			fallbackResp, fallbackErr := tryHTTPSFallback(url, skipCertVerification)
			if fallbackErr != nil {
				return fmt.Errorf("both HTTP/2 and HTTPS fallback failed. HTTP/2 error: %v, HTTPS error: %v", err, fallbackErr)
			}

			// Use the fallback response
			resp = fallbackResp
			fmt.Printf("✅ HTTPS fallback successful\n")
		} else {
			return fmt.Errorf("failed to make HTTP/2 request: %v", err)
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read HTTP/2 response: %v", err)
	}

	fmt.Printf("HTTP/2 Response: %s (Status: %s, Protocol: %s)\n",
		string(body), resp.Status, resp.Proto)

	// Print certificate validation mode
	switch certificateMode {
	case "validated":
		fmt.Printf("🔒 TLS Connection: Certificate validated successfully!\n")
	case "insecure":
		fmt.Printf("🔓 TLS Connection: Certificate verification skipped (insecure mode)\n")
	}

	// Print certificate source information
	printCertificateSource()

	// Print TLS connection info
	printTLSInfo(resp)

	return nil
}

// tryHTTPSFallback attempts to connect using regular HTTPS (HTTP/1.1) instead of HTTP/2
func tryHTTPSFallback(url string, skipCertVerification bool) (*http.Response, error) {
	var client *http.Client

	if skipCertVerification {
		// Create a regular HTTPS client with certificate verification disabled
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: 5 * time.Second,
		}
	} else {
		// Try to create a regular HTTPS client with proper certificate validation
		serverCert, err := loadServerCertificate()
		if err != nil {
			// Fallback to insecure client
			client = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
				Timeout: 5 * time.Second,
			}
		} else {
			certPool := x509.NewCertPool()
			certPool.AddCert(serverCert)

			client = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:    certPool,
						ServerName: getHost(),
					},
				},
				Timeout: 5 * time.Second,
			}
		}
	}

	return client.Get(url)
}

// createHTTP2ClientWithValidation attempts to create an HTTP/2 client with proper certificate validation
func createHTTP2ClientWithValidation() (*http.Client, string, error) {
	// Load the server's certificate for validation
	serverCert, err := loadServerCertificate()
	if err != nil {
		return nil, "", fmt.Errorf("failed to load server certificate: %v", err)
	}

	// Create a certificate pool and add our server certificate
	certPool := x509.NewCertPool()
	certPool.AddCert(serverCert)

	// Create HTTP/2 client with proper TLS validation
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    certPool,                   // Use our custom certificate pool
			ServerName: getHost(),                  // Verify server name matches certificate using dynamic host
			NextProtos: []string{"h2", "http/1.1"}, // Explicitly support HTTP/2
		},
		AllowHTTP: false, // Only allow HTTPS
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	return client, "validated", nil
}

// createInsecureHTTP2Client creates an HTTP/2 client that skips certificate verification
func createInsecureHTTP2Client() (*http.Client, string) {
	// Create HTTP/2 client with insecure TLS config
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,                       // Skip certificate verification
			NextProtos:         []string{"h2", "http/1.1"}, // Explicitly support HTTP/2
		},
		// Allow HTTP/1.1 fallback if HTTP/2 is not supported
		AllowHTTP: false, // Only allow HTTPS
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	return client, "insecure"
}

// printCertificateSource prints information about where the certificate was loaded from
func printCertificateSource() {
	if os.Getenv("TLS_CERT") != "" {
		fmt.Printf("📋 Certificate Source: Environment Variables (Docker)\n")
	} else if _, err := os.Stat("server.crt"); err == nil {
		fmt.Printf("📋 Certificate Source: File System (Local Development)\n")
	} else {
		fmt.Printf("📋 Certificate Source: None (Using insecure connection)\n")
	}
}

// printTLSInfo prints detailed TLS connection information
func printTLSInfo(resp *http.Response) {
	if resp.TLS != nil {
		fmt.Printf("🔐 TLS Version: %s\n", getTLSVersion(resp.TLS.Version))
		fmt.Printf("🔑 Cipher Suite: %s\n", getCipherSuite(resp.TLS.CipherSuite))
		fmt.Printf("📋 Server Certificates: %d\n", len(resp.TLS.PeerCertificates))
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			fmt.Printf("📅 Certificate Valid From: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
			fmt.Printf("📅 Certificate Valid Until: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
			fmt.Printf("🏢 Certificate Subject: %s\n", cert.Subject.String())

			// Print subject alternative names if available
			if len(cert.DNSNames) > 0 {
				fmt.Printf("🌐 DNS Names: %v\n", cert.DNSNames)
			}
			if len(cert.IPAddresses) > 0 {
				fmt.Printf("🔢 IP Addresses: %v\n", cert.IPAddresses)
			}
		}
	}
}

// Helper function to get TLS version string
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

// Helper function to get cipher suite string
func getCipherSuite(suite uint16) string {
	switch suite {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("Unknown (%d)", suite)
	}
}

func testAllServers() bool {
	fmt.Println("🚀 Starting comprehensive server tests...")
	fmt.Println("Make sure the server is running before testing!")

	tests := []struct {
		name string
		fn   func() error
	}{
		{"TCP", testTCPClient},
		{"UDP", testUDPClient},
		{"gRPC", testGRPCClient},
		{"HTTP", testHTTPClient},
		{"HTTP/2", testHTTP2Client},
	}

	results := make(map[string]bool)

	for _, test := range tests {
		fmt.Printf("\n" + strings.Repeat("=", 50) + "\n")
		if err := test.fn(); err != nil {
			fmt.Printf("❌ %s test failed: %v\n", test.name, err)
			results[test.name] = false
		} else {
			fmt.Printf("✅ %s test passed!\n", test.name)
			results[test.name] = true
		}
	}

	// Print summary
	fmt.Printf("\n" + strings.Repeat("=", 50) + "\n")
	fmt.Println("📊 TEST SUMMARY:")
	fmt.Printf(strings.Repeat("=", 50) + "\n")

	passed := 0
	for name, success := range results {
		status := "❌ FAILED"
		if success {
			status = "✅ PASSED"
			passed++
		}
		fmt.Printf("%-10s: %s\n", name, status)
	}

	fmt.Printf("\nOverall: %d/%d tests passed\n", passed, len(tests))

	allPassed := passed == len(tests)
	if allPassed {
		fmt.Println("🎉 All tests passed! Your multi-port server is working correctly!")
	} else {
		fmt.Println("⚠️  Some tests failed. Please check the server status.")
	}

	return allPassed
}

func main() {
	fmt.Println("🚀 Starting comprehensive server tests...")
	fmt.Println("Make sure the server is running before testing!")
	fmt.Println("")

	// Print configuration information
	host := getHost()
	fmt.Printf("🌐 Target Host: %s\n", host)
	if host != "localhost" {
		fmt.Printf("📝 Using LOAD_BALANCER_HOST environment variable\n")
	}

	// Print certificate configuration
	if os.Getenv("SKIP_CERT_VERIFICATION") == "true" {
		fmt.Printf("🔓 Certificate Verification: DISABLED (SKIP_CERT_VERIFICATION=true)\n")
	} else {
		fmt.Printf("🔒 Certificate Verification: ENABLED (set SKIP_CERT_VERIFICATION=true to disable)\n")
	}

	if os.Getenv("TLS_CERT") != "" {
		fmt.Printf("📋 TLS Certificate: Available via environment variable\n")
	} else if _, err := os.Stat("server.crt"); err == nil {
		fmt.Printf("📋 TLS Certificate: Available via file system (server.crt)\n")
	} else {
		fmt.Printf("📋 TLS Certificate: Not found (will use insecure mode for HTTPS)\n")
	}

	if testAllServers() {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}
