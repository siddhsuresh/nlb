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
	"os"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "nlb/proto"
)

// getHost returns the load balancer host from environment variable or fallback to localhost
func getHost() string {
	if host := os.Getenv("LOAD_BALANCER_HOST"); host != "" {
		return host
	}
	return "localhost"
}

// getAddresses returns the service addresses using the configured host
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
	conn, err := net.Dial("tcp", tcpAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to TCP server: %v", err)
	}
	defer conn.Close()

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
	conn, err := net.Dial("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to UDP server: %v", err)
	}
	defer conn.Close()

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
	url := fmt.Sprintf("%s/echo?message=%s", httpAddr, "Hello HTTP Server!")
	resp, err := client.Get(url)
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

	// Load the server's certificate for validation
	serverCert, err := loadServerCertificate()
	if err != nil {
		return fmt.Errorf("failed to load server certificate: %v", err)
	}

	// Create a certificate pool and add our server certificate
	certPool := x509.NewCertPool()
	certPool.AddCert(serverCert)

	// Create HTTP/2 client with proper TLS validation
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    certPool,  // Use our custom certificate pool
			ServerName: getHost(), // Verify server name matches certificate using dynamic host
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	_, _, _, _, http2Addr := getAddresses()
	url := fmt.Sprintf("%s/echo?message=%s", http2Addr, "Hello HTTP/2 Server!")
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to make HTTP/2 request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read HTTP/2 response: %v", err)
	}

	fmt.Printf("HTTP/2 Response: %s (Status: %s, Protocol: %s)\n",
		string(body), resp.Status, resp.Proto)
	fmt.Printf("🔒 TLS Connection: Certificate validated successfully!\n")

	// Print certificate source
	if os.Getenv("TLS_CERT") != "" {
		fmt.Printf("📋 Certificate Source: Environment Variables (Docker)\n")
	} else {
		fmt.Printf("📋 Certificate Source: File System (Local Development)\n")
	}

	// Print TLS connection info
	if resp.TLS != nil {
		fmt.Printf("🔐 TLS Version: %s\n", getTLSVersion(resp.TLS.Version))
		fmt.Printf("🔑 Cipher Suite: %s\n", getCipherSuite(resp.TLS.CipherSuite))
		fmt.Printf("📋 Server Certificates: %d\n", len(resp.TLS.PeerCertificates))
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			fmt.Printf("📅 Certificate Valid From: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
			fmt.Printf("📅 Certificate Valid Until: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
			fmt.Printf("🏢 Certificate Subject: %s\n", cert.Subject.String())
		}
	}

	return nil
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

func testAllServers() {
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

	if passed == len(tests) {
		fmt.Println("🎉 All tests passed! Your multi-port server is working correctly!")
	} else {
		fmt.Println("⚠️  Some tests failed. Please check the server status.")
	}
}

func main() {
	testAllServers()
}
