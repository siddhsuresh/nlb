package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "nlb/proto"
)

const (
	TCPAddr   = "localhost:8001"
	UDPAddr   = "localhost:8002"
	GRPCAddr  = "localhost:8003"
	HTTPAddr  = "http://localhost:8004"
	HTTP2Addr = "https://localhost:8005"
)

func testTCPClient() error {
	fmt.Println("=== Testing TCP Client ===")

	conn, err := net.Dial("tcp", TCPAddr)
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

	conn, err := net.Dial("udp", UDPAddr)
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

	conn, err := grpc.Dial(GRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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

	url := fmt.Sprintf("%s/echo?message=%s", HTTPAddr, "Hello HTTP Server!")
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

func testHTTP2Client() error {
	fmt.Println("\n=== Testing HTTP/2 Client ===")

	// Create HTTP/2 client with insecure TLS for demo
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	url := fmt.Sprintf("%s/echo?message=%s", HTTP2Addr, "Hello HTTP/2 Server!")
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
	return nil
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
