package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "nlb/proto"
)

const (
	TCPPort   = ":8001"
	UDPPort   = ":8002"
	GRPCPort  = ":8003"
	HTTPPort  = ":8004"
	HTTP2Port = ":8005"
)

// gRPC service implementation
type echoServer struct {
	pb.UnimplementedEchoServiceServer
}

func (s *echoServer) Echo(ctx context.Context, req *pb.EchoRequest) (*pb.EchoResponse, error) {
	return &pb.EchoResponse{
		Message:   fmt.Sprintf("gRPC Echo: %s", req.Message),
		Timestamp: time.Now().Unix(),
	}, nil
}

// TCP Server
func startTCPServer() {
	listener, err := net.Listen("tcp", TCPPort)
	if err != nil {
		log.Fatalf("Failed to listen on TCP port %s: %v", TCPPort, err)
	}
	defer listener.Close()

	log.Printf("TCP server listening on %s", TCPPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept TCP connection: %v", err)
			continue
		}

		go handleTCPConnection(conn)
	}
}

func handleTCPConnection(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Failed to read from TCP connection: %v", err)
		return
	}

	message := string(buffer[:n])
	response := fmt.Sprintf("TCP Echo: %s", message)

	_, err = conn.Write([]byte(response))
	if err != nil {
		log.Printf("Failed to write to TCP connection: %v", err)
	}
}

// UDP Server
func startUDPServer() {
	addr, err := net.ResolveUDPAddr("udp", UDPPort)
	if err != nil {
		log.Fatalf("Failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP port %s: %v", UDPPort, err)
	}
	defer conn.Close()

	log.Printf("UDP server listening on %s", UDPPort)

	buffer := make([]byte, 1024)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Failed to read UDP packet: %v", err)
			continue
		}

		message := string(buffer[:n])
		response := fmt.Sprintf("UDP Echo: %s", message)

		_, err = conn.WriteToUDP([]byte(response), clientAddr)
		if err != nil {
			log.Printf("Failed to write UDP response: %v", err)
		}
	}
}

// gRPC Server
func startGRPCServer() {
	listener, err := net.Listen("tcp", GRPCPort)
	if err != nil {
		log.Fatalf("Failed to listen on gRPC port %s: %v", GRPCPort, err)
	}

	s := grpc.NewServer()
	pb.RegisterEchoServiceServer(s, &echoServer{})
	reflection.Register(s)

	log.Printf("gRPC server listening on %s", GRPCPort)

	if err := s.Serve(listener); err != nil {
		log.Fatalf("Failed to serve gRPC: %v", err)
	}
}

// HTTP Server
func startHTTPServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		message := r.URL.Query().Get("message")
		if message == "" {
			message = "Hello from HTTP"
		}

		response := fmt.Sprintf("HTTP Echo: %s", message)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
	})

	server := &http.Server{
		Addr:    HTTPPort,
		Handler: mux,
	}

	log.Printf("HTTP server listening on %s", HTTPPort)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to serve HTTP: %v", err)
	}
}

// HTTP/2 Server
func startHTTP2Server() {
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		message := r.URL.Query().Get("message")
		if message == "" {
			message = "Hello from HTTP/2"
		}

		response := fmt.Sprintf("HTTP/2 Echo: %s (Protocol: %s)", message, r.Proto)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
	})

	// Generate self-signed certificate for HTTP/2
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	server := &http.Server{
		Addr:    HTTP2Port,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	// Configure HTTP/2
	http2.ConfigureServer(server, &http2.Server{})

	log.Printf("HTTP/2 server listening on %s", HTTP2Port)

	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Failed to serve HTTP/2: %v", err)
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	// Try to load certificates from environment variables first
	if cert, err := loadCertFromEnv(); err == nil {
		log.Println("✅ Loaded TLS certificate from environment variables")
		return cert, nil
	}

	// Fallback to file-based certificates for local development
	if certExists("server.crt") && certExists("server.key") {
		log.Println("Loading existing certificate files...")
		return tls.LoadX509KeyPair("server.crt", "server.key")
	}

	return tls.Certificate{}, fmt.Errorf("no TLS certificate found - please run in Docker or generate certificates")
}

func loadCertFromEnv() (tls.Certificate, error) {
	certB64 := os.Getenv("TLS_CERT")
	keyB64 := os.Getenv("TLS_KEY")

	if certB64 == "" || keyB64 == "" {
		return tls.Certificate{}, fmt.Errorf("TLS_CERT or TLS_KEY environment variables not set")
	}

	// Decode base64 certificates
	certPEM, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to decode TLS_CERT: %v", err)
	}

	keyPEM, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to decode TLS_KEY: %v", err)
	}

	// Create TLS certificate from PEM data
	return tls.X509KeyPair(certPEM, keyPEM)
}

func certExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func main() {
	var wg sync.WaitGroup

	// Start all servers concurrently
	wg.Add(5)

	go func() {
		defer wg.Done()
		startTCPServer()
	}()

	go func() {
		defer wg.Done()
		startUDPServer()
	}()

	go func() {
		defer wg.Done()
		startGRPCServer()
	}()

	go func() {
		defer wg.Done()
		startHTTPServer()
	}()

	go func() {
		defer wg.Done()
		startHTTP2Server()
	}()

	log.Println("All servers started successfully!")
	log.Printf("TCP Server: %s", TCPPort)
	log.Printf("UDP Server: %s", UDPPort)
	log.Printf("gRPC Server: %s", GRPCPort)
	log.Printf("HTTP Server: %s", HTTPPort)
	log.Printf("HTTP/2 Server: %s (HTTPS)", HTTP2Port)

	wg.Wait()
}
