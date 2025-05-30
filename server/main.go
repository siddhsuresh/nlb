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
	"runtime"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
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
	requestCount int64
}

func (s *echoServer) Echo(ctx context.Context, req *pb.EchoRequest) (*pb.EchoResponse, error) {
	s.requestCount++
	startTime := time.Now()

	// Extract client information from context
	clientInfo := "unknown"
	if peer, ok := peer.FromContext(ctx); ok {
		clientInfo = peer.Addr.String()
	}

	log.Printf("📨 [gRPC] Request #%d received from %s: %q", s.requestCount, clientInfo, req.Message)

	responseMsg := fmt.Sprintf("gRPC Echo: %s", req.Message)
	timestamp := time.Now().Unix()

	response := &pb.EchoResponse{
		Message:   responseMsg,
		Timestamp: timestamp,
	}

	duration := time.Since(startTime)
	log.Printf("📤 [gRPC] Request #%d response sent to %s in %v: %q (timestamp: %d)",
		s.requestCount, clientInfo, duration, responseMsg, timestamp)

	return response, nil
}

// TCP Server
func startTCPServer() {
	log.Printf("🚀 [TCP] Initializing TCP server on port %s...", TCPPort)

	listener, err := net.Listen("tcp", TCPPort)
	if err != nil {
		log.Fatalf("❌ [TCP] FATAL: Failed to bind TCP listener on port %s: %v", TCPPort, err)
	}
	defer func() {
		log.Printf("🔒 [TCP] Closing TCP listener on port %s", TCPPort)
		listener.Close()
	}()

	log.Printf("✅ [TCP] TCP server successfully bound and listening on port %s", TCPPort)
	log.Printf("📋 [TCP] Server details - Address: %s, Network: tcp", listener.Addr().String())

	connectionCount := 0
	for {
		log.Printf("⏳ [TCP] Waiting for incoming TCP connections...")

		conn, err := listener.Accept()
		if err != nil {
			log.Printf("⚠️  [TCP] ERROR: Failed to accept TCP connection: %v", err)
			continue
		}

		connectionCount++
		log.Printf("🔗 [TCP] Connection #%d accepted from %s -> %s",
			connectionCount, conn.RemoteAddr().String(), conn.LocalAddr().String())

		go handleTCPConnection(conn, connectionCount)
	}
}

func handleTCPConnection(conn net.Conn, connID int) {
	startTime := time.Now()
	remoteAddr := conn.RemoteAddr().String()
	localAddr := conn.LocalAddr().String()

	log.Printf("🔄 [TCP] [Conn#%d] Starting connection handler for %s -> %s", connID, remoteAddr, localAddr)

	defer func() {
		duration := time.Since(startTime)
		log.Printf("🔚 [TCP] [Conn#%d] Connection closed. Duration: %v, Remote: %s", connID, duration, remoteAddr)
		conn.Close()
	}()

	log.Printf("📖 [TCP] [Conn#%d] Reading data from client %s...", connID, remoteAddr)

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("❌ [TCP] [Conn#%d] ERROR: Failed to read from connection %s: %v", connID, remoteAddr, err)
		return
	}

	message := string(buffer[:n])
	log.Printf("📨 [TCP] [Conn#%d] Received %d bytes from %s: %q", connID, n, remoteAddr, message)

	response := fmt.Sprintf("TCP Echo: %s", message)
	log.Printf("📤 [TCP] [Conn#%d] Sending response (%d bytes) to %s: %q", connID, len(response), remoteAddr, response)

	bytesWritten, err := conn.Write([]byte(response))
	if err != nil {
		log.Printf("❌ [TCP] [Conn#%d] ERROR: Failed to write response to %s: %v", connID, remoteAddr, err)
		return
	}

	log.Printf("✅ [TCP] [Conn#%d] Successfully sent %d bytes to %s", connID, bytesWritten, remoteAddr)
}

// UDP Server
func startUDPServer() {
	log.Printf("🚀 [UDP] Initializing UDP server on port %s...", UDPPort)

	addr, err := net.ResolveUDPAddr("udp", UDPPort)
	if err != nil {
		log.Fatalf("❌ [UDP] FATAL: Failed to resolve UDP address %s: %v", UDPPort, err)
	}
	log.Printf("🎯 [UDP] Resolved UDP address: %s", addr.String())

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("❌ [UDP] FATAL: Failed to bind UDP socket on %s: %v", UDPPort, err)
	}
	defer func() {
		log.Printf("🔒 [UDP] Closing UDP socket on %s", UDPPort)
		conn.Close()
	}()

	log.Printf("✅ [UDP] UDP server successfully bound and listening on %s", UDPPort)
	log.Printf("📋 [UDP] Server details - Local address: %s, Network: udp", conn.LocalAddr().String())

	buffer := make([]byte, 1024)
	packetCount := 0

	for {
		log.Printf("⏳ [UDP] Waiting for incoming UDP packets...")

		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("❌ [UDP] ERROR: Failed to read UDP packet: %v", err)
			continue
		}

		packetCount++
		message := string(buffer[:n])
		log.Printf("📨 [UDP] Packet #%d received (%d bytes) from %s: %q",
			packetCount, n, clientAddr.String(), message)

		response := fmt.Sprintf("UDP Echo: %s", message)
		log.Printf("📤 [UDP] Sending response (%d bytes) to %s: %q",
			len(response), clientAddr.String(), response)

		bytesWritten, err := conn.WriteToUDP([]byte(response), clientAddr)
		if err != nil {
			log.Printf("❌ [UDP] ERROR: Failed to send response to %s: %v", clientAddr.String(), err)
			continue
		}

		log.Printf("✅ [UDP] Packet #%d successfully sent %d bytes to %s",
			packetCount, bytesWritten, clientAddr.String())
	}
}

// gRPC Server
func startGRPCServer() {
	log.Printf("🚀 [gRPC] Initializing gRPC server on port %s...", GRPCPort)

	listener, err := net.Listen("tcp", GRPCPort)
	if err != nil {
		log.Fatalf("❌ [gRPC] FATAL: Failed to bind gRPC listener on port %s: %v", GRPCPort, err)
	}
	log.Printf("🎯 [gRPC] gRPC listener bound to %s", listener.Addr().String())

	log.Printf("⚙️  [gRPC] Creating gRPC server instance...")
	s := grpc.NewServer()

	log.Printf("📋 [gRPC] Registering EchoService...")
	pb.RegisterEchoServiceServer(s, &echoServer{})

	log.Printf("🔍 [gRPC] Enabling gRPC reflection for debugging...")
	reflection.Register(s)

	log.Printf("✅ [gRPC] gRPC server successfully configured and listening on %s", GRPCPort)
	log.Printf("📋 [gRPC] Server details - Address: %s, Services: [EchoService], Reflection: enabled",
		listener.Addr().String())

	log.Printf("🔄 [gRPC] Starting to serve gRPC requests...")
	if err := s.Serve(listener); err != nil {
		log.Fatalf("❌ [gRPC] FATAL: Failed to serve gRPC on %s: %v", GRPCPort, err)
	}
}

// HTTP Server
func startHTTPServer() {
	log.Printf("🚀 [HTTP] Initializing HTTP server on port %s...", HTTPPort)

	requestCount := 0
	mux := http.NewServeMux()

	log.Printf("📋 [HTTP] Registering /echo endpoint...")
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		startTime := time.Now()

		log.Printf("📨 [HTTP] Request #%d: %s %s from %s",
			requestCount, r.Method, r.URL.Path, r.RemoteAddr)
		log.Printf("📋 [HTTP] Request #%d details - User-Agent: %s, Protocol: %s, Host: %s",
			requestCount, r.UserAgent(), r.Proto, r.Host)

		message := r.URL.Query().Get("message")
		if message == "" {
			message = "Hello from HTTP"
			log.Printf("📝 [HTTP] Request #%d: No message parameter, using default: %q", requestCount, message)
		} else {
			log.Printf("📝 [HTTP] Request #%d: Message parameter received: %q", requestCount, message)
		}

		response := fmt.Sprintf("HTTP Echo: %s", message)

		log.Printf("📤 [HTTP] Request #%d: Sending response (%d bytes): %q",
			requestCount, len(response), response)

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))

		duration := time.Since(startTime)
		log.Printf("✅ [HTTP] Request #%d completed in %v", requestCount, duration)
	})

	// Add a default handler for all other paths
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			log.Printf("⚠️  [HTTP] Request to unknown path: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("404 Not Found - Available endpoints: /echo"))
			return
		}

		log.Printf("📨 [HTTP] Root request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("HTTP Server is running! Available endpoints: /echo"))
	})

	server := &http.Server{
		Addr:    HTTPPort,
		Handler: mux,
	}

	log.Printf("✅ [HTTP] HTTP server configured and starting on %s", HTTPPort)
	log.Printf("📋 [HTTP] Server details - Address: %s, Endpoints: [/echo]", HTTPPort)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("❌ [HTTP] FATAL: Failed to serve HTTP on %s: %v", HTTPPort, err)
	}
}

// HTTP/2 Server
func startHTTP2Server() {
	log.Printf("🚀 [HTTP/2] Initializing HTTP/2 server on port %s...", HTTP2Port)

	requestCount := 0
	mux := http.NewServeMux()

	log.Printf("📋 [HTTP/2] Registering /echo endpoint...")
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		startTime := time.Now()

		log.Printf("📨 [HTTP/2] Request #%d: %s %s from %s",
			requestCount, r.Method, r.URL.Path, r.RemoteAddr)
		log.Printf("📋 [HTTP/2] Request #%d details - User-Agent: %s, Protocol: %s, Host: %s",
			requestCount, r.UserAgent(), r.Proto, r.Host)

		message := r.URL.Query().Get("message")
		if message == "" {
			message = "Hello from HTTP/2"
			log.Printf("📝 [HTTP/2] Request #%d: No message parameter, using default: %q", requestCount, message)
		} else {
			log.Printf("📝 [HTTP/2] Request #%d: Message parameter received: %q", requestCount, message)
		}

		response := fmt.Sprintf("HTTP/2 Echo: %s (Protocol: %s)", message, r.Proto)

		log.Printf("📤 [HTTP/2] Request #%d: Sending response (%d bytes): %q",
			requestCount, len(response), response)

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))

		duration := time.Since(startTime)
		log.Printf("✅ [HTTP/2] Request #%d completed in %v using protocol %s",
			requestCount, duration, r.Proto)
	})

	log.Printf("🔐 [HTTP/2] Loading TLS certificate for HTTPS/HTTP2...")
	// Generate self-signed certificate for HTTP/2
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("❌ [HTTP/2] FATAL: Failed to load TLS certificate: %v", err)
	}
	log.Printf("✅ [HTTP/2] TLS certificate loaded successfully")

	server := &http.Server{
		Addr:    HTTP2Port,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	log.Printf("⚙️  [HTTP/2] Configuring HTTP/2 support...")
	// Configure HTTP/2
	http2.ConfigureServer(server, &http2.Server{})

	log.Printf("✅ [HTTP/2] HTTP/2 server configured and starting on %s (HTTPS)", HTTP2Port)
	log.Printf("📋 [HTTP/2] Server details - Address: %s, Endpoints: [/echo], TLS: enabled, HTTP/2: enabled", HTTP2Port)

	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("❌ [HTTP/2] FATAL: Failed to serve HTTPS/HTTP2 on %s: %v", HTTP2Port, err)
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
	log.Printf("🌟 ==================== NETWORK LOAD BALANCER SERVER ====================")
	log.Printf("🚀 Starting multi-protocol server with 5 different service types...")
	log.Printf("📍 Server Configuration:")
	log.Printf("   📡 TCP Server:    %s", TCPPort)
	log.Printf("   📡 UDP Server:    %s", UDPPort)
	log.Printf("   📡 gRPC Server:   %s", GRPCPort)
	log.Printf("   📡 HTTP Server:   %s", HTTPPort)
	log.Printf("   📡 HTTP/2 Server: %s (HTTPS)", HTTP2Port)
	log.Printf("🕒 Startup Time: %s", time.Now().Format(time.RFC3339))
	log.Printf("💻 System: Go %s on %s", runtime.Version(), runtime.GOOS)
	log.Printf("⚙️  Process ID: %d", os.Getpid())
	log.Printf("========================================================================")

	var wg sync.WaitGroup
	serverCount := 5

	log.Printf("🔄 Initializing %d concurrent servers...", serverCount)

	// Start all servers concurrently
	wg.Add(serverCount)

	log.Printf("🎯 [TCP] Launching TCP server goroutine...")
	go func() {
		defer func() {
			log.Printf("🔚 [TCP] TCP server goroutine terminated")
			wg.Done()
		}()
		startTCPServer()
	}()

	log.Printf("🎯 [UDP] Launching UDP server goroutine...")
	go func() {
		defer func() {
			log.Printf("🔚 [UDP] UDP server goroutine terminated")
			wg.Done()
		}()
		startUDPServer()
	}()

	log.Printf("🎯 [gRPC] Launching gRPC server goroutine...")
	go func() {
		defer func() {
			log.Printf("🔚 [gRPC] gRPC server goroutine terminated")
			wg.Done()
		}()
		startGRPCServer()
	}()

	log.Printf("🎯 [HTTP] Launching HTTP server goroutine...")
	go func() {
		defer func() {
			log.Printf("🔚 [HTTP] HTTP server goroutine terminated")
			wg.Done()
		}()
		startHTTPServer()
	}()

	log.Printf("🎯 [HTTP/2] Launching HTTP/2 server goroutine...")
	go func() {
		defer func() {
			log.Printf("🔚 [HTTP/2] HTTP/2 server goroutine terminated")
			wg.Done()
		}()
		startHTTP2Server()
	}()

	// Give servers a moment to initialize
	time.Sleep(2 * time.Second)

	log.Printf("🎉 ==================== ALL SERVERS STARTED ====================")
	log.Printf("✅ All %d servers launched successfully and are ready to accept connections!", serverCount)
	log.Printf("📋 Service Summary:")
	log.Printf("   🔗 TCP Echo Service:    telnet localhost%s", TCPPort)
	log.Printf("   📦 UDP Echo Service:    nc -u localhost %s", UDPPort[1:]) // Remove the ":"
	log.Printf("   🚀 gRPC Echo Service:   grpcurl -plaintext localhost%s EchoService/Echo", GRPCPort)
	log.Printf("   🌐 HTTP Echo Service:   curl http://localhost%s/echo?message=hello", HTTPPort)
	log.Printf("   🔒 HTTP/2 Echo Service: curl -k https://localhost%s/echo?message=hello", HTTP2Port)
	log.Printf("==============================================================")
	log.Printf("⏳ Server will run indefinitely. Press Ctrl+C to stop all services.")

	wg.Wait()

	log.Printf("🛑 All servers have stopped. Exiting application.")
}
