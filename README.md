# Multi-Port Server Application

A comprehensive Go application that demonstrates 5 different server types running concurrently on different ports, with a client application for end-to-end testing.

## 🚀 Features

This application implements **5 different server protocols**:

1. **TCP Server** (Port 8001) - Raw TCP socket communication
2. **UDP Server** (Port 8002) - UDP packet communication  
3. **gRPC Server** (Port 8003) - Google's RPC framework
4. **HTTP Server** (Port 8004) - Standard HTTP/1.1 server
5. **HTTP/2 Server** (Port 8005) - HTTP/2 with TLS

Each server implements an "echo" functionality that responds with the received message plus additional metadata.

## 📁 Project Structure

```
nlb/
├── go.mod                 # Go module dependencies
├── Makefile              # Build and run commands
├── README.md             # This file
├── Dockerfile            # Docker container definition
├── docker-compose.yml    # Docker Compose configuration
├── .dockerignore         # Docker build context exclusions
├── proto/
│   ├── service.proto     # gRPC service definition
│   ├── service.pb.go     # Generated protobuf code
│   └── service_grpc.pb.go # Generated gRPC code
├── server/
│   └── main.go           # Multi-port server application
└── client/
    └── main.go           # Client testing application
```

## 🛠️ Prerequisites

### For Local Development
- **Go 1.21+** installed
- **Protocol Buffers compiler** (protoc) - for gRPC code generation
- **Make** (optional, for using Makefile commands)

### For Docker Deployment
- **Docker** installed and running
- **Docker Compose** (optional, for orchestration)

### Installing Dependencies

```bash
# Install protoc (macOS)
brew install protobuf

# Install Go protobuf plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Download Go dependencies
go mod tidy
```

## 🚀 Quick Start

### Option 1: Using Docker (Recommended for Production)

```bash
# Using Docker directly
make docker-build
make docker-run

# Test the containerized server
make run-client

# Clean up
make docker-clean

# Using Docker Compose
docker-compose up -d
docker-compose logs -f nlb-server
docker-compose down
```

### Option 2: Using Makefile (Local Development)

```bash
# Build both server and client
make build

# Run automated end-to-end test
make test

# Or run manually:
# Terminal 1: Start server
make run-server

# Terminal 2: Run client tests
make run-client
```

### Option 3: Manual Commands

```bash
# Build applications
go build -o bin/server ./server
go build -o bin/client ./client

# Terminal 1: Start server
./bin/server

# Terminal 2: Test all endpoints
./bin/client
```

## 🐳 Docker Usage

### Building and Running with Docker

```bash
# Build Docker image
docker build -t nlb-server:latest .

# Run container with all ports exposed
docker run -d --name nlb-server \
  -p 8001:8001 \
  -p 8002:8002/udp \
  -p 8003:8003 \
  -p 8004:8004 \
  -p 8005:8005 \
  nlb-server:latest

# Check container health
docker ps
docker logs nlb-server

# Stop and remove container
docker stop nlb-server
docker rm nlb-server
```

### Using Docker Compose

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Check health
docker-compose ps

# Stop services
docker-compose down
```

### Container Features

- **Multi-stage build** for minimal image size (~15MB final image)
- **Non-root user** for security
- **Health checks** using the built-in client
- **Signal handling** for graceful shutdown
- **All ports exposed** (8001-8005)

## 📡 Server Details

### Port Configuration

| Protocol | Port | Address | Description |
|----------|------|---------|-------------|
| TCP      | 8001 | :8001   | Raw TCP socket |
| UDP      | 8002 | :8002   | UDP packets |
| gRPC     | 8003 | :8003   | gRPC service |
| HTTP     | 8004 | :8004   | HTTP/1.1 |
| HTTP/2   | 8005 | :8005   | HTTP/2 + TLS |

### Server Features

- **Concurrent Processing**: All 5 servers run simultaneously using goroutines
- **Echo Functionality**: Each server echoes back received messages with protocol-specific formatting
- **Error Handling**: Robust error handling and logging
- **TLS Support**: HTTP/2 server includes self-signed certificate generation
- **gRPC Reflection**: gRPC server includes reflection for debugging

## 🧪 Client Testing

The client application automatically tests all 5 server types:

```bash
./bin/client
```

### Sample Output

```
🚀 Starting comprehensive server tests...
Make sure the server is running before testing!

==================================================
=== Testing TCP Client ===
TCP Response: TCP Echo: Hello TCP Server!
✅ TCP test passed!

==================================================
=== Testing UDP Client ===
UDP Response: UDP Echo: Hello UDP Server!
✅ UDP test passed!

==================================================
=== Testing gRPC Client ===
gRPC Response: gRPC Echo: Hello gRPC Server! (Timestamp: 1701234567)
✅ gRPC test passed!

==================================================
=== Testing HTTP Client ===
HTTP Response: HTTP Echo: Hello HTTP Server! (Status: 200 OK, Protocol: HTTP/1.1)
✅ HTTP test passed!

==================================================
=== Testing HTTP/2 Client ===
HTTP/2 Response: HTTP/2 Echo: Hello HTTP/2 Server! (Protocol: HTTP/2.0) (Status: 200 OK, Protocol: HTTP/2.0)
✅ HTTP/2 test passed!

==================================================
📊 TEST SUMMARY:
==================================================
TCP       : ✅ PASSED
UDP       : ✅ PASSED
gRPC      : ✅ PASSED
HTTP      : ✅ PASSED
HTTP/2    : ✅ PASSED

Overall: 5/5 tests passed
🎉 All tests passed! Your multi-port server is working correctly!
```

## 🔧 Manual Testing

### TCP Client (using netcat)
```bash
echo "Hello TCP" | nc localhost 8001
```

### UDP Client (using netcat)
```bash
echo "Hello UDP" | nc -u localhost 8002
```

### HTTP Client (using curl)
```bash
curl "http://localhost:8004/echo?message=Hello%20HTTP"
```

### HTTP/2 Client (using curl)
```bash
curl -k "https://localhost:8005/echo?message=Hello%20HTTP2"
```

### gRPC Client (using grpcurl)
```bash
# Install grpcurl first: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# List services
grpcurl -plaintext localhost:8003 list

# Call Echo method
grpcurl -plaintext -d '{"message": "Hello gRPC"}' localhost:8003 nlb.EchoService/Echo
```

## 🛠️ Development

### Building Individual Components

```bash
# Build server only
make build-server

# Build client only  
make build-client

# Clean build artifacts
make clean
```

### Docker Development

```bash
# Build Docker image
make docker-build

# Run and test Docker container
make docker-test

# Clean Docker resources
make docker-clean
```

### Modifying the gRPC Service

1. Edit `proto/service.proto`
2. Regenerate Go code:
   ```bash
   protoc --go_out=. --go_opt=paths=source_relative \
          --go-grpc_out=. --go-grpc_opt=paths=source_relative \
          proto/service.proto
   ```
3. Rebuild applications

## 📊 Performance Notes

- **TCP/UDP**: Low latency, minimal overhead
- **gRPC**: Efficient binary protocol, good for microservices
- **HTTP/1.1**: Standard web protocol, text-based
- **HTTP/2**: Multiplexed connections, server push capable
- **Container**: ~15MB image size, <50MB runtime memory

## 🔒 Security Notes

⚠️ **For Development Only**: This application uses:
- Self-signed certificates for HTTP/2
- Insecure gRPC connections
- No authentication or authorization

For production use, implement proper:
- TLS certificate management
- Authentication mechanisms
- Input validation and sanitization
- Rate limiting and DOS protection
- Container security scanning
- Network policies

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Test with Docker: `make docker-test`
6. Submit a pull request

## 📝 License

This project is for educational purposes. Feel free to use and modify as needed.

---

## 🎯 Use Cases

This multi-port server demonstration is useful for:

- **Learning different network protocols**
- **Microservice architecture prototyping**
- **Load balancer testing**
- **Network infrastructure validation**
- **Protocol performance comparison**
- **Educational networking workshops**
- **Container orchestration learning**
- **Docker networking examples** 