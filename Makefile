# Multi-Port Server and Client
.PHONY: all build-server build-client build run-server run-client test test-certs clean docker-build docker-run docker-test docker-clean

# Default target
all: build

# Build both server and client
build: build-server build-client

# Build server
build-server:
	@echo "Building server..."
	go build -o bin/server ./server

# Build client
build-client:
	@echo "Building client..."
	go build -o bin/client ./client

# Generate certificates for local development
test-certs:
	@echo "Generating certificates for local development..."
	@chmod +x scripts/test-certs.sh
	@./scripts/test-certs.sh

# Run server (with certificate check)
run-server: build-server
	@echo "Starting multi-port server..."
	@if [ ! -f "certs.env" ]; then \
		echo "⚠️  No certificates found. Generating them..."; \
		make test-certs; \
	fi
	@echo "Loading certificates from environment..."
	@bash -c 'source certs.env && ./bin/server'

# Run client (assumes server is already running)
run-client: build-client
	@echo "Running client tests..."
	@if [ -f "certs.env" ]; then \
		echo "Loading certificates for client..."; \
		bash -c 'source certs.env && ./bin/client'; \
	else \
		echo "No certificate environment found, running without TLS validation..."; \
		./bin/client; \
	fi

# Test end-to-end with environment-based certificates
test: build test-certs
	@echo "Running end-to-end test with TLS certificates..."
	@bash -c 'source certs.env && ./bin/server > server.log 2>&1 & \
	SERVER_PID=$$!; \
	echo "Server started with PID $$SERVER_PID"; \
	sleep 5; \
	source certs.env && ./bin/client; \
	TEST_RESULT=$$?; \
	echo "Stopping server..."; \
	kill $$SERVER_PID 2>/dev/null || true; \
	wait $$SERVER_PID 2>/dev/null || true; \
	rm -f server.log; \
	exit $$TEST_RESULT'

# Clean build artifacts and certificates
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f server.log
	rm -f certs.env
	rm -f cert-gen

# Docker targets
docker-build:
	@echo "Building Docker image with embedded certificates..."
	docker build -t nlb-server:latest .

docker-run: docker-build
	@echo "Running Docker container..."
	docker run -d --name nlb-server \
		-p 8001:8001 \
		-p 8002:8002/udp \
		-p 8003:8003 \
		-p 8004:8004 \
		-p 8005:8005 \
		nlb-server:latest

docker-test: docker-run
	@echo "Waiting for container to start..."
	@sleep 10
	@echo "Testing containerized server with TLS..."
	@docker exec nlb-server /bin/sh -c '. ./certs.env && ./client'
	@echo "Stopping container..."
	@docker stop nlb-server
	@docker rm nlb-server

docker-clean:
	@echo "Cleaning Docker resources..."
	@docker stop nlb-server 2>/dev/null || true
	@docker rm nlb-server 2>/dev/null || true
	@docker rmi nlb-server:latest 2>/dev/null || true

# Create bin directory
bin:
	mkdir -p bin

# Show certificate info
cert-info:
	@if [ -f "certs.env" ]; then \
		echo "📋 Certificate Environment Information:"; \
		echo "File: certs.env"; \
		echo "Variables: $$(grep -c '^TLS_' certs.env)"; \
		echo "Size: $$(wc -c < certs.env) bytes"; \
	else \
		echo "❌ No certificate environment file found. Run 'make test-certs' first."; \
	fi

# Help
help:
	@echo "Available commands:"
	@echo "  make build         - Build server and client"
	@echo "  make test-certs    - Generate TLS certificates for local development"
	@echo "  make run-server    - Start server with TLS certificates"
	@echo "  make run-client    - Run client tests"
	@echo "  make test          - Run end-to-end tests with TLS"
	@echo "  make docker-build  - Build Docker image with embedded certificates"
	@echo "  make docker-test   - Test containerized application"
	@echo "  make cert-info     - Show certificate information"
	@echo "  make clean         - Clean all build artifacts and certificates" 