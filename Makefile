# Multi-Port Server and Client
.PHONY: all build-server build-client build run-server run-client test clean docker-build docker-run docker-test docker-clean

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

# Run server
run-server: build-server
	@echo "Starting multi-port server..."
	./bin/server

# Run client (assumes server is already running)
run-client: build-client
	@echo "Running client tests..."
	./bin/client

# Test end-to-end (run server in background, test, then stop)
test: build
	@echo "Running end-to-end test..."
	@./bin/server > server.log 2>&1 & \
	SERVER_PID=$$!; \
	echo "Server started with PID $$SERVER_PID"; \
	sleep 5; \
	./bin/client; \
	TEST_RESULT=$$?; \
	echo "Stopping server..."; \
	kill $$SERVER_PID 2>/dev/null || true; \
	wait $$SERVER_PID 2>/dev/null || true; \
	rm -f server.log; \
	exit $$TEST_RESULT

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f server.log

# Docker targets
docker-build:
	@echo "Building Docker image..."
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
	@echo "Testing containerized server..."
	@make run-client
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

# Help
help:
	@echo "Available targets:"
	@echo "  build          - Build both server and client"
	@echo "  build-server   - Build server only"
	@echo "  build-client   - Build client only"
	@echo "  run-server     - Build and run server"
	@echo "  run-client     - Build and run client (requires server to be running)"
	@echo "  test           - Run end-to-end test (starts server, runs client, stops server)"
	@echo "  clean          - Remove build artifacts"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Build and run Docker container"
	@echo "  docker-test    - Build, run, and test Docker container"
	@echo "  docker-clean   - Clean Docker resources"
	@echo "  help           - Show this help message" 