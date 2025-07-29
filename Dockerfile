# Build stage
FROM golang:1.21-alpine AS builder

# Install git (needed for some Go modules)
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build certificate generator
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o cert-gen ./scripts/generate-certs.go

# Generate certificates and save to environment file
RUN ./cert-gen --file

# Build the server application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server ./server

# Build the client application (optional, for testing)
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o client ./client

# Runtime stage
FROM alpine:latest

# Install ca-certificates for HTTPS connections
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy binaries from builder stage
COPY --from=builder /app/server .
COPY --from=builder /app/client .

# Copy certificates environment file
COPY --from=builder /app/certs.env .

# Change ownership to non-root user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Load environment variables from file
ENV ENV_FILE=/app/certs.env

# Expose all server ports
EXPOSE 8001 8002 8003 8004 8005

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD /bin/sh -c '. ./certs.env && ./client' || exit 1

# Run the server with environment variables loaded
#CMD ["/bin/sh", "-c", ". ./certs.env && ./server"] 
# Force immediate memory allocation that exceeds 512MB
# CMD ["sh", "-c", "echo 'Testing OOM with RAM allocation' && dd if=/dev/zero of=/dev/shm/bigfile bs=1M count=2048"]

CMD ["sh", "-c", "echo 'Starting OOM test - allocating 1.5GB...' && timeout 60 yes | tr \\n x | head -c 1500m | tail || echo 'Process completed or killed'"]
