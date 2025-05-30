#!/bin/bash

# Test script for certificate generation
echo "🔧 Testing certificate generation..."

# Build the certificate generator
echo "Building certificate generator..."
go build -o cert-gen ./scripts/generate-certs.go

# Generate certificates to environment file
echo "Generating certificates..."
./cert-gen --file

# Check if certs.env was created
if [ -f "certs.env" ]; then
    echo "✅ Certificate environment file created successfully!"
    echo "📋 Certificate environment variables:"
    echo "$(grep -c '^export TLS_' certs.env) environment variables found"
    
    # Source the environment file
    source certs.env
    
    # Test if environment variables are set
    if [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ]; then
        echo "✅ Environment variables loaded successfully!"
        echo "🔑 TLS_CERT length: ${#TLS_CERT} characters"
        echo "🔐 TLS_KEY length: ${#TLS_KEY} characters"
    else
        echo "❌ Failed to load environment variables"
        exit 1
    fi
else
    echo "❌ Failed to create certs.env file"
    exit 1
fi

# Clean up
rm -f cert-gen

echo "🎉 Certificate generation test completed successfully!"
echo ""
echo "To use the certificates:"
echo "1. For Docker: The certificates are built into the image"
echo "2. For local development: Run 'source certs.env' before starting the server" 