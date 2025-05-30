package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	log.Println("Generating TLS certificates for HTTP/2 server...")

	// Generate a private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"NLB Multi-Port Server"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Container"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1), // localhost
			net.IPv6loopback,       // ::1
			net.IPv4(0, 0, 0, 0),   // 0.0.0.0 for Docker
		},
		DNSNames: []string{
			"localhost",
			"nlb-server", // Docker container name
			"*.local",    // Local development
		},
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// PEM encode the certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// PEM encode the private key
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	// Base64 encode for environment variables
	certB64 := base64.StdEncoding.EncodeToString(certPEM)
	keyB64 := base64.StdEncoding.EncodeToString(keyPEM)

	// Check if we should output to file or stdout
	outputToFile := len(os.Args) > 1 && os.Args[1] == "--file"

	if outputToFile {
		// Write to env file for Docker
		envContent := fmt.Sprintf("export TLS_CERT=%s\nexport TLS_KEY=%s\n", certB64, keyB64)
		if err := os.WriteFile("certs.env", []byte(envContent), 0644); err != nil {
			log.Fatalf("Failed to write environment file: %v", err)
		}
		log.Println("✅ Certificates written to certs.env file")
	} else {
		// Output environment variables to stdout
		fmt.Printf("export TLS_CERT=%s\n", certB64)
		fmt.Printf("export TLS_KEY=%s\n", keyB64)
	}

	log.Println("✅ Certificates generated successfully as environment variables")
}
