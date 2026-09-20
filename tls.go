package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// ensureTLSCertificate returns certificate and key file paths.
// If APP_TLS_CERT and APP_TLS_KEY are set, those paths are used.
// If APP_TLS_AUTO is set, a self-signed certificate is generated in dataDir.
func ensureTLSCertificate(dataDir string) (certFile, keyFile string, useTLS bool, err error) {
	certEnv := os.Getenv("APP_TLS_CERT")
	keyEnv := os.Getenv("APP_TLS_KEY")
	if certEnv != "" && keyEnv != "" {
		return certEnv, keyEnv, true, nil
	}

	if os.Getenv("APP_TLS_AUTO") != "1" {
		return "", "", false, nil
	}

	certFile = filepath.Join(dataDir, "server.crt")
	keyFile = filepath.Join(dataDir, "server.key")

	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			// Guard against a world-readable key left over from an earlier
			// version of the application.
			if err := os.Chmod(keyFile, 0600); err != nil {
				return "", "", false, fmt.Errorf("failed to restrict permissions on private key: %w", err)
			}
			return certFile, keyFile, true, nil
		}
	}

	if err := generateSelfSignedCert(certFile, keyFile); err != nil {
		return "", "", false, fmt.Errorf("failed to generate self-signed certificate: %w", err)
	}

	return certFile, keyFile, true, nil
}

func generateSelfSignedCert(certFile, keyFile string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Local Application"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	// The private key must not be readable by other local users.
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return err
	}

	return nil
}
