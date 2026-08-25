package dex

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/araihu/dex-operator/internal/config"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewClient(t *testing.T) {
	t.Run("plaintext loopback needs no TLS files", func(t *testing.T) {
		client, err := NewClient(config.Config{
			GRPCAddress:           "127.0.0.1:5557",
			GRPCInsecure:          true,
			ReconcileInterval:     time.Minute,
			ExpectedServerVersion: config.SupportedServerVersion,
		}, TLSFiles{})
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}
		t.Cleanup(func() { _ = client.Close() })
	})

	t.Run("missing TLS files fail", func(t *testing.T) {
		_, err := NewClient(validTLSConfig(), TLSFiles{
			CA:   filepath.Join(t.TempDir(), "ca.crt"),
			Cert: "missing.crt",
			Key:  "missing.key",
		})
		if err == nil || !strings.Contains(err.Error(), "load Dex CA") {
			t.Fatalf("NewClient() error = %v, want load Dex CA", err)
		}
	})

	t.Run("invalid CA content is not echoed", func(t *testing.T) {
		dir := t.TempDir()
		marker := "sentinel-private-material"
		caPath := filepath.Join(dir, "ca.crt")
		if err := os.WriteFile(caPath, []byte(marker), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := NewClient(validTLSConfig(), TLSFiles{CA: caPath, Cert: "unused", Key: "unused"})
		if err == nil {
			t.Fatal("NewClient() error = nil, want invalid CA")
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("error exposed CA content: %v", err)
		}
	})

	t.Run("valid cert-manager-shaped files", func(t *testing.T) {
		files := writeTestTLSFiles(t)
		client, err := NewClient(validTLSConfig(), files)
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}
		t.Cleanup(func() { _ = client.Close() })
	})
}

func TestOperationErrorSanitizesGRPCMessage(t *testing.T) {
	marker := "sentinel-client-secret"
	err := operationError("create client", status.Error(codes.PermissionDenied, marker))
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("error exposed gRPC message: %v", err)
	}
	if !strings.Contains(err.Error(), "create client") || !strings.Contains(err.Error(), codes.PermissionDenied.String()) {
		t.Fatalf("error lacks safe operation/code: %v", err)
	}
	var opErr *OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("error type = %T, want *OperationError", err)
	}
	if opErr.Code != codes.PermissionDenied {
		t.Fatalf("code = %s, want %s", opErr.Code, codes.PermissionDenied)
	}
}

func validTLSConfig() config.Config {
	return config.Config{
		GRPCAddress:           "dex.example.test:5557",
		GRPCServerName:        "dex.example.test",
		ReconcileInterval:     time.Minute,
		ExpectedServerVersion: config.SupportedServerVersion,
	}
}

func writeTestTLSFiles(t *testing.T) TLSFiles {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-client"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for path, data := range map[string][]byte{caPath: certPEM, certPath: certPEM, keyPath: keyPEM} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return TLSFiles{CA: caPath, Cert: certPath, Key: keyPath}
}
