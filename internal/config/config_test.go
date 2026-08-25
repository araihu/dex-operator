package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	validTLS := map[string]string{
		"DEX_GRPC_ADDRESS":            "dex.example.test:5557",
		"DEX_GRPC_SERVER_NAME":        "dex.example.test",
		"DEX_EXPECTED_SERVER_VERSION": SupportedServerVersion,
	}

	tests := []struct {
		name    string
		values  map[string]string
		wantErr string
		check   func(*testing.T, Config)
	}{
		{
			name:   "TLS defaults",
			values: validTLS,
			check: func(t *testing.T, got Config) {
				if got.GRPCInsecure {
					t.Fatal("GRPCInsecure = true, want false")
				}
				if got.ReconcileInterval != 5*time.Minute {
					t.Fatalf("ReconcileInterval = %s, want 5m", got.ReconcileInterval)
				}
			},
		},
		{name: "missing address", values: map[string]string{"DEX_EXPECTED_SERVER_VERSION": SupportedServerVersion}, wantErr: "DEX_GRPC_ADDRESS"},
		{name: "empty address", values: map[string]string{"DEX_GRPC_ADDRESS": "", "DEX_EXPECTED_SERVER_VERSION": SupportedServerVersion}, wantErr: "DEX_GRPC_ADDRESS"},
		{name: "missing TLS server name", values: map[string]string{"DEX_GRPC_ADDRESS": "dex.example.test:5557", "DEX_EXPECTED_SERVER_VERSION": SupportedServerVersion}, wantErr: "DEX_GRPC_SERVER_NAME"},
		{name: "malformed duration", values: with(validTLS, "DEX_RECONCILE_INTERVAL", "soon"), wantErr: "ReconcileInterval"},
		{name: "non-positive duration", values: with(validTLS, "DEX_RECONCILE_INTERVAL", "0s"), wantErr: "must be positive"},
		{name: "unsupported server", values: with(validTLS, "DEX_EXPECTED_SERVER_VERSION", "v2.99.0"), wantErr: "does not match supported"},
		{name: "malformed address", values: with(validTLS, "DEX_GRPC_ADDRESS", "missing-port"), wantErr: "host and port"},
		{
			name: "literal loopback plaintext",
			values: map[string]string{
				"DEX_GRPC_ADDRESS":            "127.0.0.1:5557",
				"DEX_GRPC_INSECURE":           "true",
				"DEX_EXPECTED_SERVER_VERSION": SupportedServerVersion,
			},
		},
		{
			name: "localhost plaintext",
			values: map[string]string{
				"DEX_GRPC_ADDRESS":            "localhost:5557",
				"DEX_GRPC_INSECURE":           "true",
				"DEX_EXPECTED_SERVER_VERSION": SupportedServerVersion,
			},
		},
		{
			name: "non-loopback plaintext",
			values: map[string]string{
				"DEX_GRPC_ADDRESS":            "192.0.2.10:5557",
				"DEX_GRPC_INSECURE":           "true",
				"DEX_EXPECTED_SERVER_VERSION": SupportedServerVersion,
			},
			wantErr: "loopback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.values)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Parse() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

func TestGeneratedDocumentationContainsContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "configuration.md"))
	if err != nil {
		t.Fatal(err)
	}
	document := string(data)
	for _, name := range []string{
		"DEX_GRPC_ADDRESS",
		"DEX_GRPC_SERVER_NAME",
		"DEX_GRPC_INSECURE",
		"DEX_RECONCILE_INTERVAL",
		"DEX_EXPECTED_SERVER_VERSION",
	} {
		if !strings.Contains(document, name) {
			t.Errorf("generated documentation lacks %s", name)
		}
	}
}

func with(values map[string]string, key, value string) map[string]string {
	clone := make(map[string]string, len(values)+1)
	for name, existing := range values {
		clone[name] = existing
	}
	clone[key] = value
	return clone
}
