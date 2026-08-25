// Package config owns the dex-operator runtime environment contract.
package config

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

// SupportedServerVersion is the only Dex server version this binary accepts.
const SupportedServerVersion = "v2.46.0-20260806171424-ab64ed77"

// Config contains the complete dex-operator runtime environment.
//
//go:generate go tool envdoc -output ../../docs/configuration.md
type Config struct {
	// Dex gRPC host and port.
	GRPCAddress string `env:"DEX_GRPC_ADDRESS,required,notEmpty"`
	// Certificate name verified by the gRPC TLS client.
	GRPCServerName string `env:"DEX_GRPC_SERVER_NAME"`
	// Allow plaintext gRPC only when every target address is loopback.
	GRPCInsecure bool `env:"DEX_GRPC_INSECURE" envDefault:"false"`
	// Periodic remote-drift reconciliation interval.
	ReconcileInterval time.Duration `env:"DEX_RECONCILE_INTERVAL" envDefault:"5m"`
	// Exact Dex server version expected by this binary.
	ExpectedServerVersion string `env:"DEX_EXPECTED_SERVER_VERSION,required,notEmpty"`
}

// Parse decodes and validates an isolated environment map.
func Parse(values map[string]string) (Config, error) {
	config, err := env.ParseAsWithOptions[Config](env.Options{Environment: values})
	if err != nil {
		return Config{}, fmt.Errorf("parse environment: %w", err)
	}
	if err := config.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate environment: %w", err)
	}
	return config, nil
}

// Load reads the process environment once.
func Load() (Config, error) {
	return Parse(env.ToMap(os.Environ()))
}

// Validate enforces cross-field and network safety rules.
func (config Config) Validate() error {
	if strings.TrimSpace(config.GRPCAddress) == "" {
		return fmt.Errorf("DEX_GRPC_ADDRESS must not be blank")
	}
	host, port, err := net.SplitHostPort(config.GRPCAddress)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("DEX_GRPC_ADDRESS must contain host and port")
	}
	if config.ReconcileInterval <= 0 {
		return fmt.Errorf("DEX_RECONCILE_INTERVAL must be positive")
	}
	if config.ExpectedServerVersion != SupportedServerVersion {
		return fmt.Errorf("DEX_EXPECTED_SERVER_VERSION does not match supported version")
	}
	if !config.GRPCInsecure {
		if strings.TrimSpace(config.GRPCServerName) == "" {
			return fmt.Errorf("DEX_GRPC_SERVER_NAME is required with TLS")
		}
		return nil
	}
	if err := requireLoopback(host); err != nil {
		return fmt.Errorf("DEX_GRPC_INSECURE target: %w", err)
	}
	return nil
}

func requireLoopback(host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			return fmt.Errorf("address must be loopback")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve host: %w", err)
	}
	if len(addresses) == 0 {
		return fmt.Errorf("host resolved to no addresses")
	}
	for _, address := range addresses {
		if !address.IP.IsLoopback() {
			return fmt.Errorf("all resolved addresses must be loopback")
		}
	}
	return nil
}
