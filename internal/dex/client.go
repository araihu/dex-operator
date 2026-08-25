// Package dex provides a secret-safe client for Dex's supported gRPC API.
package dex

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/araihu/dex-operator/internal/config"
	dexapi "github.com/dexidp/dex/api/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	productionCAFile   = "/var/run/dex-operator/tls/ca.crt"
	productionCertFile = "/var/run/dex-operator/tls/tls.crt"
	productionKeyFile  = "/var/run/dex-operator/tls/tls.key"
)

// TLSFiles identifies cert-manager-shaped client TLS files.
type TLSFiles struct {
	CA   string
	Cert string
	Key  string
}

// ProductionTLSFiles returns the fixed live TLS mount contract.
func ProductionTLSFiles() TLSFiles {
	return TLSFiles{CA: productionCAFile, Cert: productionCertFile, Key: productionKeyFile}
}

// Client is a concrete Dex gRPC client.
type Client struct {
	connection *grpc.ClientConn
	api        dexapi.DexClient
}

// NewClient validates configuration and constructs a Dex gRPC client.
func NewClient(runtimeConfig config.Config, files TLSFiles) (*Client, error) {
	if err := runtimeConfig.Validate(); err != nil {
		return nil, err
	}

	var transport credentials.TransportCredentials
	if runtimeConfig.GRPCInsecure {
		transport = insecure.NewCredentials()
	} else {
		secureTransport, err := loadTLSCredentials(runtimeConfig.GRPCServerName, files)
		if err != nil {
			return nil, err
		}
		transport = secureTransport
	}

	connection, err := grpc.NewClient(runtimeConfig.GRPCAddress, grpc.WithTransportCredentials(transport))
	if err != nil {
		return nil, fmt.Errorf("create Dex gRPC client: %w", err)
	}
	return &Client{connection: connection, api: dexapi.NewDexClient(connection)}, nil
}

// Close closes the underlying gRPC connection.
func (client *Client) Close() error {
	return client.connection.Close()
}

func loadTLSCredentials(serverName string, files TLSFiles) (credentials.TransportCredentials, error) {
	caPEM, err := os.ReadFile(files.CA)
	if err != nil {
		return nil, fmt.Errorf("load Dex CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("load Dex CA: invalid PEM certificate")
	}
	certificate, err := tls.LoadX509KeyPair(files.Cert, files.Key)
	if err != nil {
		return nil, fmt.Errorf("load Dex client certificate: %w", err)
	}
	return credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      roots,
		Certificates: []tls.Certificate{certificate},
		ServerName:   serverName,
	}), nil
}

// OperationError is a printable, secret-safe gRPC failure.
type OperationError struct {
	Operation string
	Code      codes.Code
}

// Error intentionally excludes the upstream message and payload.
func (err *OperationError) Error() string {
	return fmt.Sprintf("Dex %s failed with gRPC code %s", err.Operation, err.Code)
}

func operationError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return &OperationError{Operation: operation, Code: status.Code(err)}
}
