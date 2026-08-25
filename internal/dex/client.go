// Package dex provides a secret-safe client for Dex's supported gRPC API.
package dex

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

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
	rpcTimeout         = 10 * time.Second
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

// GetVersion returns Dex's server and API versions.
func (client *Client) GetVersion(ctx context.Context) (*dexapi.VersionResp, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.GetVersion(ctx, &dexapi.VersionReq{})
	return response, operationError("get version", err)
}

// ListConnectors returns dynamically stored Dex connectors.
func (client *Client) ListConnectors(ctx context.Context) (*dexapi.ListConnectorResp, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.ListConnectors(ctx, &dexapi.ListConnectorReq{})
	return response, probeError(connectorsCapability, connectorsDisabledMessage, err)
}

// CreateConnector creates a dynamic Dex connector and reports an ID collision.
func (client *Client) CreateConnector(ctx context.Context, connector *dexapi.Connector) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.CreateConnector(ctx, &dexapi.CreateConnectorReq{Connector: connector})
	if err != nil {
		return false, operationError("create connector", err)
	}
	return response.GetAlreadyExists(), nil
}

// UpdateConnector updates selected dynamic connector fields and reports remote absence.
func (client *Client) UpdateConnector(ctx context.Context, request *dexapi.UpdateConnectorReq) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.UpdateConnector(ctx, request)
	if err != nil {
		return false, operationError("update connector", err)
	}
	return response.GetNotFound(), nil
}

// DeleteConnector deletes a dynamic connector and reports remote absence.
func (client *Client) DeleteConnector(ctx context.Context, id string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.DeleteConnector(ctx, &dexapi.DeleteConnectorReq{Id: id})
	if err != nil {
		return false, operationError("delete connector", err)
	}
	return response.GetNotFound(), nil
}

// GetOAuth2Client returns a Dex client, including its secret, only in memory.
func (client *Client) GetOAuth2Client(ctx context.Context, id string) (*dexapi.Client, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.GetClient(ctx, &dexapi.GetClientReq{Id: id})
	if err != nil {
		statusErr := status.Convert(err)
		if statusErr.Code() == codes.NotFound || statusErr.Code() == codes.Unknown && statusErr.Message() == "not found" {
			return nil, false, nil
		}
		return nil, false, operationError("get OAuth2 client", err)
	}
	return response.GetClient(), true, nil
}

// CreateOAuth2Client creates a Dex client and reports an ID collision.
func (client *Client) CreateOAuth2Client(ctx context.Context, oauth2Client *dexapi.Client) (bool, *dexapi.Client, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.CreateClient(ctx, &dexapi.CreateClientReq{Client: oauth2Client})
	if err != nil {
		return false, nil, operationError("create OAuth2 client", err)
	}
	return response.GetAlreadyExists(), response.GetClient(), nil
}

// UpdateOAuth2Client updates mutable Dex client fields and reports remote absence.
func (client *Client) UpdateOAuth2Client(ctx context.Context, request *dexapi.UpdateClientReq) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.UpdateClient(ctx, request)
	if err != nil {
		return false, operationError("update OAuth2 client", err)
	}
	return response.GetNotFound(), nil
}

// DeleteOAuth2Client deletes a Dex client and reports remote absence.
func (client *Client) DeleteOAuth2Client(ctx context.Context, id string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.DeleteClient(ctx, &dexapi.DeleteClientReq{Id: id})
	if err != nil {
		return false, operationError("delete OAuth2 client", err)
	}
	return response.GetNotFound(), nil
}

// ListUserIdentities returns Dex user identities.
func (client *Client) ListUserIdentities(ctx context.Context) (*dexapi.ListUserIdentitiesResp, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.ListUserIdentities(ctx, &dexapi.ListUserIdentitiesReq{})
	return response, probeError(identitiesCapability, identitiesDisabledMessage, err)
}

// ListPasswords returns local password records without hashes, as enforced by Dex.
func (client *Client) ListPasswords(ctx context.Context) (*dexapi.ListPasswordResp, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.ListPasswords(ctx, &dexapi.ListPasswordReq{})
	return response, operationError("list passwords", err)
}

// CreatePassword creates a Dex local password record and reports an email collision.
func (client *Client) CreatePassword(ctx context.Context, password *dexapi.Password) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.CreatePassword(ctx, &dexapi.CreatePasswordReq{Password: password})
	if err != nil {
		return false, operationError("create password", err)
	}
	return response.GetAlreadyExists(), nil
}

// UpdatePassword updates a Dex password hash or username and reports remote absence.
func (client *Client) UpdatePassword(ctx context.Context, request *dexapi.UpdatePasswordReq) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.UpdatePassword(ctx, request)
	if err != nil {
		return false, operationError("update password", err)
	}
	return response.GetNotFound(), nil
}

// DeletePassword deletes a Dex password record and reports remote absence.
func (client *Client) DeletePassword(ctx context.Context, email string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.DeletePassword(ctx, &dexapi.DeletePasswordReq{Email: email})
	if err != nil {
		return false, operationError("delete password", err)
	}
	return response.GetNotFound(), nil
}

// VerifyPassword checks plaintext in memory against Dex and reports remote absence.
func (client *Client) VerifyPassword(ctx context.Context, email, password string) (bool, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.VerifyPassword(ctx, &dexapi.VerifyPasswordReq{Email: email, Password: password})
	if err != nil {
		return false, false, operationError("verify password", err)
	}
	return response.GetVerified(), !response.GetNotFound(), nil
}

// DeleteUserIdentity purges one connector identity and reports remote absence.
func (client *Client) DeleteUserIdentity(ctx context.Context, userID, connectorID string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.DeleteUserIdentity(ctx, &dexapi.DeleteUserIdentityReq{UserId: userID, ConnectorId: connectorID})
	if err != nil {
		return false, operationError("delete user identity", err)
	}
	return response.GetNotFound(), nil
}

// ListMFADevices returns non-secret MFA metadata and reports identity absence.
func (client *Client) ListMFADevices(ctx context.Context, userID, connectorID string) ([]*dexapi.MFADeviceInfo, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.ListMFADevices(ctx, &dexapi.ListMFADevicesReq{UserId: userID, ConnectorId: connectorID})
	if err != nil {
		statusErr := status.Convert(err)
		if statusErr.Code() == codes.NotFound || statusErr.Code() == codes.Unknown && statusErr.Message() == "not found" {
			return nil, false, nil
		}
		return nil, false, operationError("list MFA devices", err)
	}
	return response.GetDevices(), true, nil
}

// ResetMFA clears all MFA devices and reports identity absence.
func (client *Client) ResetMFA(ctx context.Context, userID, connectorID string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.ResetMFA(ctx, &dexapi.ResetMFAReq{UserId: userID, ConnectorId: connectorID})
	if err != nil {
		return false, operationError("reset MFA", err)
	}
	return response.GetNotFound(), nil
}

// DeleteMFASecret removes one authenticator and reports absence.
func (client *Client) DeleteMFASecret(ctx context.Context, userID, connectorID, authenticatorID string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.DeleteMFASecret(ctx, &dexapi.DeleteMFASecretReq{UserId: userID, ConnectorId: connectorID, AuthenticatorId: authenticatorID})
	if err != nil {
		return false, operationError("delete MFA authenticator", err)
	}
	return response.GetNotFound(), nil
}

// DeleteWebAuthnCredential removes one credential and reports absence.
func (client *Client) DeleteWebAuthnCredential(ctx context.Context, userID, connectorID string, credentialID []byte) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	response, err := client.api.DeleteWebAuthnCredential(ctx, &dexapi.DeleteWebAuthnCredentialReq{UserId: userID, ConnectorId: connectorID, CredentialId: credentialID})
	if err != nil {
		return false, operationError("delete WebAuthn credential", err)
	}
	return response.GetNotFound(), nil
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
