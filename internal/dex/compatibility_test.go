package dex

import (
	"errors"
	"strings"
	"testing"

	dexapi "github.com/dexidp/dex/api/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCompatibilityClassification(t *testing.T) {
	exact := &dexapi.VersionResp{Server: "v2.46.0-20260806171424-ab64ed77", Api: 4}

	tests := []struct {
		name         string
		version      *dexapi.VersionResp
		versionErr   error
		connectorErr error
		identityErr  error
		wantState    CompatibilityState
		wantReason   string
	}{
		{name: "exact tuple and capabilities", version: exact, wantState: Compatible, wantReason: "Compatible"},
		{name: "server mismatch", version: &dexapi.VersionResp{Server: "v2.45.1", Api: 4}, wantState: Incompatible, wantReason: "ServerVersionMismatch"},
		{name: "older API mismatch", version: &dexapi.VersionResp{Server: exact.Server, Api: 3}, wantState: Incompatible, wantReason: "APIVersionMismatch"},
		{name: "newer API mismatch", version: &dexapi.VersionResp{Server: exact.Server, Api: 5}, wantState: Incompatible, wantReason: "APIVersionMismatch"},
		{name: "connectors disabled", version: exact, connectorErr: &CapabilityError{Capability: connectorsCapability}, wantState: Incompatible, wantReason: "ConnectorCRUDDisabled"},
		{name: "identities disabled", version: exact, identityErr: &CapabilityError{Capability: identitiesCapability}, wantState: Incompatible, wantReason: "SessionsIdentitiesCRUDDisabled"},
		{name: "version unavailable", versionErr: status.Error(codes.Unavailable, "secret-version-detail"), wantState: Unavailable, wantReason: "DexUnavailable"},
		{name: "connector probe unavailable", version: exact, connectorErr: status.Error(codes.Unavailable, "secret-connector-detail"), wantState: Unavailable, wantReason: "DexUnavailable"},
		{name: "identity probe unavailable", version: exact, identityErr: status.Error(codes.Unavailable, "secret-identity-detail"), wantState: Unavailable, wantReason: "DexUnavailable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyCompatibility(exact.Server, tt.version, tt.versionErr, tt.connectorErr, tt.identityErr)
			if got.State != tt.wantState || got.Reason != tt.wantReason {
				t.Fatalf("classifyCompatibility() = %#v, want state %q reason %q", got, tt.wantState, tt.wantReason)
			}
			if strings.Contains(got.Reason, "secret-") {
				t.Fatalf("reason exposed upstream detail: %q", got.Reason)
			}
		})
	}
}

func TestCompatibilityCapabilityErrorBoundary(t *testing.T) {
	tests := []struct {
		name       string
		capability string
		message    string
		wantTyped  bool
	}{
		{name: "exact connector response", capability: connectorsCapability, message: connectorsDisabledMessage, wantTyped: true},
		{name: "exact identities response", capability: identitiesCapability, message: identitiesDisabledMessage, wantTyped: true},
		{name: "different response", capability: connectorsCapability, message: connectorsDisabledMessage + ".", wantTyped: false},
		{name: "different code", capability: connectorsCapability, message: connectorsDisabledMessage, wantTyped: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := codes.Unknown
			if tt.name == "different code" {
				code = codes.PermissionDenied
			}
			disabledMessage := connectorsDisabledMessage
			if tt.capability == identitiesCapability {
				disabledMessage = identitiesDisabledMessage
			}
			got := probeError(tt.capability, disabledMessage, status.Error(code, tt.message))
			var capabilityErr *CapabilityError
			if errors.As(got, &capabilityErr) != tt.wantTyped {
				t.Fatalf("probeError() type = %T, want capability error %t", got, tt.wantTyped)
			}
			if strings.Contains(got.Error(), tt.message) {
				t.Fatalf("probeError() exposed upstream message: %v", got)
			}
		})
	}
}
