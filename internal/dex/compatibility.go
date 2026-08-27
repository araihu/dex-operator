package dex

import (
	"context"
	"fmt"
	"net/http"

	dexapi "github.com/araihu/dex/api/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	supportedAPIVersion       int32 = 4
	connectorsCapability            = "connector CRUD"
	identitiesCapability            = "sessions and identities CRUD"
	connectorsDisabledMessage       = "api_connectors_crud feature flag is not enabled"
	identitiesDisabledMessage       = "api_sessions_identities_crud feature flag is not enabled"
)

// CompatibilityState is the mutation-safety state of the connected Dex server.
type CompatibilityState string

const (
	Compatible   CompatibilityState = "Compatible"
	Incompatible CompatibilityState = "Incompatible"
	Unavailable  CompatibilityState = "Unavailable"
)

// CompatibilityOutcome is a secret-safe compatibility result.
type CompatibilityOutcome struct {
	State  CompatibilityState
	Reason string
}

// CapabilityError reports a required disabled Dex capability without upstream details.
type CapabilityError struct {
	Capability string
}

func (err *CapabilityError) Error() string {
	return fmt.Sprintf("required Dex capability is disabled: %s", err.Capability)
}

// CompatibilityGate performs fresh read-only checks before readiness or mutations.
type CompatibilityGate struct {
	client         *Client
	expectedServer string
}

// NewCompatibilityGate returns a strict gate for one pinned Dex server version.
func NewCompatibilityGate(client *Client, expectedServer string) *CompatibilityGate {
	return &CompatibilityGate{client: client, expectedServer: expectedServer}
}

// Check evaluates the version tuple and required read-only capabilities in order.
func (gate *CompatibilityGate) Check(ctx context.Context) CompatibilityOutcome {
	version, versionErr := gate.client.GetVersion(ctx)
	outcome := classifyCompatibility(gate.expectedServer, version, versionErr, nil, nil)
	if outcome.State != Compatible {
		return outcome
	}

	_, connectorErr := gate.client.ListConnectors(ctx)
	outcome = classifyCompatibility(gate.expectedServer, version, nil, connectorErr, nil)
	if outcome.State != Compatible {
		return outcome
	}

	_, identityErr := gate.client.ListUserIdentities(ctx)
	return classifyCompatibility(gate.expectedServer, version, nil, nil, identityErr)
}

// ReadinessCheck adapts Check to controller-runtime readiness probes.
func (gate *CompatibilityGate) ReadinessCheck(request *http.Request) error {
	outcome := gate.Check(request.Context())
	if outcome.State == Compatible {
		return nil
	}
	return fmt.Errorf("Dex compatibility: %s (%s)", outcome.State, outcome.Reason)
}

func classifyCompatibility(expectedServer string, version *dexapi.VersionResp, versionErr, connectorErr, identityErr error) CompatibilityOutcome {
	if versionErr != nil || version == nil {
		return CompatibilityOutcome{State: Unavailable, Reason: "DexUnavailable"}
	}
	if version.GetServer() != expectedServer {
		return CompatibilityOutcome{State: Incompatible, Reason: "ServerVersionMismatch"}
	}
	if version.GetApi() != supportedAPIVersion {
		return CompatibilityOutcome{State: Incompatible, Reason: "APIVersionMismatch"}
	}
	if connectorErr != nil {
		if isCapabilityError(connectorErr, connectorsCapability) {
			return CompatibilityOutcome{State: Incompatible, Reason: "ConnectorCRUDDisabled"}
		}
		return CompatibilityOutcome{State: Unavailable, Reason: "DexUnavailable"}
	}
	if identityErr != nil {
		if isCapabilityError(identityErr, identitiesCapability) {
			return CompatibilityOutcome{State: Incompatible, Reason: "SessionsIdentitiesCRUDDisabled"}
		}
		return CompatibilityOutcome{State: Unavailable, Reason: "DexUnavailable"}
	}
	return CompatibilityOutcome{State: Compatible, Reason: "Compatible"}
}

func isCapabilityError(err error, capability string) bool {
	capabilityErr, ok := err.(*CapabilityError)
	return ok && capabilityErr.Capability == capability
}

func probeError(capability, disabledMessage string, err error) error {
	if err == nil {
		return nil
	}
	statusErr := status.Convert(err)
	if statusErr.Code() == codes.Unknown && statusErr.Message() == disabledMessage {
		return &CapabilityError{Capability: capability}
	}
	return operationError("probe "+capability, err)
}
