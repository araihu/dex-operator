package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"sort"
	"time"

	dexv1alpha1 "github.com/araihu/dex-operator/api/v1alpha1"
	dexclient "github.com/araihu/dex-operator/internal/dex"
	dexapi "github.com/araihu/dex/api/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var errInvalidMFACredentialID = errors.New("invalid unpadded base64url WebAuthn credential ID")

type mfaActionPlan struct {
	Reset            bool
	AuthenticatorIDs []string
	CredentialIDs    [][]byte
}

func planMFAActions(spec *dexv1alpha1.DexLocalUserMFASpec, handledResetNonce string) (mfaActionPlan, error) {
	if spec == nil {
		return mfaActionPlan{}, nil
	}
	plan := mfaActionPlan{
		Reset:            spec.ResetNonce != handledResetNonce,
		AuthenticatorIDs: dexclient.NormalizeSet(spec.RemoveAuthenticatorIDs),
	}
	for _, encoded := range dexclient.NormalizeSet(spec.RemoveWebAuthnCredentialIDs) {
		credentialID, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(credentialID) == 0 {
			return mfaActionPlan{}, errInvalidMFACredentialID
		}
		plan.CredentialIDs = append(plan.CredentialIDs, credentialID)
	}
	sort.Slice(plan.CredentialIDs, func(left, right int) bool {
		return bytes.Compare(plan.CredentialIDs[left], plan.CredentialIDs[right]) < 0
	})
	return plan, nil
}

func (r *DexLocalUserReconciler) reconcileMFA(ctx context.Context, userID string, spec *dexv1alpha1.DexLocalUserMFASpec, handledResetNonce string) ([]dexv1alpha1.MFADeviceStatus, string, error) {
	plan, err := planMFAActions(spec, handledResetNonce)
	if err != nil {
		return nil, handledResetNonce, err
	}
	if _, _, err := r.Dex.ListMFADevices(ctx, userID, localConnectorID); err != nil {
		return nil, handledResetNonce, err
	}
	if plan.Reset {
		if _, err := r.Dex.ResetMFA(ctx, userID, localConnectorID); err != nil {
			return nil, handledResetNonce, err
		}
	}
	for _, authenticatorID := range plan.AuthenticatorIDs {
		if _, err := r.Dex.DeleteMFASecret(ctx, userID, localConnectorID, authenticatorID); err != nil {
			return nil, handledResetNonce, err
		}
	}
	for _, credentialID := range plan.CredentialIDs {
		if _, err := r.Dex.DeleteWebAuthnCredential(ctx, userID, localConnectorID, credentialID); err != nil {
			return nil, handledResetNonce, err
		}
	}
	devices, found, err := r.Dex.ListMFADevices(ctx, userID, localConnectorID)
	if err != nil {
		return nil, handledResetNonce, err
	}
	if !found {
		devices = nil
	}
	if plan.Reset && len(devices) != 0 || mfaRemovalPresent(devices, plan) {
		return nil, handledResetNonce, errors.New("Dex MFA state did not converge")
	}
	if plan.Reset {
		handledResetNonce = spec.ResetNonce
	}
	return mapMFADevices(devices), handledResetNonce, nil
}

func mfaRemovalPresent(devices []*dexapi.MFADeviceInfo, plan mfaActionPlan) bool {
	for _, device := range devices {
		if slices.Contains(plan.AuthenticatorIDs, device.GetAuthenticatorId()) {
			return true
		}
		for _, credential := range device.GetWebauthnCredentials() {
			for _, removed := range plan.CredentialIDs {
				if bytes.Equal(credential.GetCredentialId(), removed) {
					return true
				}
			}
		}
	}
	return false
}

func mapMFADevices(devices []*dexapi.MFADeviceInfo) []dexv1alpha1.MFADeviceStatus {
	mapped := make([]dexv1alpha1.MFADeviceStatus, 0, len(devices))
	for _, device := range devices {
		status := dexv1alpha1.MFADeviceStatus{AuthenticatorID: device.GetAuthenticatorId()}
		if secret := device.GetMfaSecret(); secret != nil {
			status.Type = secret.GetType()
			status.Confirmed = secret.GetConfirmed()
			status.CreatedAt = unixStatusTime(secret.GetCreatedAt())
		}
		for _, credential := range device.GetWebauthnCredentials() {
			status.WebAuthnCredentials = append(status.WebAuthnCredentials, dexv1alpha1.WebAuthnCredentialStatus{
				CredentialID:   base64.RawURLEncoding.EncodeToString(credential.GetCredentialId()),
				DisplayName:    credential.GetDisplayName(),
				Transports:     dexclient.NormalizeSet(credential.GetTransport()),
				BackupEligible: credential.GetBackupEligible(),
				BackupState:    credential.GetBackupState(),
				CloneWarning:   credential.GetCloneWarning(),
				CreatedAt:      unixStatusTime(credential.GetCreatedAt()),
			})
		}
		sort.Slice(status.WebAuthnCredentials, func(left, right int) bool {
			return status.WebAuthnCredentials[left].CredentialID < status.WebAuthnCredentials[right].CredentialID
		})
		mapped = append(mapped, status)
	}
	sort.Slice(mapped, func(left, right int) bool {
		return mapped[left].AuthenticatorID < mapped[right].AuthenticatorID
	})
	return mapped
}

func unixStatusTime(value int64) *metav1.Time {
	if value == 0 {
		return nil
	}
	timestamp := metav1.NewTime(time.Unix(value, 0).UTC())
	return &timestamp
}
