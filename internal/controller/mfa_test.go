package controller

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	dexv1alpha1 "github.com/araihu/dex-operator/api/v1alpha1"
	dexapi "github.com/araihu/dex/api/v2"
)

func TestMFAMapEmptyInventory(t *testing.T) {
	if got := mapMFADevices(nil); len(got) != 0 {
		t.Fatalf("mapMFADevices(nil) = %#v", got)
	}
}

func TestMFAMapTOTPMetadata(t *testing.T) {
	created := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	devices := []*dexapi.MFADeviceInfo{{
		AuthenticatorId: "totp-authenticator",
		MfaSecret: &dexapi.MFASecret{
			AuthenticatorId: "totp-authenticator",
			Type:            "totp",
			Confirmed:       true,
			CreatedAt:       created.Unix(),
		},
	}}
	got := mapMFADevices(devices)
	if len(got) != 1 || got[0].AuthenticatorID != "totp-authenticator" || got[0].Type != "totp" || !got[0].Confirmed || got[0].CreatedAt == nil || !got[0].CreatedAt.Time.Equal(created) {
		t.Fatalf("mapped TOTP metadata = %#v", got)
	}
}

func TestMFAMapWebAuthnMetadata(t *testing.T) {
	created := time.Date(2026, 8, 25, 12, 30, 0, 0, time.UTC)
	devices := []*dexapi.MFADeviceInfo{{
		AuthenticatorId: "webauthn-authenticator",
		WebauthnCredentials: []*dexapi.WebAuthnCredential{{
			CredentialId:    []byte{0xfb, 0xff},
			AttestationType: "sentinel-attestation",
			Aaguid:          []byte("sentinel-aaguid"),
			SignCount:       99,
			CloneWarning:    true,
			Transport:       []string{"usb", "internal", "usb"},
			BackupEligible:  true,
			BackupState:     true,
			DisplayName:     "Security Key",
			CreatedAt:       created.Unix(),
		}},
	}}
	got := mapMFADevices(devices)
	if len(got) != 1 || len(got[0].WebAuthnCredentials) != 1 {
		t.Fatalf("mapped WebAuthn metadata = %#v", got)
	}
	credential := got[0].WebAuthnCredentials[0]
	if credential.CredentialID != "-_8" || credential.DisplayName != "Security Key" || !reflect.DeepEqual(credential.Transports, []string{"internal", "usb"}) || !credential.BackupEligible || !credential.BackupState || !credential.CloneWarning || credential.CreatedAt == nil || !credential.CreatedAt.Time.Equal(created) {
		t.Fatalf("mapped WebAuthn credential = %#v", credential)
	}
}

func TestMFAPlanResetAndDurableRemovals(t *testing.T) {
	spec := &dexv1alpha1.DexLocalUserMFASpec{
		ResetNonce:                  "reset-2",
		RemoveAuthenticatorIDs:      []string{"auth-b", "auth-a", "auth-a"},
		RemoveWebAuthnCredentialIDs: []string{"-_8", "AQI"},
	}
	plan, err := planMFAActions(spec, "reset-1")
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Reset || !reflect.DeepEqual(plan.AuthenticatorIDs, []string{"auth-a", "auth-b"}) || len(plan.CredentialIDs) != 2 || !bytes.Equal(plan.CredentialIDs[0], []byte{0x01, 0x02}) || !bytes.Equal(plan.CredentialIDs[1], []byte{0xfb, 0xff}) {
		t.Fatalf("MFA plan = %#v", plan)
	}

	replay, err := planMFAActions(spec, "reset-2")
	if err != nil {
		t.Fatal(err)
	}
	if replay.Reset || !reflect.DeepEqual(replay.AuthenticatorIDs, plan.AuthenticatorIDs) || !reflect.DeepEqual(replay.CredentialIDs, plan.CredentialIDs) {
		t.Fatalf("MFA replay plan = %#v", replay)
	}
}

func TestMFAInvalidCredentialIDIsSecretSafe(t *testing.T) {
	const sentinel = "invalid-sentinel!"
	_, err := planMFAActions(&dexv1alpha1.DexLocalUserMFASpec{RemoveWebAuthnCredentialIDs: []string{sentinel}}, "")
	if err == nil {
		t.Fatal("planMFAActions() accepted invalid base64url")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatalf("error exposed invalid credential input: %v", err)
	}
}
