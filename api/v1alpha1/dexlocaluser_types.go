/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// PasswordCharacterSet selects one generated-password character class.
// +kubebuilder:validation:Enum=letters;numbers;symbols
type PasswordCharacterSet string

const (
	// PasswordCharacterSetLetters enables ASCII upper- and lower-case letters.
	PasswordCharacterSetLetters PasswordCharacterSet = "letters"
	// PasswordCharacterSetNumbers enables decimal digits.
	PasswordCharacterSetNumbers PasswordCharacterSet = "numbers"
	// PasswordCharacterSetSymbols enables the operator's documented symbol set.
	PasswordCharacterSetSymbols PasswordCharacterSet = "symbols"
)

// GeneratedPasswordSpec configures a generated local-user password.
type GeneratedPasswordSpec struct {
	// SecretName receives the generated password and bcrypt hash.
	// +kubebuilder:validation:MinLength=1
	SecretName string `json:"secretName"`
	// Length is the generated password length.
	// +kubebuilder:validation:Minimum=16
	// +kubebuilder:validation:Maximum=128
	Length int32 `json:"length"`
	// CharacterSets selects at least one permitted character class.
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	CharacterSets []PasswordCharacterSet `json:"characterSets"`
	// RotationNonce authorizes generating and applying a replacement password when changed.
	// +optional
	RotationNonce string `json:"rotationNonce,omitempty"`
}

// DexLocalUserPasswordSpec selects a provided bcrypt hash or generated password.
// +kubebuilder:validation:XValidation:rule="has(self.hashSecretRef) != has(self.generated)",message="exactly one of hashSecretRef or generated is required"
type DexLocalUserPasswordSpec struct {
	// HashSecretRef selects a provided bcrypt hash.
	// +optional
	HashSecretRef *SecretKeyReference `json:"hashSecretRef,omitempty"`
	// Generated configures an operator-generated password.
	// +optional
	Generated *GeneratedPasswordSpec `json:"generated,omitempty"`
}

// DexLocalUserMFASpec configures supported MFA reset and device-removal operations.
type DexLocalUserMFASpec struct {
	// ResetNonce authorizes clearing all enrolled MFA devices when changed.
	// +optional
	ResetNonce string `json:"resetNonce,omitempty"`
	// RemoveAuthenticatorIDs are authenticator IDs that must remain absent.
	// +listType=set
	// +optional
	RemoveAuthenticatorIDs []string `json:"removeAuthenticatorIDs,omitempty"`
	// RemoveWebAuthnCredentialIDs are unpadded base64url credential IDs that must remain absent.
	// +listType=set
	// +kubebuilder:validation:items:Pattern="^[A-Za-z0-9_-]+$"
	// +optional
	RemoveWebAuthnCredentialIDs []string `json:"removeWebAuthnCredentialIDs,omitempty"`
}

// DexLocalUserSpec defines the desired state of a Dex local user.
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.userID) || (has(self.userID) && self.userID == oldSelf.userID)",message="userID is immutable once specified"
type DexLocalUserSpec struct {
	// Email is the immutable Dex password-record key.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="email is immutable"
	Email string `json:"email"`
	// Username is the mutable display name.
	// +kubebuilder:validation:MinLength=1
	Username string `json:"username"`
	// UserID is the immutable OIDC subject. The operator derives it when omitted.
	// +kubebuilder:validation:MinLength=1
	// +optional
	UserID string `json:"userID,omitempty"`
	// Password selects provided or generated credential material.
	Password DexLocalUserPasswordSpec `json:"password"`
	// MFA configures inventory reset and removal operations.
	// +optional
	MFA *DexLocalUserMFASpec `json:"mfa,omitempty"`
	// AdoptExisting authorizes takeover of an unowned matching Dex record.
	// +kubebuilder:default=false
	AdoptExisting bool `json:"adoptExisting,omitempty"`
	// DeletionPolicy controls cleanup of Dex state and generated Secrets.
	// +kubebuilder:default=Delete
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// WebAuthnCredentialStatus contains non-secret WebAuthn metadata returned by Dex.
type WebAuthnCredentialStatus struct {
	// CredentialID is an unpadded base64url identifier.
	CredentialID string `json:"credentialID"`
	// DisplayName is the user-visible device name.
	// +optional
	DisplayName string `json:"displayName,omitempty"`
	// Transports reports supported authenticator transports.
	// +listType=set
	// +optional
	Transports []string `json:"transports,omitempty"`
	// BackupEligible reports whether the credential can be backed up.
	BackupEligible bool `json:"backupEligible"`
	// BackupState reports whether the credential is currently backed up.
	BackupState bool `json:"backupState"`
	// CloneWarning reports a possible cloned authenticator.
	CloneWarning bool `json:"cloneWarning"`
	// CreatedAt is the registration time when Dex reports one.
	// +optional
	CreatedAt *metav1.Time `json:"createdAt,omitempty"`
}

// MFADeviceStatus contains non-secret MFA device metadata returned by Dex.
type MFADeviceStatus struct {
	// AuthenticatorID identifies the configured Dex authenticator.
	AuthenticatorID string `json:"authenticatorID"`
	// Type is the Dex authenticator type.
	// +optional
	Type string `json:"type,omitempty"`
	// Confirmed reports whether enrollment completed.
	Confirmed bool `json:"confirmed"`
	// CreatedAt is the enrollment time when Dex reports one.
	// +optional
	CreatedAt *metav1.Time `json:"createdAt,omitempty"`
	// WebAuthnCredentials contains non-secret credential metadata.
	// +optional
	WebAuthnCredentials []WebAuthnCredentialStatus `json:"webAuthnCredentials,omitempty"`
}

// DexLocalUserStatus defines the observed state of a Dex local user.
type DexLocalUserStatus struct {
	// ResolvedUserID is both the derived/explicit ID and the external ownership preclaim.
	// +optional
	ResolvedUserID string `json:"resolvedUserID,omitempty"`
	// HandledRotationNonce is the last successfully applied generated-credential nonce.
	// +optional
	HandledRotationNonce string `json:"handledRotationNonce,omitempty"`
	// HandledMFAResetNonce is the last successfully applied MFA reset nonce.
	// +optional
	HandledMFAResetNonce string `json:"handledMFAResetNonce,omitempty"`
	// AppliedSecretResourceVersion is the last converged input/generated Secret version.
	// +optional
	AppliedSecretResourceVersion string `json:"appliedSecretResourceVersion,omitempty"`
	// AppliedCredentialSource is the last converged provided or generated password mode.
	// +kubebuilder:validation:Enum=Provided;Generated
	// +optional
	AppliedCredentialSource string `json:"appliedCredentialSource,omitempty"`
	// MFADevices contains only non-secret device metadata.
	// +optional
	MFADevices []MFADeviceStatus `json:"mfaDevices,omitempty"`
	// ObservedGeneration is the most recent converged or evaluated spec generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Conditions report Ready, Compatible, and Drifted state.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced

// DexLocalUser is the Schema for the dexlocalusers API.
type DexLocalUser struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitzero"`
	Spec              DexLocalUserSpec `json:"spec"`
	// +optional
	Status DexLocalUserStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// DexLocalUserList contains a list of DexLocalUser.
type DexLocalUserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []DexLocalUser `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &DexLocalUser{}, &DexLocalUserList{})
		return nil
	})
}
