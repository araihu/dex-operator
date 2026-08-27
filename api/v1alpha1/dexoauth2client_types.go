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

// GeneratedOAuth2ClientSecretSpec configures generated client data.
// +kubebuilder:validation:XValidation:rule="!has(self.clientIDKey) || !has(self.clientSecretKey) || self.clientIDKey != self.clientSecretKey",message="clientIDKey and clientSecretKey must differ"
type GeneratedOAuth2ClientSecretSpec struct {
	// SecretName receives the generated client data.
	// +kubebuilder:validation:MinLength=1
	SecretName string `json:"secretName"`
	// ClientIDKey optionally writes the non-secret client ID under this Secret data key.
	// Omit it to preserve the legacy clientSecret-only Secret shape.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern="^[-._a-zA-Z0-9]+$"
	// +optional
	ClientIDKey string `json:"clientIDKey,omitempty"`
	// ClientSecretKey writes the generated client secret under this Secret data key.
	// +kubebuilder:default=clientSecret
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern="^[-._a-zA-Z0-9]+$"
	// +optional
	ClientSecretKey string `json:"clientSecretKey,omitempty"`
}

// DexOAuth2ClientSecretSpec selects provided or generated confidential material.
// +kubebuilder:validation:XValidation:rule="has(self.providedSecretRef) != has(self.generated)",message="exactly one of providedSecretRef or generated is required"
type DexOAuth2ClientSecretSpec struct {
	// ProvidedSecretRef selects an existing client secret.
	// +optional
	ProvidedSecretRef *SecretKeyReference `json:"providedSecretRef,omitempty"`
	// Generated configures an operator-generated client secret.
	// +optional
	Generated *GeneratedOAuth2ClientSecretSpec `json:"generated,omitempty"`
	// RotationNonce authorizes delete/recreate secret rotation when changed.
	// +optional
	RotationNonce string `json:"rotationNonce,omitempty"`
}

// DexOAuth2ClientSpec defines the desired state of an OAuth2 client.
// +kubebuilder:validation:XValidation:rule="self.public ? !has(self.secret) : has(self.secret)",message="public clients must omit secret and confidential clients must provide it"
type DexOAuth2ClientSpec struct {
	// ID is the immutable Dex client identifier.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="id is immutable"
	ID string `json:"id"`
	// Public selects a public OAuth2 client and is immutable.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="public is immutable"
	Public bool `json:"public"`
	// Name is the mutable display name.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// LogoURL is an optional client logo URL. Empty removes the logo through recreate.
	// +optional
	LogoURL string `json:"logoURL,omitempty"`
	// RedirectURIs are accepted OAuth2 redirect URIs.
	// +listType=set
	// +optional
	RedirectURIs []string `json:"redirectURIs,omitempty"`
	// TrustedPeers are clients trusted for cross-client assertions.
	// +listType=set
	// +optional
	TrustedPeers []string `json:"trustedPeers,omitempty"`
	// AllowedConnectors restricts connectors usable by this client.
	// +listType=set
	// +optional
	AllowedConnectors []string `json:"allowedConnectors,omitempty"`
	// Secret configures confidential client material and is forbidden for public clients.
	// +optional
	Secret *DexOAuth2ClientSecretSpec `json:"secret,omitempty"`
	// AdoptExisting authorizes takeover of an unowned matching Dex record.
	// +kubebuilder:default=false
	AdoptExisting bool `json:"adoptExisting,omitempty"`
	// DeletionPolicy controls cleanup of Dex state and generated Secrets.
	// +kubebuilder:default=Delete
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// DexOAuth2ClientStatus defines observed non-secret state.
type DexOAuth2ClientStatus struct {
	// ExternalID is the Dex client ID ownership preclaim.
	// +optional
	ExternalID string `json:"externalID,omitempty"`
	// HandledRotationNonce is the last successfully applied secret rotation nonce.
	// +optional
	HandledRotationNonce string `json:"handledRotationNonce,omitempty"`
	// AppliedSecretResourceVersion is the last converged input/generated Secret version.
	// +optional
	AppliedSecretResourceVersion string `json:"appliedSecretResourceVersion,omitempty"`
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

// DexOAuth2Client is the Schema for the dexoauth2clients API.
type DexOAuth2Client struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitzero"`
	Spec              DexOAuth2ClientSpec `json:"spec"`
	// +optional
	Status DexOAuth2ClientStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// DexOAuth2ClientList contains a list of DexOAuth2Client.
type DexOAuth2ClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []DexOAuth2Client `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &DexOAuth2Client{}, &DexOAuth2ClientList{})
		return nil
	})
}
