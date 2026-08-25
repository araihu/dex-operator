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

// DexConnectorSpec defines the desired state of a Dex connector.
type DexConnectorSpec struct {
	// ID is the immutable Dex connector identifier.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="id is immutable"
	ID string `json:"id"`
	// Type is the immutable Dex connector type.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="type is immutable"
	Type string `json:"type"`
	// Name is the mutable display name.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// ConfigSecretRef selects exact connector JSON bytes.
	ConfigSecretRef SecretKeyReference `json:"configSecretRef"`
	// GrantTypes restricts OAuth2 grant types. Empty means unrestricted.
	// +listType=set
	// +optional
	GrantTypes []string `json:"grantTypes,omitempty"`
	// AdoptExisting authorizes takeover of an unowned matching Dex record.
	// +kubebuilder:default=false
	AdoptExisting bool `json:"adoptExisting,omitempty"`
	// DeletionPolicy controls cleanup of Dex state.
	// +kubebuilder:default=Delete
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// DexConnectorStatus defines observed non-secret state.
type DexConnectorStatus struct {
	// ExternalID is the Dex connector ID ownership preclaim.
	// +optional
	ExternalID string `json:"externalID,omitempty"`
	// AppliedSecretResourceVersion is the last converged config Secret version.
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

// DexConnector is the Schema for the dexconnectors API.
type DexConnector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitzero"`
	Spec              DexConnectorSpec   `json:"spec"`
	Status            DexConnectorStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// DexConnectorList contains a list of DexConnector.
type DexConnectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []DexConnector `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &DexConnector{}, &DexConnectorList{})
		return nil
	})
}
