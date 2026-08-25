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

// DeletionPolicy controls whether deleting a Kubernetes object deletes its Dex record.
// +kubebuilder:validation:Enum=Delete;Retain
type DeletionPolicy string

const (
	// DeletionPolicyDelete removes the managed Dex record and generated Secret.
	DeletionPolicyDelete DeletionPolicy = "Delete"
	// DeletionPolicyRetain leaves the Dex record and detaches any generated Secret.
	DeletionPolicyRetain DeletionPolicy = "Retain"
)

const (
	// ConditionReady reports whether current desired state is converged.
	ConditionReady = "Ready"
	// ConditionCompatible reports whether the configured Dex tuple is supported.
	ConditionCompatible = "Compatible"
	// ConditionDrifted reports observed drift that could not be corrected.
	ConditionDrifted = "Drifted"
)

// SecretKeyReference selects one key from a Secret in the resource namespace.
type SecretKeyReference struct {
	// Name is the Secret name.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Key is the data key within the Secret.
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}
