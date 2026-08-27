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

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"slices"
	"time"
	"unicode/utf8"

	dexv1alpha1 "github.com/araihu/dex-operator/api/v1alpha1"
	"github.com/araihu/dex-operator/internal/credentials"
	dexclient "github.com/araihu/dex-operator/internal/dex"
	dexapi "github.com/dexidp/dex/api/v2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	generatedOAuth2RotationNonceAnnotation    = "dex.araihu.com/rotation-nonce"
	generatedOAuth2ClientSecretKeyAnnotation  = "dex.araihu.com/client-secret-key"
	generatedOAuth2ManagedLabelKeysAnnotation = "dex.araihu.com/managed-label-keys"
	defaultGeneratedOAuth2ClientSecretKey     = "clientSecret"
)

// DexOAuth2ClientReconciler reconciles DexOAuth2Client resources through Dex's gRPC API.
type DexOAuth2ClientReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	Dex               *dexclient.Client
	CompatibilityGate *dexclient.CompatibilityGate
	ReconcileInterval time.Duration
}

// +kubebuilder:rbac:groups=dex.araihu.com,resources=dexoauth2clients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=dex.araihu.com,resources=dexoauth2clients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=dex.araihu.com,resources=dexoauth2clients/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile converges one OAuth2 client while keeping secret material in memory and Secrets only.
func (r *DexOAuth2ClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	resource := &dexv1alpha1.DexOAuth2Client{}
	if err := r.Get(ctx, req.NamespacedName, resource); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !resource.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, resource)
	}
	if err := EnsureFinalizer(ctx, r.Client, resource); err != nil {
		return ctrl.Result{}, err
	}

	providedSecret, providedResourceVersion, err := r.loadProvidedSecret(ctx, resource)
	if err != nil {
		return r.statusResult(ctx, resource, ReasonInvalidInput, "Referenced OAuth2 client secret is unavailable or invalid.", metav1.ConditionUnknown, false, nil)
	}
	if result, blocked, err := r.compatibilityResult(ctx, resource, false); blocked || err != nil {
		return result, err
	}

	observed, found, err := r.Dex.GetOAuth2Client(ctx, resource.Spec.ID)
	if err != nil {
		return r.statusResult(ctx, resource, ReasonDexUnavailable, "Dex OAuth2 client state could not be observed.", metav1.ConditionFalse, false, err)
	}
	if resource.Status.ExternalID != "" && resource.Status.ExternalID != resource.Spec.ID {
		return r.statusResult(ctx, resource, ReasonConflict, "External ownership is claimed for a different OAuth2 client ID.", metav1.ConditionTrue, true, nil)
	}
	if found && resource.Status.ExternalID == "" && !resource.Spec.AdoptExisting {
		return r.statusResult(ctx, resource, ReasonConflict, "A Dex OAuth2 client with this ID already exists; explicit adoption is required.", metav1.ConditionTrue, true, nil)
	}
	if resource.Status.ExternalID == "" {
		if err := PreclaimOwnership(ctx, r.Client, resource, resource.Spec.ID); err != nil {
			return ctrl.Result{}, err
		}
	}

	rotationRequested := resource.Spec.Secret != nil && resource.Spec.Secret.RotationNonce != resource.Status.HandledRotationNonce
	secretValue, secretResourceVersion := providedSecret, providedResourceVersion
	if resource.Spec.Secret != nil && resource.Spec.Secret.Generated != nil {
		secretValue, secretResourceVersion, err = r.generatedSecret(ctx, resource, observed, found, rotationRequested, false)
		if err != nil {
			return r.statusResult(ctx, resource, ReasonConflict, "Generated OAuth2 client Secret is not safely usable.", metav1.ConditionTrue, true, nil)
		}
		checkpointed, checkpointErr := r.checkpointGeneratedOAuth2ClientSecretRecovery(ctx, resource, observed, found, rotationRequested, secretValue, secretResourceVersion)
		if checkpointErr != nil {
			return ctrl.Result{}, checkpointErr
		}
		if checkpointed {
			return ctrl.Result{Requeue: true}, nil
		}
	}
	if !resource.Spec.Public && (secretValue == "" || !utf8.ValidString(secretValue)) {
		return r.statusResult(ctx, resource, ReasonInvalidInput, "OAuth2 client secret must be non-empty UTF-8 data.", metav1.ConditionTrue, false, nil)
	}
	if !found && !rotationRequested && resource.Status.AppliedSecretResourceVersion != "" && resource.Spec.Secret.ProvidedSecretRef != nil && secretResourceVersion != resource.Status.AppliedSecretResourceVersion {
		return r.statusResult(ctx, resource, ReasonConflict, "OAuth2 client credential continuity is not proven; a new rotation nonce is required.", metav1.ConditionTrue, true, nil)
	}
	desired := desiredDexOAuth2Client(resource, secretValue)
	if found && observed.GetPublic() == desired.GetPublic() && !desired.GetPublic() && observed.GetSecret() != desired.GetSecret() && !rotationRequested {
		return r.statusResult(ctx, resource, ReasonConflict, "OAuth2 client secret drift requires a new rotation nonce.", metav1.ConditionTrue, true, nil)
	}

	recreate := found && oauth2ClientNeedsRecreate(desired, observed)
	if !found || recreate {
		if recreate {
			if _, err := r.Dex.DeleteOAuth2Client(ctx, resource.Spec.ID); err != nil {
				return r.statusResult(ctx, resource, ReasonDriftCorrectionFailed, "Dex OAuth2 client replacement could not delete existing state.", metav1.ConditionTrue, true, err)
			}
		}
		alreadyExists, _, createErr := r.Dex.CreateOAuth2Client(ctx, desired)
		if createErr != nil {
			return r.statusResult(ctx, resource, ReasonDriftCorrectionFailed, "Dex OAuth2 client creation failed.", metav1.ConditionTrue, true, createErr)
		}
		if alreadyExists {
			return ctrl.Result{Requeue: true}, nil
		}
	} else {
		request, changed := oauth2ClientUpdate(desired, observed)
		if changed {
			notFound, updateErr := r.Dex.UpdateOAuth2Client(ctx, request)
			if updateErr != nil {
				return r.statusResult(ctx, resource, ReasonDriftCorrectionFailed, "Dex OAuth2 client update failed.", metav1.ConditionTrue, true, updateErr)
			}
			if notFound {
				return ctrl.Result{Requeue: true}, nil
			}
		}
	}

	observed, found, err = r.Dex.GetOAuth2Client(ctx, resource.Spec.ID)
	if err != nil {
		return r.statusResult(ctx, resource, ReasonDexUnavailable, "Dex OAuth2 client state could not be confirmed.", metav1.ConditionFalse, false, err)
	}
	if !found || !oauth2ClientManagedEqual(desired, observed) {
		return r.statusResult(ctx, resource, ReasonDriftCorrectionFailed, "Dex OAuth2 client did not converge.", metav1.ConditionTrue, true, nil)
	}
	if resource.Spec.Secret != nil && resource.Spec.Secret.Generated != nil {
		confirmedSecret, confirmedResourceVersion, confirmedErr := r.generatedSecret(ctx, resource, observed, true, rotationRequested, true)
		if confirmedErr != nil || confirmedSecret != observed.GetSecret() {
			return r.statusResult(ctx, resource, ReasonConflict, "Generated OAuth2 client Secret layout could not be safely confirmed.", metav1.ConditionTrue, true, nil)
		}
		secretResourceVersion = confirmedResourceVersion
	}
	if err := r.patchStatus(ctx, resource, func(status *dexv1alpha1.DexOAuth2ClientStatus) error {
		status.HandledRotationNonce = ""
		if resource.Spec.Secret != nil {
			status.HandledRotationNonce = resource.Spec.Secret.RotationNonce
		}
		status.AppliedSecretResourceVersion = secretResourceVersion
		status.ObservedGeneration = resource.Generation
		if err := SetCondition(&status.Conditions, resource.Generation, dexv1alpha1.ConditionReady, metav1.ConditionTrue, ReasonConverged, "Dex OAuth2 client is converged."); err != nil {
			return err
		}
		if err := SetCondition(&status.Conditions, resource.Generation, dexv1alpha1.ConditionCompatible, metav1.ConditionTrue, ReasonConverged, "Configured Dex is compatible."); err != nil {
			return err
		}
		return SetCondition(&status.Conditions, resource.Generation, dexv1alpha1.ConditionDrifted, metav1.ConditionFalse, ReasonConverged, "No uncorrected drift is present.")
	}); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: r.ReconcileInterval}, nil
}

func oauth2ClientNeedsRecreate(desired, observed *dexapi.Client) bool {
	return observed.GetPublic() != desired.GetPublic() ||
		observed.GetSecret() != desired.GetSecret() ||
		observed.GetLogoUrl() != "" && desired.GetLogoUrl() == "" ||
		len(observed.GetPostLogoutRedirectUris()) > 0 && len(desired.GetPostLogoutRedirectUris()) == 0
}

func (r *DexOAuth2ClientReconciler) loadProvidedSecret(ctx context.Context, resource *dexv1alpha1.DexOAuth2Client) (string, string, error) {
	if resource.Spec.Public || resource.Spec.Secret == nil || resource.Spec.Secret.ProvidedSecretRef == nil {
		return "", "", nil
	}
	value, resourceVersion, err := LoadSecretValue(ctx, r.Client, resource, *resource.Spec.Secret.ProvidedSecretRef)
	if err != nil {
		return "", "", err
	}
	if len(value) == 0 || !utf8.Valid(value) {
		return "", "", apierrors.NewBadRequest("OAuth2 client secret must be non-empty UTF-8 data")
	}
	return string(value), resourceVersion, nil
}

func (r *DexOAuth2ClientReconciler) generatedSecret(ctx context.Context, resource *dexv1alpha1.DexOAuth2Client, observed *dexapi.Client, found, rotationRequested, remoteConverged bool) (string, string, error) {
	policy := resource.Spec.Secret.Generated
	if errs := metav1validation.ValidateLabels(policy.Labels, field.NewPath("spec", "secret", "generated", "labels")); len(errs) > 0 {
		return "", "", errs.ToAggregate()
	}
	name := policy.SecretName
	secret := &corev1.Secret{}
	key := types.NamespacedName{Namespace: resource.Namespace, Name: name}
	err := r.Get(ctx, key, secret)
	if err == nil {
		if err := requireControllerOwner(secret, resource); err != nil {
			return "", "", err
		}
		secretKey := policy.ClientSecretKey
		if secretKey == "" {
			secretKey = defaultGeneratedOAuth2ClientSecretKey
		}
		appliedSecretKey := secret.Annotations[generatedOAuth2ClientSecretKeyAnnotation]
		if appliedSecretKey == "" {
			appliedSecretKey = defaultGeneratedOAuth2ClientSecretKey
		}
		if rotationRequested && secret.Annotations[generatedOAuth2RotationNonceAnnotation] != resource.Spec.Secret.RotationNonce {
			value, err := credentials.GenerateOAuth2Secret()
			if err != nil {
				return "", "", err
			}
			base := secret.DeepCopy()
			secret.Data = generatedOAuth2ClientSecretData(resource, secret.Data, value)
			if remoteConverged {
				if err := reconcileGeneratedOAuth2ClientSecretLabels(secret, policy.Labels); err != nil {
					return "", "", err
				}
			}
			if secret.Annotations == nil {
				secret.Annotations = map[string]string{}
			}
			secret.Annotations[generatedOAuth2RotationNonceAnnotation] = resource.Spec.Secret.RotationNonce
			secret.Annotations[generatedOAuth2ClientSecretKeyAnnotation] = secretKey
			if appliedSecretKey != secretKey && policy.ClientIDKey != appliedSecretKey {
				delete(secret.Data, appliedSecretKey)
			}
			if err := r.Patch(ctx, secret, client.MergeFrom(base)); err != nil {
				return "", "", err
			}
			return value, secret.ResourceVersion, nil
		}
		if !found && !rotationRequested && resource.Status.AppliedSecretResourceVersion != "" && secret.ResourceVersion != resource.Status.AppliedSecretResourceVersion {
			return "", "", apierrors.NewBadRequest("generated OAuth2 client Secret changed while Dex state is absent")
		}
		value, ok := secret.Data[secretKey]
		layoutMigration := false
		if !found {
			appliedValue, appliedOK := secret.Data[appliedSecretKey]
			if !appliedOK || len(appliedValue) == 0 || !utf8.Valid(appliedValue) {
				return "", "", apierrors.NewBadRequest("generated OAuth2 client Secret lacks its last applied client secret key")
			}
			if ok && !bytes.Equal(value, appliedValue) {
				return "", "", apierrors.NewBadRequest("generated OAuth2 client Secret target key differs from the last applied credential")
			}
			value, ok = appliedValue, true
			layoutMigration = appliedSecretKey != secretKey
		} else if (!ok || len(value) == 0 || !utf8.Valid(value)) && appliedSecretKey != secretKey {
			appliedValue, appliedOK := secret.Data[appliedSecretKey]
			if appliedOK && len(appliedValue) > 0 && utf8.Valid(appliedValue) && observed.GetSecret() == string(appliedValue) {
				value, ok = appliedValue, true
				layoutMigration = true
			}
		} else if appliedSecretKey != secretKey && observed.GetSecret() == string(value) {
			layoutMigration = true
		}
		if !ok || len(value) == 0 || !utf8.Valid(value) {
			return "", "", apierrors.NewBadRequest("generated OAuth2 client Secret lacks usable client secret data")
		}
		if !found {
			return string(value), secret.ResourceVersion, nil
		}
		if !remoteConverged {
			return string(value), secret.ResourceVersion, nil
		}
		base := secret.DeepCopy()
		secret.Data = generatedOAuth2ClientSecretData(resource, secret.Data, string(value))
		if err := reconcileGeneratedOAuth2ClientSecretLabels(secret, policy.Labels); err != nil {
			return "", "", err
		}
		if layoutMigration && policy.ClientIDKey != appliedSecretKey {
			delete(secret.Data, appliedSecretKey)
		}
		if appliedSecretKey == secretKey || layoutMigration {
			if secret.Annotations == nil {
				secret.Annotations = map[string]string{}
			}
			secret.Annotations[generatedOAuth2ClientSecretKeyAnnotation] = secretKey
		}
		if !maps.EqualFunc(base.Data, secret.Data, bytes.Equal) || !maps.Equal(base.Labels, secret.Labels) || !maps.Equal(base.Annotations, secret.Annotations) {
			if err := r.Patch(ctx, secret, client.MergeFrom(base)); err != nil {
				return "", "", err
			}
		}
		return string(value), secret.ResourceVersion, nil
	}
	if !apierrors.IsNotFound(err) {
		return "", "", err
	}
	if !found && !rotationRequested && resource.Status.AppliedSecretResourceVersion != "" {
		return "", "", apierrors.NewBadRequest("generated OAuth2 client Secret and Dex state are both absent")
	}

	value := ""
	if found && !rotationRequested && !observed.GetPublic() && observed.GetSecret() != "" {
		value = observed.GetSecret()
	} else {
		value, err = credentials.GenerateOAuth2Secret()
		if err != nil {
			return "", "", err
		}
	}
	secretKey := policy.ClientSecretKey
	if secretKey == "" {
		secretKey = defaultGeneratedOAuth2ClientSecretKey
	}
	annotations := map[string]string{generatedOAuth2ClientSecretKeyAnnotation: secretKey}
	if rotationRequested {
		annotations[generatedOAuth2RotationNonceAnnotation] = resource.Spec.Secret.RotationNonce
	}
	if len(policy.Labels) > 0 {
		managedKeys, err := json.Marshal(slices.Sorted(maps.Keys(policy.Labels)))
		if err != nil {
			return "", "", err
		}
		annotations[generatedOAuth2ManagedLabelKeysAnnotation] = string(managedKeys)
	}
	created, err := CreateGeneratedSecret(ctx, r.Client, r.Scheme, resource, name, generatedOAuth2ClientSecretData(resource, nil, value), policy.Labels, annotations)
	if err != nil {
		return "", "", err
	}
	return value, created.ResourceVersion, nil
}

func (r *DexOAuth2ClientReconciler) checkpointGeneratedOAuth2ClientSecretRecovery(ctx context.Context, resource *dexv1alpha1.DexOAuth2Client, observed *dexapi.Client, found, rotationRequested bool, secretValue, secretResourceVersion string) (bool, error) {
	if !found || rotationRequested || observed.GetSecret() != secretValue || resource.Status.AppliedSecretResourceVersion == "" || secretResourceVersion == resource.Status.AppliedSecretResourceVersion {
		return false, nil
	}
	if err := r.patchStatus(ctx, resource, func(status *dexv1alpha1.DexOAuth2ClientStatus) error {
		status.AppliedSecretResourceVersion = secretResourceVersion
		return nil
	}); err != nil {
		return false, err
	}
	return true, nil
}

func reconcileGeneratedOAuth2ClientSecretLabels(secret *corev1.Secret, desired map[string]string) error {
	var managedKeys []string
	if encoded := secret.Annotations[generatedOAuth2ManagedLabelKeysAnnotation]; encoded != "" {
		if err := json.Unmarshal([]byte(encoded), &managedKeys); err != nil {
			return apierrors.NewBadRequest("generated OAuth2 client Secret has invalid managed label metadata")
		}
	}
	for _, key := range managedKeys {
		if _, keep := desired[key]; !keep {
			delete(secret.Labels, key)
		}
	}
	if len(desired) == 0 {
		delete(secret.Annotations, generatedOAuth2ManagedLabelKeysAnnotation)
		return nil
	}
	if secret.Labels == nil {
		secret.Labels = make(map[string]string, len(desired))
	}
	maps.Copy(secret.Labels, desired)
	encoded, err := json.Marshal(slices.Sorted(maps.Keys(desired)))
	if err != nil {
		return err
	}
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	secret.Annotations[generatedOAuth2ManagedLabelKeysAnnotation] = string(encoded)
	return nil
}

func generatedOAuth2ClientSecretData(resource *dexv1alpha1.DexOAuth2Client, data map[string][]byte, secret string) map[string][]byte {
	policy := resource.Spec.Secret.Generated
	secretKey := policy.ClientSecretKey
	if secretKey == "" {
		secretKey = defaultGeneratedOAuth2ClientSecretKey
	}
	if data == nil {
		data = make(map[string][]byte, 2)
	}
	data[secretKey] = []byte(secret)
	if policy.ClientIDKey != "" {
		data[policy.ClientIDKey] = []byte(resource.Spec.ID)
	}
	return data
}

func desiredDexOAuth2Client(resource *dexv1alpha1.DexOAuth2Client, secret string) *dexapi.Client {
	return &dexapi.Client{
		Id:                     resource.Spec.ID,
		Secret:                 secret,
		Public:                 resource.Spec.Public,
		Name:                   resource.Spec.Name,
		LogoUrl:                resource.Spec.LogoURL,
		RedirectUris:           dexclient.NormalizeSet(resource.Spec.RedirectURIs),
		PostLogoutRedirectUris: dexclient.NormalizeSet(resource.Spec.PostLogoutRedirectURIs),
		TrustedPeers:           dexclient.NormalizeSet(resource.Spec.TrustedPeers),
		AllowedConnectors:      dexclient.NormalizeSet(resource.Spec.AllowedConnectors),
	}
}

func oauth2ClientUpdate(desired, observed *dexapi.Client) (*dexapi.UpdateClientReq, bool) {
	request := &dexapi.UpdateClientReq{Id: desired.GetId()}
	changed := false
	if desired.GetName() != observed.GetName() {
		request.Name = desired.GetName()
		changed = true
	}
	if desired.GetLogoUrl() != observed.GetLogoUrl() {
		request.LogoUrl = desired.GetLogoUrl()
		changed = true
	}
	for _, field := range []struct {
		desired  []string
		observed []string
		set      func([]string)
	}{
		{desired.GetRedirectUris(), observed.GetRedirectUris(), func(values []string) { request.RedirectUris = values }},
		{desired.GetPostLogoutRedirectUris(), observed.GetPostLogoutRedirectUris(), func(values []string) { request.PostLogoutRedirectUris = values }},
		{desired.GetTrustedPeers(), observed.GetTrustedPeers(), func(values []string) { request.TrustedPeers = values }},
		{desired.GetAllowedConnectors(), observed.GetAllowedConnectors(), func(values []string) { request.AllowedConnectors = values }},
	} {
		desiredValues := dexclient.NormalizeSet(field.desired)
		if !slices.Equal(desiredValues, dexclient.NormalizeSet(field.observed)) {
			field.set(append([]string{}, desiredValues...))
			changed = true
		}
	}
	return request, changed
}

func oauth2ClientManagedEqual(desired, observed *dexapi.Client) bool {
	return desired.GetId() == observed.GetId() &&
		desired.GetSecret() == observed.GetSecret() &&
		desired.GetPublic() == observed.GetPublic() &&
		desired.GetName() == observed.GetName() &&
		desired.GetLogoUrl() == observed.GetLogoUrl() &&
		slices.Equal(dexclient.NormalizeSet(desired.GetRedirectUris()), dexclient.NormalizeSet(observed.GetRedirectUris())) &&
		slices.Equal(dexclient.NormalizeSet(desired.GetPostLogoutRedirectUris()), dexclient.NormalizeSet(observed.GetPostLogoutRedirectUris())) &&
		slices.Equal(dexclient.NormalizeSet(desired.GetTrustedPeers()), dexclient.NormalizeSet(observed.GetTrustedPeers())) &&
		slices.Equal(dexclient.NormalizeSet(desired.GetAllowedConnectors()), dexclient.NormalizeSet(observed.GetAllowedConnectors()))
}

func (r *DexOAuth2ClientReconciler) finalize(ctx context.Context, resource *dexv1alpha1.DexOAuth2Client) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(resource, Finalizer) {
		return ctrl.Result{}, nil
	}
	if resource.Spec.DeletionPolicy == dexv1alpha1.DeletionPolicyRetain {
		if err := r.detachGeneratedSecret(ctx, resource); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, RemoveFinalizer(ctx, r.Client, resource)
	}
	if resource.Status.ExternalID != "" && resource.Status.ExternalID != resource.Spec.ID {
		return r.statusResult(ctx, resource, ReasonDeletionBlocked, "Deletion is blocked by an external ownership mismatch.", metav1.ConditionTrue, true, nil)
	}
	if resource.Status.ExternalID != "" {
		if result, blocked, err := r.compatibilityResult(ctx, resource, true); blocked || err != nil {
			return result, err
		}
		if _, err := r.Dex.DeleteOAuth2Client(ctx, resource.Spec.ID); err != nil {
			return r.statusResult(ctx, resource, ReasonDeletionBlocked, "Deletion is blocked because Dex cleanup failed.", metav1.ConditionTrue, true, err)
		}
	}
	if err := r.deleteGeneratedSecret(ctx, resource); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, RemoveFinalizer(ctx, r.Client, resource)
}

func (r *DexOAuth2ClientReconciler) detachGeneratedSecret(ctx context.Context, resource *dexv1alpha1.DexOAuth2Client) error {
	if resource.Spec.Secret == nil || resource.Spec.Secret.Generated == nil {
		return nil
	}
	return DetachGeneratedSecret(ctx, r.Client, r.Scheme, resource, resource.Spec.Secret.Generated.SecretName)
}

func (r *DexOAuth2ClientReconciler) deleteGeneratedSecret(ctx context.Context, resource *dexv1alpha1.DexOAuth2Client) error {
	if resource.Spec.Secret == nil || resource.Spec.Secret.Generated == nil {
		return nil
	}
	secret := &corev1.Secret{}
	key := types.NamespacedName{Namespace: resource.Namespace, Name: resource.Spec.Secret.Generated.SecretName}
	if err := r.Get(ctx, key, secret); err != nil {
		return client.IgnoreNotFound(err)
	}
	if err := requireControllerOwner(secret, resource); err != nil {
		return err
	}
	return r.Delete(ctx, secret)
}

func (r *DexOAuth2ClientReconciler) compatibilityResult(ctx context.Context, resource *dexv1alpha1.DexOAuth2Client, deleting bool) (ctrl.Result, bool, error) {
	outcome := r.CompatibilityGate.Check(ctx)
	if outcome.State == dexclient.Compatible {
		return ctrl.Result{}, false, nil
	}
	reason := ReasonDexUnavailable
	message := "Configured Dex is unavailable."
	if outcome.State == dexclient.Incompatible {
		reason = ReasonIncompatibleDex
		message = "Configured Dex version or required capabilities are incompatible."
	}
	readyReason := reason
	readyMessage := message
	if deleting {
		readyReason = ReasonDeletionBlocked
		readyMessage = "Deletion is blocked until Dex compatibility is restored."
	}
	result, err := r.statusResult(ctx, resource, readyReason, readyMessage, metav1.ConditionFalse, false, nil)
	return result, true, err
}

func (r *DexOAuth2ClientReconciler) statusResult(ctx context.Context, resource *dexv1alpha1.DexOAuth2Client, reason, message string, compatible metav1.ConditionStatus, drifted bool, cause error) (ctrl.Result, error) {
	err := r.patchStatus(ctx, resource, func(status *dexv1alpha1.DexOAuth2ClientStatus) error {
		status.ObservedGeneration = resource.Generation
		if err := SetCondition(&status.Conditions, resource.Generation, dexv1alpha1.ConditionReady, metav1.ConditionFalse, reason, message); err != nil {
			return err
		}
		compatibleReason := reason
		compatibleMessage := message
		if compatible == metav1.ConditionTrue {
			compatibleReason = ReasonConverged
			compatibleMessage = "Configured Dex is compatible."
		}
		if err := SetCondition(&status.Conditions, resource.Generation, dexv1alpha1.ConditionCompatible, compatible, compatibleReason, compatibleMessage); err != nil {
			return err
		}
		driftStatus := metav1.ConditionFalse
		driftReason := ReasonConverged
		driftMessage := "No uncorrected drift is present."
		if drifted {
			driftStatus = metav1.ConditionTrue
			driftReason = reason
			driftMessage = message
		}
		return SetCondition(&status.Conditions, resource.Generation, dexv1alpha1.ConditionDrifted, driftStatus, driftReason, driftMessage)
	})
	if err != nil {
		return ctrl.Result{}, err
	}
	if cause != nil {
		return ctrl.Result{}, cause
	}
	return ctrl.Result{RequeueAfter: r.ReconcileInterval}, nil
}

func (r *DexOAuth2ClientReconciler) patchStatus(ctx context.Context, resource *dexv1alpha1.DexOAuth2Client, mutate func(*dexv1alpha1.DexOAuth2ClientStatus) error) error {
	base := resource.DeepCopy()
	if err := mutate(&resource.Status); err != nil {
		return err
	}
	return r.Status().Patch(ctx, resource, client.MergeFrom(base))
}

// SetupWithManager sets up the controller and its referenced/generated Secret watch.
func (r *DexOAuth2ClientReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dexv1alpha1.DexOAuth2Client{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
			secret, ok := object.(*corev1.Secret)
			if !ok {
				return nil
			}
			requests, err := SecretRequests(ctx, r.Client, secret, &dexv1alpha1.DexOAuth2ClientList{}, OAuth2ClientSecretIndex)
			if err != nil {
				logf.FromContext(ctx).Error(err, "Map Secret to DexOAuth2Client")
				return nil
			}
			return requests
		})).
		Named("dexoauth2client").
		Complete(r)
}
