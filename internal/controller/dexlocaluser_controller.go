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
	"context"
	"errors"
	"time"

	dexv1alpha1 "github.com/araihu/dex-operator/api/v1alpha1"
	"github.com/araihu/dex-operator/internal/credentials"
	dexclient "github.com/araihu/dex-operator/internal/dex"
	dexapi "github.com/dexidp/dex/api/v2"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	generatedPasswordRotationNonceAnnotation = "dex.araihu.com/password-rotation-nonce"
	localConnectorID                         = "local"
	minimumDexBcryptCost                     = 10
	maximumDexBcryptCost                     = 16
)

// DexLocalUserReconciler reconciles DexLocalUser resources through Dex's gRPC API.
type DexLocalUserReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	Dex               *dexclient.Client
	CompatibilityGate *dexclient.CompatibilityGate
	ReconcileInterval time.Duration
}

// +kubebuilder:rbac:groups=dex.araihu.com,resources=dexlocalusers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=dex.araihu.com,resources=dexlocalusers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=dex.araihu.com,resources=dexlocalusers/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile converges one local user without persisting password material outside Secrets and Dex.
func (r *DexLocalUserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	resource := &dexv1alpha1.DexLocalUser{}
	if err := r.Get(ctx, req.NamespacedName, resource); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !resource.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, resource)
	}
	if err := EnsureFinalizer(ctx, r.Client, resource); err != nil {
		return ctrl.Result{}, err
	}

	resolvedUserID := resource.Spec.UserID
	if resolvedUserID == "" {
		resolvedUserID = credentials.LocalUserID(resource.Namespace, resource.Name)
	}
	providedHash, secretResourceVersion, err := r.loadProvidedHash(ctx, resource)
	if err != nil {
		return r.statusResult(ctx, resource, ReasonInvalidInput, "Referenced bcrypt hash is unavailable or outside Dex's accepted cost range.", metav1.ConditionUnknown, false, nil)
	}
	if result, blocked, err := r.compatibilityResult(ctx, resource, false); blocked || err != nil {
		return result, err
	}

	observed, err := r.observe(ctx, resource.Spec.Email)
	if err != nil {
		return r.statusResult(ctx, resource, ReasonDexUnavailable, "Dex password state could not be observed.", metav1.ConditionFalse, false, err)
	}
	if resource.Status.ResolvedUserID != "" && resource.Status.ResolvedUserID != resolvedUserID {
		return r.statusResult(ctx, resource, ReasonConflict, "Resolved ownership is already claimed for a different user ID.", metav1.ConditionTrue, true, nil)
	}
	if observed != nil && resource.Status.ResolvedUserID == "" {
		if !resource.Spec.AdoptExisting {
			return r.statusResult(ctx, resource, ReasonConflict, "A Dex password with this email already exists; explicit adoption is required.", metav1.ConditionTrue, true, nil)
		}
		if observed.GetUserId() != resolvedUserID {
			return r.statusResult(ctx, resource, ReasonConflict, "Existing Dex user ID differs from the resolved ID; set spec.userID to the observed value before adoption.", metav1.ConditionTrue, true, nil)
		}
	}
	if resource.Status.ResolvedUserID == "" {
		if err := PreclaimOwnership(ctx, r.Client, resource, resolvedUserID); err != nil {
			return ctrl.Result{}, err
		}
	}

	rotationRequested := resource.Spec.Password.Generated != nil && resource.Spec.Password.Generated.RotationNonce != resource.Status.HandledRotationNonce
	password, hash := "", providedHash
	if resource.Spec.Password.Generated != nil {
		password, hash, secretResourceVersion, err = r.generatedPassword(ctx, resource, rotationRequested)
		if err != nil {
			return r.statusResult(ctx, resource, ReasonConflict, "Generated password Secret is missing or was modified; a new rotation nonce is required.", metav1.ConditionTrue, true, nil)
		}
	}

	if observed != nil && observed.GetUserId() != resolvedUserID {
		if err := r.markIdentityRepair(ctx, resource); err != nil {
			return ctrl.Result{}, err
		}
		if _, err := r.Dex.DeleteUserIdentity(ctx, observed.GetUserId(), localConnectorID); err != nil {
			return r.statusResult(ctx, resource, ReasonDriftCorrectionFailed, "Dex identity cleanup for user-ID repair failed.", metav1.ConditionTrue, true, err)
		}
		if _, err := r.Dex.DeletePassword(ctx, resource.Spec.Email); err != nil {
			return r.statusResult(ctx, resource, ReasonDriftCorrectionFailed, "Dex password removal for user-ID repair failed.", metav1.ConditionTrue, true, err)
		}
		observed = nil
	}

	desired := &dexapi.Password{Email: resource.Spec.Email, Username: resource.Spec.Username, UserId: resolvedUserID, Hash: hash}
	if observed == nil {
		alreadyExists, createErr := r.Dex.CreatePassword(ctx, desired)
		if createErr != nil {
			return r.statusResult(ctx, resource, ReasonDriftCorrectionFailed, "Dex password creation failed.", metav1.ConditionTrue, true, createErr)
		}
		if alreadyExists {
			return ctrl.Result{Requeue: true}, nil
		}
	} else {
		request := &dexapi.UpdatePasswordReq{Email: resource.Spec.Email}
		changed := false
		if observed.GetUsername() != resource.Spec.Username {
			request.NewUsername = resource.Spec.Username
			changed = true
		}
		if resource.Spec.Password.HashSecretRef != nil && secretResourceVersion != resource.Status.AppliedSecretResourceVersion {
			request.NewHash = hash
			changed = true
		}
		if resource.Spec.Password.Generated != nil {
			verified, found, verifyErr := r.Dex.VerifyPassword(ctx, resource.Spec.Email, password)
			if verifyErr != nil {
				return r.statusResult(ctx, resource, ReasonDexUnavailable, "Dex password could not be verified.", metav1.ConditionFalse, false, verifyErr)
			}
			if !found {
				return ctrl.Result{Requeue: true}, nil
			}
			if !verified || rotationRequested {
				request.NewHash = hash
				changed = true
			}
		}
		if changed {
			notFound, updateErr := r.Dex.UpdatePassword(ctx, request)
			if updateErr != nil {
				return r.statusResult(ctx, resource, ReasonDriftCorrectionFailed, "Dex password update failed.", metav1.ConditionTrue, true, updateErr)
			}
			if notFound {
				return ctrl.Result{Requeue: true}, nil
			}
		}
	}

	observed, err = r.observe(ctx, resource.Spec.Email)
	if err != nil {
		return r.statusResult(ctx, resource, ReasonDexUnavailable, "Dex password state could not be confirmed.", metav1.ConditionFalse, false, err)
	}
	if observed == nil || observed.GetUserId() != resolvedUserID || observed.GetUsername() != resource.Spec.Username {
		return r.statusResult(ctx, resource, ReasonDriftCorrectionFailed, "Dex password identity did not converge.", metav1.ConditionTrue, true, nil)
	}
	if resource.Spec.Password.Generated != nil {
		verified, found, verifyErr := r.Dex.VerifyPassword(ctx, resource.Spec.Email, password)
		if verifyErr != nil {
			return r.statusResult(ctx, resource, ReasonDexUnavailable, "Dex password convergence could not be verified.", metav1.ConditionFalse, false, verifyErr)
		}
		if !found || !verified {
			return r.statusResult(ctx, resource, ReasonDriftCorrectionFailed, "Dex password credential did not converge.", metav1.ConditionTrue, true, nil)
		}
	}
	if err := r.patchStatus(ctx, resource, func(status *dexv1alpha1.DexLocalUserStatus) error {
		status.ResolvedUserID = resolvedUserID
		status.HandledRotationNonce = ""
		if resource.Spec.Password.Generated != nil {
			status.HandledRotationNonce = resource.Spec.Password.Generated.RotationNonce
		}
		status.AppliedSecretResourceVersion = secretResourceVersion
		status.ObservedGeneration = resource.Generation
		if err := SetCondition(&status.Conditions, resource.Generation, dexv1alpha1.ConditionReady, metav1.ConditionTrue, ReasonConverged, "Dex local user is converged."); err != nil {
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

func (r *DexLocalUserReconciler) loadProvidedHash(ctx context.Context, resource *dexv1alpha1.DexLocalUser) ([]byte, string, error) {
	if resource.Spec.Password.HashSecretRef == nil {
		return nil, "", nil
	}
	hash, resourceVersion, err := LoadSecretValue(ctx, r.Client, resource, *resource.Spec.Password.HashSecretRef)
	if err != nil {
		return nil, "", err
	}
	if err := validateDexBcryptHash(hash); err != nil {
		return nil, "", err
	}
	return hash, resourceVersion, nil
}

func validateDexBcryptHash(hash []byte) error {
	cost, err := bcrypt.Cost(hash)
	if err != nil {
		return errors.New("invalid bcrypt hash")
	}
	if cost < minimumDexBcryptCost || cost > maximumDexBcryptCost {
		return errors.New("bcrypt cost outside supported Dex range")
	}
	return nil
}

func (r *DexLocalUserReconciler) generatedPassword(ctx context.Context, resource *dexv1alpha1.DexLocalUser, rotationRequested bool) (string, []byte, string, error) {
	policy := resource.Spec.Password.Generated
	secret := &corev1.Secret{}
	key := types.NamespacedName{Namespace: resource.Namespace, Name: policy.SecretName}
	err := r.Get(ctx, key, secret)
	if err == nil {
		if err := requireControllerOwner(secret, resource); err != nil {
			return "", nil, "", err
		}
		if rotationRequested && secret.Annotations[generatedPasswordRotationNonceAnnotation] != policy.RotationNonce {
			password, hash, err := generatePasswordMaterial(policy)
			if err != nil {
				return "", nil, "", err
			}
			base := secret.DeepCopy()
			secret.Data = map[string][]byte{"password": []byte(password), "bcryptHash": hash}
			if secret.Annotations == nil {
				secret.Annotations = map[string]string{}
			}
			secret.Annotations[generatedPasswordRotationNonceAnnotation] = policy.RotationNonce
			if err := r.Patch(ctx, secret, client.MergeFrom(base)); err != nil {
				return "", nil, "", err
			}
			return password, hash, secret.ResourceVersion, nil
		}
		if !rotationRequested && resource.Status.AppliedSecretResourceVersion != "" && secret.ResourceVersion != resource.Status.AppliedSecretResourceVersion {
			return "", nil, "", errors.New("generated password Secret changed without rotation")
		}
		password, passwordOK := secret.Data["password"]
		hash, hashOK := secret.Data["bcryptHash"]
		if !passwordOK || !hashOK || len(password) == 0 || validateDexBcryptHash(hash) != nil || bcrypt.CompareHashAndPassword(hash, password) != nil {
			return "", nil, "", errors.New("generated password Secret is invalid")
		}
		return string(password), append([]byte(nil), hash...), secret.ResourceVersion, nil
	}
	if !apierrors.IsNotFound(err) {
		return "", nil, "", err
	}
	if resource.Status.AppliedSecretResourceVersion != "" && !rotationRequested {
		return "", nil, "", errors.New("generated password Secret is lost")
	}

	password, hash, err := generatePasswordMaterial(policy)
	if err != nil {
		return "", nil, "", err
	}
	created, err := CreateGeneratedSecret(ctx, r.Client, r.Scheme, resource, policy.SecretName, map[string][]byte{"password": []byte(password), "bcryptHash": hash})
	if err != nil {
		return "", nil, "", err
	}
	if rotationRequested {
		base := created.DeepCopy()
		if created.Annotations == nil {
			created.Annotations = map[string]string{}
		}
		created.Annotations[generatedPasswordRotationNonceAnnotation] = policy.RotationNonce
		if err := r.Patch(ctx, created, client.MergeFrom(base)); err != nil {
			return "", nil, "", err
		}
	}
	return password, hash, created.ResourceVersion, nil
}

func generatePasswordMaterial(policy *dexv1alpha1.GeneratedPasswordSpec) (string, []byte, error) {
	password, err := credentials.GeneratePassword(int(policy.Length), policy.CharacterSets)
	if err != nil {
		return "", nil, err
	}
	hash, err := credentials.BcryptHash(password)
	if err != nil {
		return "", nil, err
	}
	return password, hash, nil
}

func (r *DexLocalUserReconciler) observe(ctx context.Context, email string) (*dexapi.Password, error) {
	response, err := r.Dex.ListPasswords(ctx)
	if err != nil {
		return nil, err
	}
	for _, password := range response.GetPasswords() {
		if password.GetEmail() == email {
			return password, nil
		}
	}
	return nil, nil
}

func (r *DexLocalUserReconciler) markIdentityRepair(ctx context.Context, resource *dexv1alpha1.DexLocalUser) error {
	return r.patchStatus(ctx, resource, func(status *dexv1alpha1.DexLocalUserStatus) error {
		if err := SetCondition(&status.Conditions, resource.Generation, dexv1alpha1.ConditionReady, metav1.ConditionFalse, ReasonReconciling, "Repairing Dex user-ID drift."); err != nil {
			return err
		}
		if err := SetCondition(&status.Conditions, resource.Generation, dexv1alpha1.ConditionCompatible, metav1.ConditionTrue, ReasonConverged, "Configured Dex is compatible."); err != nil {
			return err
		}
		return SetCondition(&status.Conditions, resource.Generation, dexv1alpha1.ConditionDrifted, metav1.ConditionTrue, ReasonReconciling, "Repairing user-ID drift requires identity and session cleanup.")
	})
}

func (r *DexLocalUserReconciler) finalize(ctx context.Context, resource *dexv1alpha1.DexLocalUser) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(resource, Finalizer) {
		return ctrl.Result{}, nil
	}
	if resource.Spec.DeletionPolicy == dexv1alpha1.DeletionPolicyRetain {
		if err := r.detachGeneratedSecret(ctx, resource); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, RemoveFinalizer(ctx, r.Client, resource)
	}
	resolvedUserID := resource.Spec.UserID
	if resolvedUserID == "" {
		resolvedUserID = credentials.LocalUserID(resource.Namespace, resource.Name)
	}
	if resource.Status.ResolvedUserID != "" && resource.Status.ResolvedUserID != resolvedUserID {
		return r.statusResult(ctx, resource, ReasonDeletionBlocked, "Deletion is blocked by an external ownership mismatch.", metav1.ConditionTrue, true, nil)
	}
	if resource.Status.ResolvedUserID != "" {
		if result, blocked, err := r.compatibilityResult(ctx, resource, true); blocked || err != nil {
			return result, err
		}
		if _, err := r.Dex.DeletePassword(ctx, resource.Spec.Email); err != nil {
			return r.statusResult(ctx, resource, ReasonDeletionBlocked, "Deletion is blocked because Dex password cleanup failed.", metav1.ConditionTrue, true, err)
		}
		if _, err := r.Dex.DeleteUserIdentity(ctx, resource.Status.ResolvedUserID, localConnectorID); err != nil {
			return r.statusResult(ctx, resource, ReasonDeletionBlocked, "Deletion is blocked because Dex identity cleanup failed.", metav1.ConditionTrue, true, err)
		}
	}
	if err := r.deleteGeneratedSecret(ctx, resource); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, RemoveFinalizer(ctx, r.Client, resource)
}

func (r *DexLocalUserReconciler) detachGeneratedSecret(ctx context.Context, resource *dexv1alpha1.DexLocalUser) error {
	if resource.Spec.Password.Generated == nil {
		return nil
	}
	return DetachGeneratedSecret(ctx, r.Client, r.Scheme, resource, resource.Spec.Password.Generated.SecretName)
}

func (r *DexLocalUserReconciler) deleteGeneratedSecret(ctx context.Context, resource *dexv1alpha1.DexLocalUser) error {
	if resource.Spec.Password.Generated == nil {
		return nil
	}
	secret := &corev1.Secret{}
	key := types.NamespacedName{Namespace: resource.Namespace, Name: resource.Spec.Password.Generated.SecretName}
	if err := r.Get(ctx, key, secret); err != nil {
		return client.IgnoreNotFound(err)
	}
	if err := requireControllerOwner(secret, resource); err != nil {
		return err
	}
	return r.Delete(ctx, secret)
}

func (r *DexLocalUserReconciler) compatibilityResult(ctx context.Context, resource *dexv1alpha1.DexLocalUser, deleting bool) (ctrl.Result, bool, error) {
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

func (r *DexLocalUserReconciler) statusResult(ctx context.Context, resource *dexv1alpha1.DexLocalUser, reason, message string, compatible metav1.ConditionStatus, drifted bool, cause error) (ctrl.Result, error) {
	err := r.patchStatus(ctx, resource, func(status *dexv1alpha1.DexLocalUserStatus) error {
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

func (r *DexLocalUserReconciler) patchStatus(ctx context.Context, resource *dexv1alpha1.DexLocalUser, mutate func(*dexv1alpha1.DexLocalUserStatus) error) error {
	base := resource.DeepCopy()
	if err := mutate(&resource.Status); err != nil {
		return err
	}
	return r.Status().Patch(ctx, resource, client.MergeFrom(base))
}

// SetupWithManager sets up the controller and its referenced/generated Secret watch.
func (r *DexLocalUserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dexv1alpha1.DexLocalUser{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
			secret, ok := object.(*corev1.Secret)
			if !ok {
				return nil
			}
			requests, err := SecretRequests(ctx, r.Client, secret, &dexv1alpha1.DexLocalUserList{}, LocalUserSecretIndex)
			if err != nil {
				logf.FromContext(ctx).Error(err, "Map Secret to DexLocalUser")
				return nil
			}
			return requests
		})).
		Named("dexlocaluser").
		Complete(r)
}
