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
	"slices"
	"time"

	dexv1alpha1 "github.com/araihu/dex-operator/api/v1alpha1"
	dexclient "github.com/araihu/dex-operator/internal/dex"
	dexapi "github.com/dexidp/dex/api/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// DexConnectorReconciler reconciles DexConnector resources through Dex's gRPC API.
type DexConnectorReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	Dex               *dexclient.Client
	CompatibilityGate *dexclient.CompatibilityGate
	ReconcileInterval time.Duration
}

// +kubebuilder:rbac:groups=dex.araihu.com,resources=dexconnectors,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=dex.araihu.com,resources=dexconnectors/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=dex.araihu.com,resources=dexconnectors/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile converges one connector without exposing its configuration bytes.
func (r *DexConnectorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	resource := &dexv1alpha1.DexConnector{}
	if err := r.Get(ctx, req.NamespacedName, resource); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !resource.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, resource)
	}
	if err := EnsureFinalizer(ctx, r.Client, resource); err != nil {
		return ctrl.Result{}, err
	}

	desiredConfig, secretResourceVersion, err := LoadSecretValue(ctx, r.Client, resource, resource.Spec.ConfigSecretRef)
	if err != nil {
		return r.statusResult(ctx, resource, ReasonInvalidInput, "Referenced connector configuration is unavailable.", metav1.ConditionUnknown, false, nil)
	}
	if _, err := dexclient.ConnectorJSONEqual(resource.Name, resource.Spec.ConfigSecretRef.Key, desiredConfig, desiredConfig); err != nil {
		return r.statusResult(ctx, resource, ReasonInvalidInput, "Referenced connector configuration is not valid JSON.", metav1.ConditionUnknown, false, nil)
	}
	if result, blocked, err := r.compatibilityResult(ctx, resource, false); blocked || err != nil {
		return result, err
	}

	observed, err := r.observe(ctx, resource.Spec.ID)
	if err != nil {
		return r.statusResult(ctx, resource, ReasonDexUnavailable, "Dex connector state could not be observed.", metav1.ConditionFalse, false, err)
	}
	if resource.Status.ExternalID != "" && resource.Status.ExternalID != resource.Spec.ID {
		return r.statusResult(ctx, resource, ReasonConflict, "External ownership is claimed for a different connector ID.", metav1.ConditionTrue, true, nil)
	}
	if observed != nil && resource.Status.ExternalID == "" && !resource.Spec.AdoptExisting {
		return r.statusResult(ctx, resource, ReasonConflict, "A Dex connector with this ID already exists; explicit adoption is required.", metav1.ConditionTrue, true, nil)
	}
	if resource.Status.ExternalID == "" {
		if err := PreclaimOwnership(ctx, r.Client, resource, resource.Spec.ID); err != nil {
			return ctrl.Result{}, err
		}
	}

	desired := &dexapi.Connector{
		Id:         resource.Spec.ID,
		Type:       resource.Spec.Type,
		Name:       resource.Spec.Name,
		Config:     desiredConfig,
		GrantTypes: dexclient.NormalizeSet(resource.Spec.GrantTypes),
	}
	if observed == nil {
		alreadyExists, createErr := r.Dex.CreateConnector(ctx, desired)
		if createErr != nil {
			return r.statusResult(ctx, resource, ReasonDriftCorrectionFailed, "Dex connector creation failed.", metav1.ConditionTrue, true, createErr)
		}
		if alreadyExists {
			return ctrl.Result{Requeue: true}, nil
		}
	} else {
		request, changed, comparisonErr := connectorUpdate(desired, observed, resource.Name, resource.Spec.ConfigSecretRef.Key)
		if comparisonErr != nil {
			return r.statusResult(ctx, resource, ReasonDriftCorrectionFailed, "Observed connector configuration could not be compared safely.", metav1.ConditionTrue, true, comparisonErr)
		}
		if changed {
			notFound, updateErr := r.Dex.UpdateConnector(ctx, request)
			if updateErr != nil {
				return r.statusResult(ctx, resource, ReasonDriftCorrectionFailed, "Dex connector update failed.", metav1.ConditionTrue, true, updateErr)
			}
			if notFound {
				return ctrl.Result{Requeue: true}, nil
			}
		}
	}

	observed, err = r.observe(ctx, resource.Spec.ID)
	if err != nil {
		return r.statusResult(ctx, resource, ReasonDexUnavailable, "Dex connector state could not be confirmed.", metav1.ConditionFalse, false, err)
	}
	if observed == nil {
		return ctrl.Result{Requeue: true}, nil
	}
	_, changed, err := connectorUpdate(desired, observed, resource.Name, resource.Spec.ConfigSecretRef.Key)
	if err != nil || changed {
		return r.statusResult(ctx, resource, ReasonDriftCorrectionFailed, "Dex connector did not converge.", metav1.ConditionTrue, true, err)
	}
	if err := r.patchStatus(ctx, resource, func(status *dexv1alpha1.DexConnectorStatus) error {
		status.AppliedSecretResourceVersion = secretResourceVersion
		status.ObservedGeneration = resource.Generation
		if err := SetCondition(&status.Conditions, resource.Generation, dexv1alpha1.ConditionReady, metav1.ConditionTrue, ReasonConverged, "Dex connector is converged."); err != nil {
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

func (r *DexConnectorReconciler) finalize(ctx context.Context, resource *dexv1alpha1.DexConnector) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(resource, Finalizer) {
		return ctrl.Result{}, nil
	}
	if resource.Spec.DeletionPolicy == dexv1alpha1.DeletionPolicyRetain || resource.Status.ExternalID == "" {
		return ctrl.Result{}, RemoveFinalizer(ctx, r.Client, resource)
	}
	if resource.Status.ExternalID != resource.Spec.ID {
		return r.statusResult(ctx, resource, ReasonDeletionBlocked, "Deletion is blocked by an external ownership mismatch.", metav1.ConditionTrue, true, nil)
	}
	if result, blocked, err := r.compatibilityResult(ctx, resource, true); blocked || err != nil {
		return result, err
	}
	_, err := r.Dex.DeleteConnector(ctx, resource.Spec.ID)
	if err != nil {
		return r.statusResult(ctx, resource, ReasonDeletionBlocked, "Deletion is blocked because Dex cleanup failed.", metav1.ConditionTrue, true, err)
	}
	return ctrl.Result{}, RemoveFinalizer(ctx, r.Client, resource)
}

func (r *DexConnectorReconciler) observe(ctx context.Context, id string) (*dexapi.Connector, error) {
	response, err := r.Dex.ListConnectors(ctx)
	if err != nil {
		return nil, err
	}
	for _, connector := range response.GetConnectors() {
		if connector.GetId() == id {
			return connector, nil
		}
	}
	return nil, nil
}

func connectorUpdate(desired, observed *dexapi.Connector, resource, secretKey string) (*dexapi.UpdateConnectorReq, bool, error) {
	request := &dexapi.UpdateConnectorReq{Id: desired.GetId()}
	changed := false
	if observed.GetType() != desired.GetType() {
		request.NewType = desired.GetType()
		changed = true
	}
	if observed.GetName() != desired.GetName() {
		request.NewName = desired.GetName()
		changed = true
	}
	configEqual, err := dexclient.ConnectorJSONEqual(resource, secretKey, desired.GetConfig(), observed.GetConfig())
	if err != nil {
		return nil, false, err
	}
	if !configEqual {
		request.NewConfig = desired.GetConfig()
		changed = true
	}
	desiredGrants := dexclient.NormalizeSet(desired.GetGrantTypes())
	observedGrants := dexclient.NormalizeSet(observed.GetGrantTypes())
	if !slices.Equal(desiredGrants, observedGrants) {
		request.NewGrantTypes = &dexapi.GrantTypes{GrantTypes: desiredGrants}
		changed = true
	}
	return request, changed, nil
}

func (r *DexConnectorReconciler) compatibilityResult(ctx context.Context, resource *dexv1alpha1.DexConnector, deleting bool) (ctrl.Result, bool, error) {
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

func (r *DexConnectorReconciler) statusResult(ctx context.Context, resource *dexv1alpha1.DexConnector, reason, message string, compatible metav1.ConditionStatus, drifted bool, cause error) (ctrl.Result, error) {
	err := r.patchStatus(ctx, resource, func(status *dexv1alpha1.DexConnectorStatus) error {
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

func (r *DexConnectorReconciler) patchStatus(ctx context.Context, resource *dexv1alpha1.DexConnector, mutate func(*dexv1alpha1.DexConnectorStatus) error) error {
	base := resource.DeepCopy()
	if err := mutate(&resource.Status); err != nil {
		return err
	}
	return r.Status().Patch(ctx, resource, client.MergeFrom(base))
}

// SetupWithManager sets up the controller and its referenced-Secret watch.
func (r *DexConnectorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dexv1alpha1.DexConnector{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
			secret, ok := object.(*corev1.Secret)
			if !ok {
				return nil
			}
			requests, err := SecretRequests(ctx, r.Client, secret, &dexv1alpha1.DexConnectorList{}, ConnectorSecretIndex)
			if err != nil {
				logf.FromContext(ctx).Error(err, "Map Secret to DexConnector")
				return nil
			}
			return requests
		})).
		Named("dexconnector").
		Complete(r)
}
