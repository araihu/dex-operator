package controller

import (
	"context"
	"fmt"

	dexv1alpha1 "github.com/araihu/dex-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	Finalizer               = "dex.araihu.com/finalizer"
	LocalUserSecretIndex    = "dexlocaluser.secretNames"
	OAuth2ClientSecretIndex = "dexoauth2client.secretNames"
	ConnectorSecretIndex    = "dexconnector.secretNames"

	ReasonReconciling           = "Reconciling"
	ReasonConverged             = "Converged"
	ReasonConflict              = "Conflict"
	ReasonInvalidInput          = "InvalidInput"
	ReasonDexUnavailable        = "DexUnavailable"
	ReasonIncompatibleDex       = "IncompatibleDex"
	ReasonDriftCorrectionFailed = "DriftCorrectionFailed"
	ReasonDeletionBlocked       = "DeletionBlocked"
)

var allowedReasons = map[string]struct{}{
	ReasonReconciling:           {},
	ReasonConverged:             {},
	ReasonConflict:              {},
	ReasonInvalidInput:          {},
	ReasonDexUnavailable:        {},
	ReasonIncompatibleDex:       {},
	ReasonDriftCorrectionFailed: {},
	ReasonDeletionBlocked:       {},
}

// SetCondition inserts or updates one approved secret-safe condition.
func SetCondition(conditions *[]metav1.Condition, generation int64, conditionType string, status metav1.ConditionStatus, reason, message string) error {
	switch conditionType {
	case dexv1alpha1.ConditionReady, dexv1alpha1.ConditionCompatible, dexv1alpha1.ConditionDrifted:
	default:
		return fmt.Errorf("unsupported condition type %q", conditionType)
	}
	if _, ok := allowedReasons[reason]; !ok {
		return fmt.Errorf("unsupported condition reason %q", reason)
	}
	meta.SetStatusCondition(conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		ObservedGeneration: generation,
		Reason:             reason,
		Message:            message,
	})
	return nil
}

// EnsureFinalizer persists the operator finalizer before remote ownership begins.
func EnsureFinalizer(ctx context.Context, kube client.Client, object client.Object) error {
	if controllerutil.ContainsFinalizer(object, Finalizer) {
		return nil
	}
	base := object.DeepCopyObject().(client.Object)
	controllerutil.AddFinalizer(object, Finalizer)
	return kube.Patch(ctx, object, client.MergeFrom(base))
}

// RemoveFinalizer persists removal after deletion or retention completes.
func RemoveFinalizer(ctx context.Context, kube client.Client, object client.Object) error {
	if !controllerutil.ContainsFinalizer(object, Finalizer) {
		return nil
	}
	base := object.DeepCopyObject().(client.Object)
	controllerutil.RemoveFinalizer(object, Finalizer)
	return client.IgnoreNotFound(kube.Patch(ctx, object, client.MergeFrom(base)))
}

// PreclaimOwnership persists the external identity before the first create or adoption mutation.
func PreclaimOwnership(ctx context.Context, kube client.Client, object client.Object, externalID string) error {
	base := object.DeepCopyObject().(client.Object)
	current, set, err := ownershipField(object)
	if err != nil {
		return err
	}
	if current != "" {
		if current != externalID {
			return fmt.Errorf("external ownership is already claimed as %q", current)
		}
		return nil
	}
	set(externalID)
	return kube.Status().Patch(ctx, object, client.MergeFrom(base))
}

func ownershipField(object client.Object) (string, func(string), error) {
	switch typed := object.(type) {
	case *dexv1alpha1.DexLocalUser:
		return typed.Status.ResolvedUserID, func(value string) { typed.Status.ResolvedUserID = value }, nil
	case *dexv1alpha1.DexOAuth2Client:
		return typed.Status.ExternalID, func(value string) { typed.Status.ExternalID = value }, nil
	case *dexv1alpha1.DexConnector:
		return typed.Status.ExternalID, func(value string) { typed.Status.ExternalID = value }, nil
	default:
		return "", nil, fmt.Errorf("unsupported ownership object %T", object)
	}
}

// LoadSecretValue reads one same-namespace Secret key without formatting its bytes.
func LoadSecretValue(ctx context.Context, kube client.Client, owner client.Object, reference dexv1alpha1.SecretKeyReference) ([]byte, string, error) {
	secret := &corev1.Secret{}
	key := types.NamespacedName{Namespace: owner.GetNamespace(), Name: reference.Name}
	if err := kube.Get(ctx, key, secret); err != nil {
		return nil, "", fmt.Errorf("load Secret %s/%s: %w", key.Namespace, key.Name, err)
	}
	value, ok := secret.Data[reference.Key]
	if !ok {
		return nil, "", fmt.Errorf("Secret %s/%s lacks key %q", key.Namespace, key.Name, reference.Key)
	}
	return append([]byte(nil), value...), secret.ResourceVersion, nil
}

// RegisterSecretIndexes installs one named-Secret index per managed CRD.
func RegisterSecretIndexes(ctx context.Context, indexer client.FieldIndexer) error {
	for _, registration := range []struct {
		object  client.Object
		field   string
		extract client.IndexerFunc
	}{
		{&dexv1alpha1.DexLocalUser{}, LocalUserSecretIndex, localUserSecretNames},
		{&dexv1alpha1.DexOAuth2Client{}, OAuth2ClientSecretIndex, oauth2ClientSecretNames},
		{&dexv1alpha1.DexConnector{}, ConnectorSecretIndex, connectorSecretNames},
	} {
		if err := indexer.IndexField(ctx, registration.object, registration.field, registration.extract); err != nil {
			return err
		}
	}
	return nil
}

// SecretRequests maps a Secret event only to same-namespace CRs naming it.
func SecretRequests(ctx context.Context, kube client.Client, secret *corev1.Secret, list client.ObjectList, index string) ([]reconcile.Request, error) {
	if err := kube.List(ctx, list, client.InNamespace(secret.Namespace), client.MatchingFields{index: secret.Name}); err != nil {
		return nil, err
	}
	objects, err := meta.ExtractList(list)
	if err != nil {
		return nil, err
	}
	requests := make([]reconcile.Request, 0, len(objects))
	for _, object := range objects {
		managed, ok := object.(client.Object)
		if !ok {
			return nil, fmt.Errorf("indexed item %T is not a client object", object)
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(managed)})
	}
	return requests, nil
}

func localUserSecretNames(object client.Object) []string {
	user, ok := object.(*dexv1alpha1.DexLocalUser)
	if !ok {
		return nil
	}
	if user.Spec.Password.HashSecretRef != nil {
		return []string{user.Spec.Password.HashSecretRef.Name}
	}
	if user.Spec.Password.Generated != nil {
		return []string{user.Spec.Password.Generated.SecretName}
	}
	return nil
}

func oauth2ClientSecretNames(object client.Object) []string {
	oauthClient, ok := object.(*dexv1alpha1.DexOAuth2Client)
	if !ok || oauthClient.Spec.Secret == nil {
		return nil
	}
	if oauthClient.Spec.Secret.ProvidedSecretRef != nil {
		return []string{oauthClient.Spec.Secret.ProvidedSecretRef.Name}
	}
	if oauthClient.Spec.Secret.Generated != nil {
		return []string{oauthClient.Spec.Secret.Generated.SecretName}
	}
	return nil
}

func connectorSecretNames(object client.Object) []string {
	connector, ok := object.(*dexv1alpha1.DexConnector)
	if !ok || connector.Spec.ConfigSecretRef.Name == "" {
		return nil
	}
	return []string{connector.Spec.ConfigSecretRef.Name}
}

// CreateGeneratedSecret creates an owned Secret or returns the already-owned one unchanged.
func CreateGeneratedSecret(ctx context.Context, kube client.Client, scheme *runtime.Scheme, owner client.Object, name string, data map[string][]byte) (*corev1.Secret, error) {
	key := types.NamespacedName{Namespace: owner.GetNamespace(), Name: name}
	existing := &corev1.Secret{}
	if err := kube.Get(ctx, key, existing); err == nil {
		if err := requireControllerOwner(existing, owner); err != nil {
			return nil, err
		}
		return existing, nil
	} else if !apierrors.IsNotFound(err) {
		return nil, err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: owner.GetNamespace()},
		Type:       corev1.SecretTypeOpaque,
		Data:       data,
	}
	if err := controllerutil.SetControllerReference(owner, secret, scheme); err != nil {
		return nil, err
	}
	if err := kube.Create(ctx, secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// DetachGeneratedSecret removes this CR's controller reference for Retain deletion policy.
func DetachGeneratedSecret(ctx context.Context, kube client.Client, scheme *runtime.Scheme, owner client.Object, name string) error {
	secret := &corev1.Secret{}
	key := types.NamespacedName{Namespace: owner.GetNamespace(), Name: name}
	if err := kube.Get(ctx, key, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	controller := metav1.GetControllerOf(secret)
	if controller == nil {
		return nil
	}
	if controller.UID != owner.GetUID() {
		return fmt.Errorf("Secret %s/%s has a different controller owner", key.Namespace, key.Name)
	}
	if err := controllerutil.RemoveControllerReference(owner, secret, scheme); err != nil {
		return err
	}
	return kube.Update(ctx, secret)
}

func requireControllerOwner(secret *corev1.Secret, owner client.Object) error {
	controller := metav1.GetControllerOf(secret)
	if controller == nil || controller.UID != owner.GetUID() {
		return fmt.Errorf("Secret %s/%s is not controlled by %s/%s", secret.Namespace, secret.Name, owner.GetNamespace(), owner.GetName())
	}
	return nil
}
