package controller

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	dexv1alpha1 "github.com/araihu/dex-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestConditionTransitions(t *testing.T) {
	var conditions []metav1.Condition
	if err := SetCondition(&conditions, 3, dexv1alpha1.ConditionReady, metav1.ConditionFalse, ReasonReconciling, "reconciling"); err != nil {
		t.Fatal(err)
	}
	if len(conditions) != 1 || conditions[0].ObservedGeneration != 3 || conditions[0].Reason != ReasonReconciling {
		t.Fatalf("condition = %#v", conditions)
	}
	previousTransition := conditions[0].LastTransitionTime
	if err := SetCondition(&conditions, 4, dexv1alpha1.ConditionReady, metav1.ConditionTrue, ReasonConverged, "converged"); err != nil {
		t.Fatal(err)
	}
	if conditions[0].ObservedGeneration != 4 || conditions[0].Reason != ReasonConverged || conditions[0].Status != metav1.ConditionTrue {
		t.Fatalf("condition = %#v", conditions[0])
	}
	if conditions[0].LastTransitionTime.Before(&previousTransition) {
		t.Fatal("condition transition time moved backwards")
	}
	if err := SetCondition(&conditions, 4, "Unknown", metav1.ConditionTrue, ReasonConverged, "bad"); err == nil {
		t.Fatal("SetCondition() accepted unknown condition type")
	}
	if err := SetCondition(&conditions, 4, dexv1alpha1.ConditionReady, metav1.ConditionTrue, "UnknownReason", "bad"); err == nil {
		t.Fatal("SetCondition() accepted unknown reason")
	}
}

func TestOwnershipPreclaimAndFinalizer(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	user := &dexv1alpha1.DexLocalUser{ObjectMeta: metav1.ObjectMeta{Name: "admin", Namespace: "default", UID: types.UID("user-uid")}}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&dexv1alpha1.DexLocalUser{}).WithObjects(user).Build()

	if err := EnsureFinalizer(ctx, kube, user); err != nil {
		t.Fatal(err)
	}
	if !contains(user.Finalizers, Finalizer) {
		t.Fatalf("finalizers = %#v", user.Finalizers)
	}
	if err := PreclaimOwnership(ctx, kube, user, "resolved-user-id"); err != nil {
		t.Fatal(err)
	}
	stored := &dexv1alpha1.DexLocalUser{}
	if err := kube.Get(ctx, client.ObjectKeyFromObject(user), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.ResolvedUserID != "resolved-user-id" {
		t.Fatalf("preclaim = %q", stored.Status.ResolvedUserID)
	}
	if err := PreclaimOwnership(ctx, kube, stored, "other-user-id"); err == nil {
		t.Fatal("PreclaimOwnership() replaced an existing claim")
	}
	if err := RemoveFinalizer(ctx, kube, user); err != nil {
		t.Fatal(err)
	}
	if contains(user.Finalizers, Finalizer) {
		t.Fatalf("finalizers = %#v", user.Finalizers)
	}
}

func TestRemoveFinalizerIgnoresAlreadyDeletedObject(t *testing.T) {
	ctx := context.Background()
	user := &dexv1alpha1.DexLocalUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "admin",
			Namespace:  "default",
			Finalizers: []string{Finalizer},
		},
	}
	kube := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()

	if err := RemoveFinalizer(ctx, kube, user); err != nil {
		t.Fatalf("RemoveFinalizer() error = %v, want nil", err)
	}
}

func TestSecretLoadingAndIndexedMapping(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "default", ResourceVersion: "7"}, Data: map[string][]byte{"password": []byte("secret-value")}}
	otherNamespace := secret.DeepCopy()
	otherNamespace.Namespace = "other"
	otherNamespace.Data["password"] = []byte("wrong-value")
	user := &dexv1alpha1.DexLocalUser{
		ObjectMeta: metav1.ObjectMeta{Name: "admin", Namespace: "default"},
		Spec:       dexv1alpha1.DexLocalUserSpec{Password: dexv1alpha1.DexLocalUserPasswordSpec{HashSecretRef: &dexv1alpha1.SecretKeyReference{Name: "credentials", Key: "password"}}},
	}
	unrelated := user.DeepCopy()
	unrelated.Name = "unrelated"
	unrelated.Spec.Password.HashSecretRef.Name = "other-secret"
	crossNamespace := user.DeepCopy()
	crossNamespace.Namespace = "other"
	oauth := &dexv1alpha1.DexOAuth2Client{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
		Spec: dexv1alpha1.DexOAuth2ClientSpec{Secret: &dexv1alpha1.DexOAuth2ClientSecretSpec{
			ProvidedSecretRef: &dexv1alpha1.SecretKeyReference{Name: "credentials", Key: "password"},
		}},
	}
	connector := &dexv1alpha1.DexConnector{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc", Namespace: "default"},
		Spec:       dexv1alpha1.DexConnectorSpec{ConfigSecretRef: dexv1alpha1.SecretKeyReference{Name: "credentials", Key: "config.json"}},
	}

	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(secret, otherNamespace, user, unrelated, crossNamespace, oauth, connector).
		WithIndex(&dexv1alpha1.DexLocalUser{}, LocalUserSecretIndex, localUserSecretNames).
		WithIndex(&dexv1alpha1.DexOAuth2Client{}, OAuth2ClientSecretIndex, oauth2ClientSecretNames).
		WithIndex(&dexv1alpha1.DexConnector{}, ConnectorSecretIndex, connectorSecretNames).
		Build()

	value, resourceVersion, err := LoadSecretValue(ctx, kube, user, *user.Spec.Password.HashSecretRef)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "secret-value" || resourceVersion != "7" {
		t.Fatalf("LoadSecretValue() = %q, %q", value, resourceVersion)
	}
	requests, err := SecretRequests(ctx, kube, secret, &dexv1alpha1.DexLocalUserList{}, LocalUserSecretIndex)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := requestNames(requests), []string{"default/admin"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SecretRequests() = %#v, want %#v", got, want)
	}
	for _, mapping := range []struct {
		list  client.ObjectList
		index string
		want  []string
	}{
		{&dexv1alpha1.DexOAuth2ClientList{}, OAuth2ClientSecretIndex, []string{"default/app"}},
		{&dexv1alpha1.DexConnectorList{}, ConnectorSecretIndex, []string{"default/oidc"}},
	} {
		requests, err := SecretRequests(ctx, kube, secret, mapping.list, mapping.index)
		if err != nil {
			t.Fatal(err)
		}
		if got := requestNames(requests); !reflect.DeepEqual(got, mapping.want) {
			t.Fatalf("SecretRequests(%s) = %#v, want %#v", mapping.index, got, mapping.want)
		}
	}

	marker := "sentinel-secret-value"
	secret.Data["marker"] = []byte(marker)
	if _, _, err := LoadSecretValue(ctx, kube, user, dexv1alpha1.SecretKeyReference{Name: secret.Name, Key: "missing"}); err == nil {
		t.Fatal("LoadSecretValue() error = nil, want missing key")
	} else if strings.Contains(err.Error(), marker) {
		t.Fatalf("error exposed Secret data: %v", err)
	}
}

func TestSecretIndexExtractors(t *testing.T) {
	user := &dexv1alpha1.DexLocalUser{Spec: dexv1alpha1.DexLocalUserSpec{Password: dexv1alpha1.DexLocalUserPasswordSpec{Generated: &dexv1alpha1.GeneratedPasswordSpec{SecretName: "user-secret"}}}}
	oauth := &dexv1alpha1.DexOAuth2Client{Spec: dexv1alpha1.DexOAuth2ClientSpec{Secret: &dexv1alpha1.DexOAuth2ClientSecretSpec{Generated: &dexv1alpha1.GeneratedOAuth2ClientSecretSpec{SecretName: "client-secret"}}}}
	connector := &dexv1alpha1.DexConnector{Spec: dexv1alpha1.DexConnectorSpec{ConfigSecretRef: dexv1alpha1.SecretKeyReference{Name: "connector-secret", Key: "config.json"}}}

	if got := localUserSecretNames(user); !reflect.DeepEqual(got, []string{"user-secret"}) {
		t.Fatalf("localUserSecretNames() = %#v", got)
	}
	if got := oauth2ClientSecretNames(oauth); !reflect.DeepEqual(got, []string{"client-secret"}) {
		t.Fatalf("oauth2ClientSecretNames() = %#v", got)
	}
	if got := connectorSecretNames(connector); !reflect.DeepEqual(got, []string{"connector-secret"}) {
		t.Fatalf("connectorSecretNames() = %#v", got)
	}
}

func TestSecretGeneratedOwnerConflictAndRetainDetach(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	owner := &dexv1alpha1.DexOAuth2Client{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default", UID: types.UID("owner-one")}}
	otherOwner := owner.DeepCopy()
	otherOwner.Name = "other"
	otherOwner.UID = types.UID("owner-two")
	kube := fake.NewClientBuilder().WithScheme(scheme).Build()

	created, err := CreateGeneratedSecret(ctx, kube, scheme, owner, "app-secret", map[string][]byte{"clientSecret": []byte("value")})
	if err != nil {
		t.Fatal(err)
	}
	if controller := metav1.GetControllerOf(created); controller == nil || controller.UID != owner.UID {
		t.Fatalf("controller owner = %#v", controller)
	}
	if _, err := CreateGeneratedSecret(ctx, kube, scheme, otherOwner, "app-secret", map[string][]byte{"clientSecret": []byte("other")}); err == nil {
		t.Fatal("CreateGeneratedSecret() accepted conflicting owner")
	}
	if err := DetachGeneratedSecret(ctx, kube, scheme, owner, "app-secret"); err != nil {
		t.Fatal(err)
	}
	retained := &corev1.Secret{}
	if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: "app-secret"}, retained); err != nil {
		t.Fatal(err)
	}
	if metav1.GetControllerOf(retained) != nil {
		t.Fatalf("retained Secret still has controller: %#v", retained.OwnerReferences)
	}
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := dexv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func requestNames(requests []reconcile.Request) []string {
	names := make([]string, 0, len(requests))
	for _, request := range requests {
		names = append(names, request.Namespace+"/"+request.Name)
	}
	sort.Strings(names)
	return names
}

func contains(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}
