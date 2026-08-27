package controller

import (
	"context"
	"slices"
	"testing"

	dexv1alpha1 "github.com/araihu/dex-operator/api/v1alpha1"
	dexapi "github.com/dexidp/dex/api/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestOAuth2ClientPostLogoutRedirectURIs(t *testing.T) {
	resource := &dexv1alpha1.DexOAuth2Client{Spec: dexv1alpha1.DexOAuth2ClientSpec{
		ID:                     "app",
		Name:                   "App",
		PostLogoutRedirectURIs: []string{"https://app.example/logout", "https://app.example/signed-out", "https://app.example/logout"},
	}}
	desired := desiredDexOAuth2Client(resource, "")
	want := []string{"https://app.example/logout", "https://app.example/signed-out"}
	if !slices.Equal(desired.GetPostLogoutRedirectUris(), want) {
		t.Fatalf("desired post-logout redirects = %v, want %v", desired.GetPostLogoutRedirectUris(), want)
	}

	observed := &dexapi.Client{Id: "app", Name: "App", PostLogoutRedirectUris: []string{"https://old.example/logout"}}
	request, changed := oauth2ClientUpdate(desired, observed)
	if !changed || !slices.Equal(request.GetPostLogoutRedirectUris(), want) {
		t.Fatalf("post-logout redirect update = changed %t values %v, want true %v", changed, request.GetPostLogoutRedirectUris(), want)
	}
	if oauth2ClientManagedEqual(desired, observed) {
		t.Fatal("post-logout redirect drift was treated as converged")
	}

	desired.PostLogoutRedirectUris = nil
	if !oauth2ClientNeedsRecreate(desired, observed) {
		t.Fatal("post-logout redirect removal did not require recreation")
	}
}

func TestGeneratedOAuth2ClientSecretLabelsAreDeclarative(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	resource := &dexv1alpha1.DexOAuth2Client{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default", UID: types.UID("owner-one")},
		Spec: dexv1alpha1.DexOAuth2ClientSpec{
			ID: "app",
			Secret: &dexv1alpha1.DexOAuth2ClientSecretSpec{Generated: &dexv1alpha1.GeneratedOAuth2ClientSecretSpec{
				SecretName: "app-secret",
				Labels: map[string]string{
					"app.kubernetes.io/part-of": "argocd",
					"dex.araihu.com/purpose":    "oidc",
				},
			}},
		},
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).Build()
	created, err := CreateGeneratedSecret(ctx, kube, scheme, resource, "app-secret", map[string][]byte{"clientSecret": []byte("secret-value")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	created.Labels = map[string]string{"consumer.example/keep": "true"}
	if err := kube.Update(ctx, created); err != nil {
		t.Fatal(err)
	}

	reconciler := &DexOAuth2ClientReconciler{Client: kube, Scheme: scheme}
	if _, _, err := reconciler.generatedSecret(ctx, resource, &dexapi.Client{Id: "app", Secret: "secret-value"}, true, false, true); err != nil {
		t.Fatal(err)
	}
	secret := getTestSecret(t, ctx, kube, "app-secret")
	for key, want := range map[string]string{
		"app.kubernetes.io/part-of": "argocd",
		"dex.araihu.com/purpose":    "oidc",
		"consumer.example/keep":     "true",
	} {
		if got := secret.Labels[key]; got != want {
			t.Errorf("label %q = %q, want %q", key, got, want)
		}
	}
	if secret.UID != created.UID || string(secret.Data["clientSecret"]) != "secret-value" {
		t.Fatal("label reconciliation replaced the Secret or changed its credential")
	}

	resource.Spec.Secret.Generated.Labels = map[string]string{"app.kubernetes.io/part-of": "argocd-updated"}
	if _, _, err := reconciler.generatedSecret(ctx, resource, &dexapi.Client{Id: "app", Secret: "secret-value"}, true, false, true); err != nil {
		t.Fatal(err)
	}
	secret = getTestSecret(t, ctx, kube, "app-secret")
	if got := secret.Labels["app.kubernetes.io/part-of"]; got != "argocd-updated" {
		t.Fatalf("updated managed label = %q, want argocd-updated", got)
	}
	if _, exists := secret.Labels["dex.araihu.com/purpose"]; exists {
		t.Fatal("removed declarative label remains on generated Secret")
	}
	if got := secret.Labels["consumer.example/keep"]; got != "true" {
		t.Fatalf("unmanaged label = %q, want true", got)
	}
}

func TestGeneratedOAuth2ClientSecretRejectsInvalidLabels(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	resource := &dexv1alpha1.DexOAuth2Client{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default", UID: types.UID("owner-one")},
		Spec: dexv1alpha1.DexOAuth2ClientSpec{
			ID: "app",
			Secret: &dexv1alpha1.DexOAuth2ClientSecretSpec{Generated: &dexv1alpha1.GeneratedOAuth2ClientSecretSpec{
				SecretName: "app-secret",
				Labels:     map[string]string{"invalid label": "value"},
			}},
		},
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).Build()
	if _, err := CreateGeneratedSecret(ctx, kube, scheme, resource, "app-secret", map[string][]byte{"clientSecret": []byte("secret-value")}, nil, nil); err != nil {
		t.Fatal(err)
	}
	reconciler := &DexOAuth2ClientReconciler{Client: kube, Scheme: scheme}
	if _, _, err := reconciler.generatedSecret(ctx, resource, &dexapi.Client{Id: "app", Secret: "secret-value"}, true, false, false); err == nil {
		t.Fatal("generatedSecret() accepted invalid declarative labels")
	}
	if labels := getTestSecret(t, ctx, kube, "app-secret").Labels; len(labels) != 0 {
		t.Fatalf("invalid labels mutated Secret metadata: %#v", labels)
	}
}

func TestGeneratedOAuth2ClientSecretLabelsWaitForRemoteConvergence(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	resource := &dexv1alpha1.DexOAuth2Client{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default", UID: types.UID("owner-one")},
		Spec: dexv1alpha1.DexOAuth2ClientSpec{
			ID: "app",
			Secret: &dexv1alpha1.DexOAuth2ClientSecretSpec{Generated: &dexv1alpha1.GeneratedOAuth2ClientSecretSpec{
				SecretName: "app-secret",
				Labels:     map[string]string{"app.kubernetes.io/part-of": "argocd"},
			}},
		},
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).Build()
	created, err := CreateGeneratedSecret(ctx, kube, scheme, resource, "app-secret", map[string][]byte{"clientSecret": []byte("secret-value")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	resource.Status.AppliedSecretResourceVersion = created.ResourceVersion
	reconciler := &DexOAuth2ClientReconciler{Client: kube, Scheme: scheme}

	// First pass may delete Dex for post-logout redirect removal. Metadata must wait
	// so a failed CreateClient leaves the recorded Secret resourceVersion retryable.
	if _, resourceVersion, err := reconciler.generatedSecret(ctx, resource, &dexapi.Client{
		Id: "app", Secret: "secret-value", PostLogoutRedirectUris: []string{"https://app.example/logout"},
	}, true, false, false); err != nil {
		t.Fatal(err)
	} else if resourceVersion != created.ResourceVersion {
		t.Fatalf("pre-recreate Secret resourceVersion = %q, want %q", resourceVersion, created.ResourceVersion)
	}
	if labels := getTestSecret(t, ctx, kube, "app-secret").Labels; len(labels) != 0 {
		t.Fatalf("labels applied before remote convergence: %#v", labels)
	}

	// Simulate CreateClient failure after DeleteClient: retry sees Dex absent.
	if value, resourceVersion, err := reconciler.generatedSecret(ctx, resource, nil, false, false, false); err != nil {
		t.Fatalf("retry after failed recreate: %v", err)
	} else if value != "secret-value" || resourceVersion != created.ResourceVersion {
		t.Fatalf("retry credential = value %q resourceVersion %q", value, resourceVersion)
	}

	if value, _, err := reconciler.generatedSecret(ctx, resource, &dexapi.Client{Id: "app", Secret: "secret-value"}, true, false, true); err != nil {
		t.Fatalf("confirm recreated client: %v", err)
	} else if value != "secret-value" {
		t.Fatalf("confirmed credential = %q, want original", value)
	}
	if got := getTestSecret(t, ctx, kube, "app-secret").Labels["app.kubernetes.io/part-of"]; got != "argocd" {
		t.Fatalf("post-convergence label = %q, want argocd", got)
	}
}

func TestGeneratedOAuth2ClientSecretRecoveryIsCheckpointedBeforeRemoteRecreate(t *testing.T) {
	ctx := context.Background()
	scheme := testScheme(t)
	resource := &dexv1alpha1.DexOAuth2Client{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default", UID: types.UID("owner-one")},
		Spec: dexv1alpha1.DexOAuth2ClientSpec{
			ID: "app",
			Secret: &dexv1alpha1.DexOAuth2ClientSecretSpec{Generated: &dexv1alpha1.GeneratedOAuth2ClientSecretSpec{
				SecretName: "app-secret",
				Labels:     map[string]string{"app.kubernetes.io/part-of": "argocd"},
			}},
		},
		Status: dexv1alpha1.DexOAuth2ClientStatus{
			ExternalID:                   "app",
			AppliedSecretResourceVersion: "deleted-secret-rv",
		},
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&dexv1alpha1.DexOAuth2Client{}).WithObjects(resource).Build()
	if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: "app"}, resource); err != nil {
		t.Fatal(err)
	}
	reconciler := &DexOAuth2ClientReconciler{Client: kube, Scheme: scheme}

	value, recoveredResourceVersion, err := reconciler.generatedSecret(ctx, resource, &dexapi.Client{
		Id: "app", Secret: "secret-value", PostLogoutRedirectUris: []string{"https://app.example/logout"},
	}, true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	observed := &dexapi.Client{Id: "app", Secret: "secret-value", PostLogoutRedirectUris: []string{"https://app.example/logout"}}
	checkpointed, err := reconciler.checkpointGeneratedOAuth2ClientSecretRecovery(ctx, resource, observed, true, false, "tampered-value", recoveredResourceVersion)
	if err != nil {
		t.Fatal(err)
	}
	if checkpointed || resource.Status.AppliedSecretResourceVersion != "deleted-secret-rv" {
		t.Fatalf("mismatched credential checkpoint = %t status RV %q", checkpointed, resource.Status.AppliedSecretResourceVersion)
	}
	checkpointed, err = reconciler.checkpointGeneratedOAuth2ClientSecretRecovery(ctx, resource, observed, true, false, value, recoveredResourceVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !checkpointed || resource.Status.AppliedSecretResourceVersion != recoveredResourceVersion {
		t.Fatalf("recovery checkpoint = %t status RV %q, want true and %q", checkpointed, resource.Status.AppliedSecretResourceVersion, recoveredResourceVersion)
	}

	// Simulate DeleteClient success and CreateClient failure after the checkpoint.
	retryValue, retryResourceVersion, err := reconciler.generatedSecret(ctx, resource, nil, false, false, false)
	if err != nil {
		t.Fatalf("retry after failed recreate: %v", err)
	}
	if retryValue != value || retryResourceVersion != recoveredResourceVersion {
		t.Fatalf("retry credential = value %q resourceVersion %q, want value %q resourceVersion %q", retryValue, retryResourceVersion, value, recoveredResourceVersion)
	}
}

func getTestSecret(t *testing.T, ctx context.Context, kube client.Client, name string) *corev1.Secret {
	t.Helper()
	secret := &corev1.Secret{}
	if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, secret); err != nil {
		t.Fatal(err)
	}
	return secret
}
