//go:build integration

package integration

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	dexv1alpha1 "github.com/araihu/dex-operator/api/v1alpha1"
	"github.com/araihu/dex-operator/internal/controller"
	dexclient "github.com/araihu/dex-operator/internal/dex"
	dexapi "github.com/dexidp/dex/api/v2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestDexOAuth2Client(t *testing.T) {
	dexHarness := startDexHarness(t, memoryStorage)
	harness := startKubernetesHarness(t, dexHarness)
	ctx := context.Background()

	t.Run("public lifecycle", func(t *testing.T) {
		resource := newPublicOAuth2Client("public-client")
		mustCreate(t, ctx, harness.client, resource)
		managed := awaitReadyOAuth2Client(t, ctx, harness.client, resource.Name)
		assertRemoteOAuth2Client(t, ctx, harness, desiredOAuth2Client(managed, ""))

		readyBefore := meta.FindStatusCondition(managed.Status.Conditions, dexv1alpha1.ConditionReady).LastTransitionTime
		time.Sleep(600 * time.Millisecond)
		managed = getOAuth2Client(t, ctx, harness.client, resource.Name)
		readyAfter := meta.FindStatusCondition(managed.Status.Conditions, dexv1alpha1.ConditionReady).LastTransitionTime
		if !readyAfter.Equal(&readyBefore) {
			t.Fatalf("no-op reconciliation changed Ready transition: %s -> %s", readyBefore, readyAfter)
		}

		previousGeneration := managed.Generation
		managed.Spec.Name = "Public Updated"
		managed.Spec.LogoURL = "https://araihu.com/logo.svg"
		managed.Spec.RedirectURIs = []string{"https://app.araihu.com/callback", "http://127.0.0.1/callback"}
		managed.Spec.TrustedPeers = []string{"peer-b", "peer-a"}
		managed.Spec.AllowedConnectors = []string{"github", "local"}
		mustUpdate(t, ctx, harness.client, managed)
		managed = awaitReadyOAuth2ClientAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		assertRemoteOAuth2Client(t, ctx, harness, desiredOAuth2Client(managed, ""))

		previousGeneration = managed.Generation
		managed.Spec.LogoURL = ""
		mustUpdate(t, ctx, harness.client, managed)
		managed = awaitReadyOAuth2ClientAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		observed := remoteOAuth2Client(t, ctx, harness, resource.Spec.ID)
		if observed == nil || observed.GetLogoUrl() != "" {
			t.Fatal("logo removal did not converge")
		}

		if notFound, err := harness.dexClient.UpdateOAuth2Client(ctx, &dexapi.UpdateClientReq{
			Id:                resource.Spec.ID,
			Name:              "Drifted",
			RedirectUris:      []string{"https://drifted.example/callback"},
			TrustedPeers:      []string{},
			AllowedConnectors: []string{},
		}); err != nil || notFound {
			t.Fatalf("inject OAuth2 client drift: notFound=%t err=%v", notFound, err)
		}
		awaitRemoteOAuth2Client(t, ctx, harness, resource.Spec.ID, func(observed *dexapi.Client) bool {
			return oauth2ClientEqual(desiredOAuth2Client(managed, ""), observed)
		})

		if notFound, err := harness.dexClient.DeleteOAuth2Client(ctx, resource.Spec.ID); err != nil || notFound {
			t.Fatalf("delete OAuth2 client out of band: notFound=%t err=%v", notFound, err)
		}
		awaitRemoteOAuth2Client(t, ctx, harness, resource.Spec.ID, func(observed *dexapi.Client) bool {
			return oauth2ClientEqual(desiredOAuth2Client(managed, ""), observed)
		})

		mustDelete(t, ctx, harness.client, managed)
		awaitOAuth2ClientDeletion(t, ctx, harness.client, resource.Name)
		awaitRemoteOAuth2ClientAbsence(t, ctx, harness, resource.Spec.ID)
	})

	t.Run("provided secret and explicit rotation", func(t *testing.T) {
		secret := mustCreateOpaqueSecret(t, ctx, harness.client, "provided-client-secret", map[string][]byte{"clientSecret": []byte("provided-one")})
		resource := newConfidentialOAuth2Client("provided-client")
		resource.Spec.Secret = &dexv1alpha1.DexOAuth2ClientSecretSpec{ProvidedSecretRef: &dexv1alpha1.SecretKeyReference{Name: secret.Name, Key: "clientSecret"}}
		mustCreate(t, ctx, harness.client, resource)
		managed := awaitReadyOAuth2Client(t, ctx, harness.client, resource.Name)
		assertRemoteOAuth2Client(t, ctx, harness, desiredOAuth2Client(managed, "provided-one"))

		secret = getSecret(t, ctx, harness.client, secret.Name)
		secret.Annotations = map[string]string{"test": "resource-version-only"}
		mustUpdate(t, ctx, harness.client, secret)
		awaitOAuth2SecretResourceVersion(t, ctx, harness.client, resource.Name, secret.ResourceVersion)
		assertRemoteOAuth2Client(t, ctx, harness, desiredOAuth2Client(managed, "provided-one"))

		secret = getSecret(t, ctx, harness.client, secret.Name)
		secret.Data["clientSecret"] = []byte("provided-two")
		mustUpdate(t, ctx, harness.client, secret)
		awaitOAuth2Condition(t, ctx, harness.client, resource.Name, metav1.ConditionFalse, controller.ReasonConflict)
		observed := remoteOAuth2Client(t, ctx, harness, resource.Spec.ID)
		if observed == nil || observed.GetSecret() != "provided-one" {
			t.Fatal("unauthorized provided-secret change mutated Dex")
		}

		managed = getOAuth2Client(t, ctx, harness.client, resource.Name)
		previousGeneration := managed.Generation
		managed.Spec.Secret.RotationNonce = "rotation-1"
		mustUpdate(t, ctx, harness.client, managed)
		managed = awaitReadyOAuth2ClientAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		if managed.Status.HandledRotationNonce != "rotation-1" {
			t.Fatalf("handled rotation nonce = %q", managed.Status.HandledRotationNonce)
		}
		assertRemoteOAuth2Client(t, ctx, harness, desiredOAuth2Client(managed, "provided-two"))

		mustDelete(t, ctx, harness.client, managed)
		awaitOAuth2ClientDeletion(t, ctx, harness.client, resource.Name)
		awaitRemoteOAuth2ClientAbsence(t, ctx, harness, resource.Spec.ID)
		if getSecretIfPresent(t, ctx, harness.client, secret.Name) == nil {
			t.Fatal("provided Secret was deleted with the OAuth2 client")
		}
	})

	t.Run("generated secret rotation and recovery", func(t *testing.T) {
		resource := newConfidentialOAuth2Client("generated-client")
		resource.Spec.Secret = &dexv1alpha1.DexOAuth2ClientSecretSpec{Generated: &dexv1alpha1.GeneratedOAuth2ClientSecretSpec{SecretName: "generated-client-secret"}}
		mustCreate(t, ctx, harness.client, resource)
		managed := awaitReadyOAuth2Client(t, ctx, harness.client, resource.Name)
		generated := awaitSecret(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName)
		generatedValue := string(generated.Data["clientSecret"])
		if len(generatedValue) != 64 || strings.Trim(generatedValue, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") != "" {
			t.Fatal("generated client secret does not match the 64-character URL-safe contract")
		}
		if owner := metav1.GetControllerOf(generated); owner == nil || owner.UID != managed.UID {
			t.Fatalf("generated Secret controller owner = %#v", owner)
		}
		assertRemoteOAuth2Client(t, ctx, harness, desiredOAuth2Client(managed, generatedValue))

		generated.Data["clientSecret"] = []byte("manual-edit")
		mustUpdate(t, ctx, harness.client, generated)
		awaitOAuth2Condition(t, ctx, harness.client, resource.Name, metav1.ConditionFalse, controller.ReasonConflict)
		observed := remoteOAuth2Client(t, ctx, harness, resource.Spec.ID)
		if observed == nil || observed.GetSecret() != generatedValue {
			t.Fatal("manual generated-Secret edit mutated Dex without rotation")
		}

		managed = getOAuth2Client(t, ctx, harness.client, resource.Name)
		previousGeneration := managed.Generation
		managed.Spec.Secret.RotationNonce = "generated-rotation-1"
		mustUpdate(t, ctx, harness.client, managed)
		managed = awaitReadyOAuth2ClientAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		rotated := awaitSecretValueChange(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName, "manual-edit")
		if len(rotated) != 64 || rotated == generatedValue {
			t.Fatal("generated rotation did not produce fresh 64-character material")
		}
		assertRemoteOAuth2Client(t, ctx, harness, desiredOAuth2Client(managed, rotated))

		generated = awaitSecret(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName)
		oldUID := generated.UID
		mustDelete(t, ctx, harness.client, generated)
		recovered := awaitSecretUIDChange(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName, oldUID)
		if string(recovered.Data["clientSecret"]) != rotated {
			t.Fatal("lost generated Secret was not recovered from owned Dex state")
		}
		if owner := metav1.GetControllerOf(recovered); owner == nil || owner.UID != managed.UID {
			t.Fatalf("recovered Secret controller owner = %#v", owner)
		}

		managed = getOAuth2Client(t, ctx, harness.client, resource.Name)
		mustDelete(t, ctx, harness.client, managed)
		awaitOAuth2ClientDeletion(t, ctx, harness.client, resource.Name)
		awaitRemoteOAuth2ClientAbsence(t, ctx, harness, resource.Spec.ID)
		awaitSecretAbsence(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName)
	})

	t.Run("conflict and adoption", func(t *testing.T) {
		const id = "adopted-client"
		if alreadyExists, _, err := harness.dexClient.CreateOAuth2Client(ctx, &dexapi.Client{Id: id, Public: true, Name: "Existing"}); err != nil || alreadyExists {
			t.Fatalf("create existing OAuth2 client: alreadyExists=%t err=%v", alreadyExists, err)
		}
		resource := newPublicOAuth2Client(id)
		mustCreate(t, ctx, harness.client, resource)
		conflicted := awaitOAuth2Condition(t, ctx, harness.client, resource.Name, metav1.ConditionFalse, controller.ReasonConflict)
		if conflicted.Status.ExternalID != "" {
			t.Fatalf("conflicted resource claimed external ID %q", conflicted.Status.ExternalID)
		}
		previousGeneration := conflicted.Generation
		conflicted.Spec.AdoptExisting = true
		mustUpdate(t, ctx, harness.client, conflicted)
		adopted := awaitReadyOAuth2ClientAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		assertRemoteOAuth2Client(t, ctx, harness, desiredOAuth2Client(adopted, ""))
		mustDelete(t, ctx, harness.client, adopted)
		awaitOAuth2ClientDeletion(t, ctx, harness.client, resource.Name)
		awaitRemoteOAuth2ClientAbsence(t, ctx, harness, id)
	})

	t.Run("Retain detaches generated Secret", func(t *testing.T) {
		resource := newConfidentialOAuth2Client("retained-client")
		resource.Spec.Secret = &dexv1alpha1.DexOAuth2ClientSecretSpec{Generated: &dexv1alpha1.GeneratedOAuth2ClientSecretSpec{SecretName: "retained-client-secret"}}
		resource.Spec.DeletionPolicy = dexv1alpha1.DeletionPolicyRetain
		mustCreate(t, ctx, harness.client, resource)
		managed := awaitReadyOAuth2Client(t, ctx, harness.client, resource.Name)
		mustDelete(t, ctx, harness.client, managed)
		awaitOAuth2ClientDeletion(t, ctx, harness.client, resource.Name)
		retainedSecret := awaitSecret(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName)
		if metav1.GetControllerOf(retainedSecret) != nil {
			t.Fatalf("retained generated Secret still has a controller: %#v", retainedSecret.OwnerReferences)
		}
		if remoteOAuth2Client(t, ctx, harness, resource.Spec.ID) == nil {
			t.Fatal("Retain deleted the remote OAuth2 client")
		}
		_, _ = harness.dexClient.DeleteOAuth2Client(ctx, resource.Spec.ID)
	})
}

func TestDexConnector(t *testing.T) {
	dexHarness := startDexHarness(t, memoryStorage)
	harness := startKubernetesHarness(t, dexHarness)
	ctx := context.Background()

	t.Run("missing Secret", func(t *testing.T) {
		resource := newConnector("missing-secret", "missing-secret-config")
		mustCreate(t, ctx, harness.client, resource)
		awaitCondition(t, ctx, harness.client, resource.Name, dexv1alpha1.ConditionReady, metav1.ConditionFalse, controller.ReasonInvalidInput)
		if remoteConnector(t, ctx, harness, resource.Spec.ID) != nil {
			t.Fatal("connector was created without its Secret")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		mustCreateConfigSecret(t, ctx, harness.client, "invalid-config", []byte(`{"sentinel":`))
		resource := newConnector("invalid-json", "invalid-config")
		mustCreate(t, ctx, harness.client, resource)
		awaitCondition(t, ctx, harness.client, resource.Name, dexv1alpha1.ConditionReady, metav1.ConditionFalse, controller.ReasonInvalidInput)
		if remoteConnector(t, ctx, harness, resource.Spec.ID) != nil {
			t.Fatal("connector was created from invalid JSON")
		}
	})

	t.Run("create, no-op, update, drift repair, recreation, and Delete", func(t *testing.T) {
		initialConfig := []byte(`{"key":"value","nested":{"one":1}}`)
		secret := mustCreateConfigSecret(t, ctx, harness.client, "managed-config", initialConfig)
		resource := newConnector("managed", secret.Name)
		mustCreate(t, ctx, harness.client, resource)
		managed := awaitReadyConnector(t, ctx, harness.client, resource.Name)
		if managed.Status.ExternalID != resource.Spec.ID || managed.Status.AppliedSecretResourceVersion != secret.ResourceVersion {
			t.Fatalf("status = %#v", managed.Status)
		}
		assertRemoteConnector(t, ctx, harness, resource.Spec.ID, "Managed", initialConfig, nil)

		readyBefore := meta.FindStatusCondition(managed.Status.Conditions, dexv1alpha1.ConditionReady).LastTransitionTime
		time.Sleep(600 * time.Millisecond)
		managed = getConnector(t, ctx, harness.client, resource.Name)
		readyAfter := meta.FindStatusCondition(managed.Status.Conditions, dexv1alpha1.ConditionReady).LastTransitionTime
		if !readyAfter.Equal(&readyBefore) {
			t.Fatalf("no-op reconciliation changed Ready transition: %s -> %s", readyBefore, readyAfter)
		}

		secret = getSecret(t, ctx, harness.client, secret.Name)
		secret.Data["config.json"] = []byte(`{ "nested": { "one": 1 }, "key": "value" }`)
		mustUpdate(t, ctx, harness.client, secret)
		awaitSecretResourceVersion(t, ctx, harness.client, resource.Name, secret.ResourceVersion)
		observed := remoteConnector(t, ctx, harness, resource.Spec.ID)
		if observed == nil || !bytes.Equal(observed.GetConfig(), initialConfig) {
			t.Fatalf("semantic JSON no-op rewrote config: %q", observed.GetConfig())
		}

		updatedConfig := []byte(`{"key":"updated"}`)
		secret = getSecret(t, ctx, harness.client, secret.Name)
		secret.Data["config.json"] = updatedConfig
		mustUpdate(t, ctx, harness.client, secret)
		managed = getConnector(t, ctx, harness.client, resource.Name)
		previousGeneration := managed.Generation
		managed.Spec.Name = "Managed Updated"
		managed.Spec.GrantTypes = []string{"refresh_token", "authorization_code"}
		mustUpdate(t, ctx, harness.client, managed)
		awaitReadyConnectorAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		assertRemoteConnector(t, ctx, harness, resource.Spec.ID, "Managed Updated", updatedConfig, []string{"authorization_code", "refresh_token"})

		if notFound, err := harness.dexClient.UpdateConnector(ctx, &dexapi.UpdateConnectorReq{
			Id:            resource.Spec.ID,
			NewName:       "Drifted",
			NewConfig:     []byte(`{"drifted":true}`),
			NewGrantTypes: &dexapi.GrantTypes{},
		}); err != nil || notFound {
			t.Fatalf("inject connector drift: notFound=%t err=%v", notFound, err)
		}
		awaitRemoteConnector(t, ctx, harness, resource.Spec.ID, func(connector *dexapi.Connector) bool {
			equal, _ := connectorConfigEqual(updatedConfig, connector.GetConfig())
			return connector.GetName() == "Managed Updated" && equal && equalStrings(connector.GetGrantTypes(), []string{"authorization_code", "refresh_token"})
		})

		if notFound, err := harness.dexClient.DeleteConnector(ctx, resource.Spec.ID); err != nil || notFound {
			t.Fatalf("delete managed connector out of band: notFound=%t err=%v", notFound, err)
		}
		awaitRemoteConnector(t, ctx, harness, resource.Spec.ID, func(connector *dexapi.Connector) bool {
			return connector.GetName() == "Managed Updated"
		})

		mustDelete(t, ctx, harness.client, managed)
		awaitKubernetesDeletion(t, ctx, harness.client, resource.Name)
		awaitRemoteAbsence(t, ctx, harness, resource.Spec.ID)
	})

	t.Run("conflict and explicit adoption", func(t *testing.T) {
		const id = "adopted"
		if alreadyExists, err := harness.dexClient.CreateConnector(ctx, &dexapi.Connector{Id: id, Type: "test", Name: "Existing", Config: []byte(`{"existing":true}`)}); err != nil || alreadyExists {
			t.Fatalf("create existing connector: alreadyExists=%t err=%v", alreadyExists, err)
		}
		mustCreateConfigSecret(t, ctx, harness.client, "adopted-config", []byte(`{"desired":true}`))
		resource := newConnector(id, "adopted-config")
		mustCreate(t, ctx, harness.client, resource)
		conflicted := awaitCondition(t, ctx, harness.client, resource.Name, dexv1alpha1.ConditionReady, metav1.ConditionFalse, controller.ReasonConflict)
		if conflicted.Status.ExternalID != "" {
			t.Fatalf("conflicted resource claimed external ID %q", conflicted.Status.ExternalID)
		}
		previousGeneration := conflicted.Generation
		conflicted.Spec.AdoptExisting = true
		mustUpdate(t, ctx, harness.client, conflicted)
		adopted := awaitReadyConnectorAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		if adopted.Status.ExternalID != id {
			t.Fatalf("adopted external ID = %q", adopted.Status.ExternalID)
		}
		assertRemoteConnector(t, ctx, harness, id, "Managed", []byte(`{"desired":true}`), nil)
		mustDelete(t, ctx, harness.client, adopted)
		awaitKubernetesDeletion(t, ctx, harness.client, resource.Name)
		awaitRemoteAbsence(t, ctx, harness, id)
	})

	t.Run("Retain", func(t *testing.T) {
		mustCreateConfigSecret(t, ctx, harness.client, "retained-config", []byte(`{"retained":true}`))
		resource := newConnector("retained", "retained-config")
		resource.Spec.DeletionPolicy = dexv1alpha1.DeletionPolicyRetain
		mustCreate(t, ctx, harness.client, resource)
		retained := awaitReadyConnector(t, ctx, harness.client, resource.Name)
		mustDelete(t, ctx, harness.client, retained)
		awaitKubernetesDeletion(t, ctx, harness.client, resource.Name)
		if remoteConnector(t, ctx, harness, resource.Spec.ID) == nil {
			t.Fatal("Retain deleted the remote connector")
		}
	})

	t.Run("Dex unavailable blocks finalizer", func(t *testing.T) {
		mustCreateConfigSecret(t, ctx, harness.client, "blocked-config", []byte(`{"blocked":true}`))
		resource := newConnector("blocked", "blocked-config")
		mustCreate(t, ctx, harness.client, resource)
		blocked := awaitReadyConnector(t, ctx, harness.client, resource.Name)
		stopCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := dexHarness.container.Stop(stopCtx, nil); err != nil {
			t.Fatal(err)
		}
		mustDelete(t, ctx, harness.client, blocked)
		deleting := awaitCondition(t, ctx, harness.client, resource.Name, dexv1alpha1.ConditionReady, metav1.ConditionFalse, controller.ReasonDeletionBlocked)
		if deleting.DeletionTimestamp.IsZero() || !containsString(deleting.Finalizers, controller.Finalizer) {
			t.Fatalf("deletion was not blocked by finalizer: %#v", deleting.ObjectMeta)
		}
	})
}

func newConnector(name, secretName string) *dexv1alpha1.DexConnector {
	return &dexv1alpha1.DexConnector{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: dexv1alpha1.DexConnectorSpec{
			ID:              name,
			Type:            "test",
			Name:            "Managed",
			ConfigSecretRef: dexv1alpha1.SecretKeyReference{Name: secretName, Key: "config.json"},
		},
	}
}

func mustCreateConfigSecret(t *testing.T, ctx context.Context, kube client.Client, name string, config []byte) *corev1.Secret {
	t.Helper()
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}, Data: map[string][]byte{"config.json": config}}
	mustCreate(t, ctx, kube, secret)
	return secret
}

func mustCreate(t *testing.T, ctx context.Context, kube client.Client, object client.Object) {
	t.Helper()
	if err := kube.Create(ctx, object); err != nil {
		t.Fatal(err)
	}
}

func mustUpdate(t *testing.T, ctx context.Context, kube client.Client, object client.Object) {
	t.Helper()
	if err := kube.Update(ctx, object); err != nil {
		t.Fatal(err)
	}
}

func mustDelete(t *testing.T, ctx context.Context, kube client.Client, object client.Object) {
	t.Helper()
	if err := kube.Delete(ctx, object); err != nil {
		t.Fatal(err)
	}
}

func getConnector(t *testing.T, ctx context.Context, kube client.Client, name string) *dexv1alpha1.DexConnector {
	t.Helper()
	resource := &dexv1alpha1.DexConnector{}
	if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, resource); err != nil {
		t.Fatal(err)
	}
	return resource
}

func getSecret(t *testing.T, ctx context.Context, kube client.Client, name string) *corev1.Secret {
	t.Helper()
	secret := &corev1.Secret{}
	if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, secret); err != nil {
		t.Fatal(err)
	}
	return secret
}

func awaitReadyConnector(t *testing.T, ctx context.Context, kube client.Client, name string) *dexv1alpha1.DexConnector {
	t.Helper()
	return awaitCondition(t, ctx, kube, name, dexv1alpha1.ConditionReady, metav1.ConditionTrue, controller.ReasonConverged)
}

func awaitReadyConnectorAfter(t *testing.T, ctx context.Context, kube client.Client, name string, generation int64) *dexv1alpha1.DexConnector {
	t.Helper()
	var result *dexv1alpha1.DexConnector
	eventually(t, func() (bool, error) {
		resource := &dexv1alpha1.DexConnector{}
		if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, resource); err != nil {
			return false, err
		}
		condition := meta.FindStatusCondition(resource.Status.Conditions, dexv1alpha1.ConditionReady)
		if resource.Generation > generation && condition != nil && condition.ObservedGeneration == resource.Generation && condition.Status == metav1.ConditionTrue && condition.Reason == controller.ReasonConverged {
			result = resource
			return true, nil
		}
		return false, nil
	})
	return result
}

func awaitCondition(t *testing.T, ctx context.Context, kube client.Client, name, conditionType string, status metav1.ConditionStatus, reason string) *dexv1alpha1.DexConnector {
	t.Helper()
	var result *dexv1alpha1.DexConnector
	eventually(t, func() (bool, error) {
		resource := &dexv1alpha1.DexConnector{}
		if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, resource); err != nil {
			return false, err
		}
		condition := meta.FindStatusCondition(resource.Status.Conditions, conditionType)
		if condition != nil && condition.ObservedGeneration == resource.Generation && condition.Status == status && condition.Reason == reason {
			result = resource
			return true, nil
		}
		return false, nil
	})
	return result
}

func awaitSecretResourceVersion(t *testing.T, ctx context.Context, kube client.Client, name, resourceVersion string) {
	t.Helper()
	eventually(t, func() (bool, error) {
		resource := &dexv1alpha1.DexConnector{}
		if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, resource); err != nil {
			return false, err
		}
		return resource.Status.AppliedSecretResourceVersion == resourceVersion, nil
	})
}

func awaitKubernetesDeletion(t *testing.T, ctx context.Context, kube client.Client, name string) {
	t.Helper()
	eventually(t, func() (bool, error) {
		err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, &dexv1alpha1.DexConnector{})
		return apierrors.IsNotFound(err), ignoreNotFound(err)
	})
}

func remoteConnector(t *testing.T, ctx context.Context, harness *kubernetesHarness, id string) *dexapi.Connector {
	t.Helper()
	response, err := harness.dexClient.ListConnectors(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, connector := range response.GetConnectors() {
		if connector.GetId() == id {
			return connector
		}
	}
	return nil
}

func assertRemoteConnector(t *testing.T, ctx context.Context, harness *kubernetesHarness, id, name string, config []byte, grantTypes []string) {
	t.Helper()
	connector := remoteConnector(t, ctx, harness, id)
	if connector == nil {
		t.Fatalf("remote connector %q is absent", id)
	}
	equalConfig, err := connectorConfigEqual(config, connector.GetConfig())
	if err != nil || connector.GetName() != name || !equalConfig || !equalStrings(connector.GetGrantTypes(), grantTypes) {
		t.Fatalf("remote connector mismatch: name=%q configEqual=%t grants=%v err=%v", connector.GetName(), equalConfig, connector.GetGrantTypes(), err)
	}
}

func awaitRemoteConnector(t *testing.T, ctx context.Context, harness *kubernetesHarness, id string, check func(*dexapi.Connector) bool) {
	t.Helper()
	eventually(t, func() (bool, error) {
		response, err := harness.dexClient.ListConnectors(ctx)
		if err != nil {
			return false, err
		}
		for _, connector := range response.GetConnectors() {
			if connector.GetId() == id {
				return check(connector), nil
			}
		}
		return false, nil
	})
}

func awaitRemoteAbsence(t *testing.T, ctx context.Context, harness *kubernetesHarness, id string) {
	t.Helper()
	eventually(t, func() (bool, error) {
		response, err := harness.dexClient.ListConnectors(ctx)
		if err != nil {
			return false, err
		}
		for _, connector := range response.GetConnectors() {
			if connector.GetId() == id {
				return false, nil
			}
		}
		return true, nil
	})
}

func eventually(t *testing.T, check func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ok, err := check()
		if ok {
			return
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("condition not met before timeout: %v", lastErr)
}

func connectorConfigEqual(desired, observed []byte) (bool, error) {
	return dexclient.ConnectorJSONEqual("integration connector", "config.json", desired, observed)
}

func equalStrings(left, right []string) bool {
	return slices.Equal(dexclient.NormalizeSet(left), dexclient.NormalizeSet(right))
}

func ignoreNotFound(err error) error {
	if err == nil || apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func containsString(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}

func newPublicOAuth2Client(name string) *dexv1alpha1.DexOAuth2Client {
	return &dexv1alpha1.DexOAuth2Client{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: dexv1alpha1.DexOAuth2ClientSpec{
			ID:           name,
			Public:       true,
			Name:         "Public Client",
			RedirectURIs: []string{"https://app.araihu.com/callback"},
		},
	}
}

func newConfidentialOAuth2Client(name string) *dexv1alpha1.DexOAuth2Client {
	return &dexv1alpha1.DexOAuth2Client{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: dexv1alpha1.DexOAuth2ClientSpec{
			ID:           name,
			Name:         "Confidential Client",
			RedirectURIs: []string{"https://app.araihu.com/callback"},
		},
	}
}

func desiredOAuth2Client(resource *dexv1alpha1.DexOAuth2Client, secret string) *dexapi.Client {
	return &dexapi.Client{
		Id:                resource.Spec.ID,
		Secret:            secret,
		Public:            resource.Spec.Public,
		Name:              resource.Spec.Name,
		LogoUrl:           resource.Spec.LogoURL,
		RedirectUris:      dexclient.NormalizeSet(resource.Spec.RedirectURIs),
		TrustedPeers:      dexclient.NormalizeSet(resource.Spec.TrustedPeers),
		AllowedConnectors: dexclient.NormalizeSet(resource.Spec.AllowedConnectors),
	}
}

func mustCreateOpaqueSecret(t *testing.T, ctx context.Context, kube client.Client, name string, data map[string][]byte) *corev1.Secret {
	t.Helper()
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}, Type: corev1.SecretTypeOpaque, Data: data}
	mustCreate(t, ctx, kube, secret)
	return secret
}

func getOAuth2Client(t *testing.T, ctx context.Context, kube client.Client, name string) *dexv1alpha1.DexOAuth2Client {
	t.Helper()
	resource := &dexv1alpha1.DexOAuth2Client{}
	if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, resource); err != nil {
		t.Fatal(err)
	}
	return resource
}

func awaitReadyOAuth2Client(t *testing.T, ctx context.Context, kube client.Client, name string) *dexv1alpha1.DexOAuth2Client {
	t.Helper()
	return awaitOAuth2Condition(t, ctx, kube, name, metav1.ConditionTrue, controller.ReasonConverged)
}

func awaitReadyOAuth2ClientAfter(t *testing.T, ctx context.Context, kube client.Client, name string, generation int64) *dexv1alpha1.DexOAuth2Client {
	t.Helper()
	var result *dexv1alpha1.DexOAuth2Client
	eventually(t, func() (bool, error) {
		resource := &dexv1alpha1.DexOAuth2Client{}
		if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, resource); err != nil {
			return false, err
		}
		condition := meta.FindStatusCondition(resource.Status.Conditions, dexv1alpha1.ConditionReady)
		if resource.Generation > generation && condition != nil && condition.ObservedGeneration == resource.Generation && condition.Status == metav1.ConditionTrue && condition.Reason == controller.ReasonConverged {
			result = resource
			return true, nil
		}
		return false, nil
	})
	return result
}

func awaitOAuth2Condition(t *testing.T, ctx context.Context, kube client.Client, name string, status metav1.ConditionStatus, reason string) *dexv1alpha1.DexOAuth2Client {
	t.Helper()
	var result *dexv1alpha1.DexOAuth2Client
	eventually(t, func() (bool, error) {
		resource := &dexv1alpha1.DexOAuth2Client{}
		if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, resource); err != nil {
			return false, err
		}
		condition := meta.FindStatusCondition(resource.Status.Conditions, dexv1alpha1.ConditionReady)
		if condition != nil && condition.ObservedGeneration == resource.Generation && condition.Status == status && condition.Reason == reason {
			result = resource
			return true, nil
		}
		return false, nil
	})
	return result
}

func awaitOAuth2SecretResourceVersion(t *testing.T, ctx context.Context, kube client.Client, name, resourceVersion string) {
	t.Helper()
	eventually(t, func() (bool, error) {
		resource := &dexv1alpha1.DexOAuth2Client{}
		if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, resource); err != nil {
			return false, err
		}
		return resource.Status.AppliedSecretResourceVersion == resourceVersion, nil
	})
}

func awaitOAuth2ClientDeletion(t *testing.T, ctx context.Context, kube client.Client, name string) {
	t.Helper()
	eventually(t, func() (bool, error) {
		err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, &dexv1alpha1.DexOAuth2Client{})
		return apierrors.IsNotFound(err), ignoreNotFound(err)
	})
}

func remoteOAuth2Client(t *testing.T, ctx context.Context, harness *kubernetesHarness, id string) *dexapi.Client {
	t.Helper()
	observed, found, err := harness.dexClient.GetOAuth2Client(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		return nil
	}
	return observed
}

func assertRemoteOAuth2Client(t *testing.T, ctx context.Context, harness *kubernetesHarness, desired *dexapi.Client) {
	t.Helper()
	observed := remoteOAuth2Client(t, ctx, harness, desired.GetId())
	if observed == nil {
		t.Fatalf("remote OAuth2 client %q is absent", desired.GetId())
	}
	if !oauth2ClientEqual(desired, observed) {
		t.Fatalf("remote OAuth2 client mismatch: public=%t name=%q logo=%q redirects=%v peers=%v connectors=%v secretMatches=%t",
			observed.GetPublic(), observed.GetName(), observed.GetLogoUrl(), observed.GetRedirectUris(), observed.GetTrustedPeers(), observed.GetAllowedConnectors(), observed.GetSecret() == desired.GetSecret())
	}
}

func oauth2ClientEqual(desired, observed *dexapi.Client) bool {
	return desired.GetId() == observed.GetId() &&
		desired.GetSecret() == observed.GetSecret() &&
		desired.GetPublic() == observed.GetPublic() &&
		desired.GetName() == observed.GetName() &&
		desired.GetLogoUrl() == observed.GetLogoUrl() &&
		equalStrings(desired.GetRedirectUris(), observed.GetRedirectUris()) &&
		equalStrings(desired.GetTrustedPeers(), observed.GetTrustedPeers()) &&
		equalStrings(desired.GetAllowedConnectors(), observed.GetAllowedConnectors())
}

func awaitRemoteOAuth2Client(t *testing.T, ctx context.Context, harness *kubernetesHarness, id string, check func(*dexapi.Client) bool) {
	t.Helper()
	eventually(t, func() (bool, error) {
		observed, found, err := harness.dexClient.GetOAuth2Client(ctx, id)
		if err != nil {
			return false, err
		}
		return found && check(observed), nil
	})
}

func awaitRemoteOAuth2ClientAbsence(t *testing.T, ctx context.Context, harness *kubernetesHarness, id string) {
	t.Helper()
	eventually(t, func() (bool, error) {
		_, found, err := harness.dexClient.GetOAuth2Client(ctx, id)
		return !found, err
	})
}

func awaitSecret(t *testing.T, ctx context.Context, kube client.Client, name string) *corev1.Secret {
	t.Helper()
	var result *corev1.Secret
	eventually(t, func() (bool, error) {
		secret := &corev1.Secret{}
		if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, secret); err != nil {
			return false, ignoreNotFound(err)
		}
		result = secret
		return true, nil
	})
	return result
}

func getSecretIfPresent(t *testing.T, ctx context.Context, kube client.Client, name string) *corev1.Secret {
	t.Helper()
	secret := &corev1.Secret{}
	if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		t.Fatal(err)
	}
	return secret
}

func awaitSecretValueChange(t *testing.T, ctx context.Context, kube client.Client, name, previous string) string {
	t.Helper()
	var result string
	eventually(t, func() (bool, error) {
		secret := &corev1.Secret{}
		if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, secret); err != nil {
			return false, ignoreNotFound(err)
		}
		result = string(secret.Data["clientSecret"])
		return result != "" && result != previous, nil
	})
	return result
}

func awaitSecretUIDChange(t *testing.T, ctx context.Context, kube client.Client, name string, previous types.UID) *corev1.Secret {
	t.Helper()
	var result *corev1.Secret
	eventually(t, func() (bool, error) {
		secret := &corev1.Secret{}
		if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, secret); err != nil {
			return false, ignoreNotFound(err)
		}
		if secret.UID == previous {
			return false, nil
		}
		result = secret
		return true, nil
	})
	return result
}

func awaitSecretAbsence(t *testing.T, ctx context.Context, kube client.Client, name string) {
	t.Helper()
	eventually(t, func() (bool, error) {
		err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, &corev1.Secret{})
		return apierrors.IsNotFound(err), ignoreNotFound(err)
	})
}
