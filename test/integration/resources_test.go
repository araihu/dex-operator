//go:build integration

package integration

import (
	"bytes"
	"context"
	"slices"
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
