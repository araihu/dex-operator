//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	dexv1alpha1 "github.com/araihu/dex-operator/api/v1alpha1"
	"github.com/araihu/dex-operator/internal/controller"
	"github.com/araihu/dex-operator/internal/credentials"
	dexclient "github.com/araihu/dex-operator/internal/dex"
	dexapi "github.com/dexidp/dex/api/v2"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestReadyConditionSet(t *testing.T) {
	conditions := []metav1.Condition{
		{Type: dexv1alpha1.ConditionReady, Status: metav1.ConditionTrue, Reason: controller.ReasonConverged, ObservedGeneration: 3},
		{Type: dexv1alpha1.ConditionCompatible, Status: metav1.ConditionTrue, Reason: controller.ReasonConverged, ObservedGeneration: 3},
		{Type: dexv1alpha1.ConditionDrifted, Status: metav1.ConditionFalse, Reason: controller.ReasonConverged, ObservedGeneration: 3},
	}
	if !readyConditionSet(conditions, 3) {
		t.Fatal("converged condition set was rejected")
	}
	conditions[2].Status = metav1.ConditionTrue
	if readyConditionSet(conditions, 3) {
		t.Fatal("drifted condition set was accepted")
	}
}

func TestRestartReplay(t *testing.T) {
	dexHarness := startDexHarness(t, sqliteStorage)
	harness := startKubernetesHarness(t, dexHarness)
	ctx := context.Background()

	connectorConfig := []byte(`{"restart":"connector"}`)
	mustCreateConfigSecret(t, ctx, harness.client, "restart-connector-config", connectorConfig)
	connector := newConnector("restart-connector", "restart-connector-config")
	oauth := newConfidentialOAuth2Client("restart-client")
	oauth.Spec.Secret = &dexv1alpha1.DexOAuth2ClientSecretSpec{Generated: &dexv1alpha1.GeneratedOAuth2ClientSecretSpec{SecretName: "restart-client-secret"}}
	user := newGeneratedLocalUser("restart-user", "restart@example.com", "restart-subject", "restart-user-secret")
	for _, resource := range []client.Object{connector, oauth, user} {
		mustCreate(t, ctx, harness.client, resource)
	}
	awaitReadyConnector(t, ctx, harness.client, connector.Name)
	awaitReadyOAuth2Client(t, ctx, harness.client, oauth.Name)
	awaitReadyLocalUser(t, ctx, harness.client, user.Name)
	clientSecret := string(awaitSecret(t, ctx, harness.client, oauth.Spec.Secret.Generated.SecretName).Data["clientSecret"])
	password := string(awaitSecret(t, ctx, harness.client, user.Spec.Password.Generated.SecretName).Data["password"])

	dexHarness.restart(t)
	awaitRemoteConnector(t, ctx, harness, connector.Spec.ID, func(observed *dexapi.Connector) bool {
		equal, _ := connectorConfigEqual(connectorConfig, observed.GetConfig())
		return equal
	})
	awaitRemoteOAuth2Client(t, ctx, harness, oauth.Spec.ID, func(observed *dexapi.Client) bool {
		return observed.GetSecret() == clientSecret
	})
	awaitPasswordVerification(t, ctx, harness, user.Spec.Email, password, true)
	if got := string(awaitSecret(t, ctx, harness.client, oauth.Spec.Secret.Generated.SecretName).Data["clientSecret"]); got != clientSecret {
		t.Fatal("restart replay rotated the generated OAuth2 client Secret")
	}
	if got := string(awaitSecret(t, ctx, harness.client, user.Spec.Password.Generated.SecretName).Data["password"]); got != password {
		t.Fatal("restart replay rotated the generated local-user password")
	}
}

func TestSecretSafety(t *testing.T) {
	dexHarness := startDexHarness(t, memoryStorage)
	harness := startKubernetesHarness(t, dexHarness)
	ctx := context.Background()

	connectorSecret := `{"token":"sentinel-connector-secret-3fcb2d"}`
	mustCreateConfigSecret(t, ctx, harness.client, "secret-safety-connector", []byte(connectorSecret))
	connector := newConnector("secret-safety-connector", "secret-safety-connector")
	oauthSecret := "sentinel-oauth-secret-02d6e1"
	mustCreateOpaqueSecret(t, ctx, harness.client, "secret-safety-oauth", map[string][]byte{"clientSecret": []byte(oauthSecret)})
	oauth := newConfidentialOAuth2Client("secret-safety-oauth")
	oauth.Spec.Secret = &dexv1alpha1.DexOAuth2ClientSecretSpec{ProvidedSecretRef: &dexv1alpha1.SecretKeyReference{Name: "secret-safety-oauth", Key: "clientSecret"}}
	user := newGeneratedLocalUser("secret-safety-user", "secret-safety@example.com", "secret-safety-subject", "secret-safety-user")
	for _, resource := range []client.Object{connector, oauth, user} {
		mustCreate(t, ctx, harness.client, resource)
	}
	managedConnector := awaitReadyConnector(t, ctx, harness.client, connector.Name)
	managedOAuth := awaitReadyOAuth2Client(t, ctx, harness.client, oauth.Name)
	managedUser := awaitReadyLocalUser(t, ctx, harness.client, user.Name)
	generated := awaitSecret(t, ctx, harness.client, user.Spec.Password.Generated.SecretName)
	clientKey, err := os.ReadFile(dexHarness.clientTLS.Key)
	if err != nil {
		t.Fatal(err)
	}

	status, err := json.Marshal([]any{managedConnector.Status, managedOAuth.Status, managedUser.Status})
	if err != nil {
		t.Fatal(err)
	}
	events := &corev1.EventList{}
	if err := harness.client.List(ctx, events, client.InNamespace("default")); err != nil {
		t.Fatal(err)
	}
	eventJSON, err := json.Marshal(events.Items)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		connectorSecret,
		oauthSecret,
		string(generated.Data["password"]),
		string(generated.Data["bcryptHash"]),
		string(clientKey),
	} {
		for name, observed := range map[string]string{
			"status": string(status),
			"logs":   harness.logs.String(),
			"events": string(eventJSON),
		} {
			if strings.Contains(observed, secret) {
				t.Fatalf("%s exposed secret material", name)
			}
		}
	}
}

func TestDexLocalUser(t *testing.T) {
	dexHarness := startDexHarness(t, memoryStorage)
	harness := startKubernetesHarness(t, dexHarness)
	ctx := context.Background()

	t.Run("derived ID and provided hash lifecycle", func(t *testing.T) {
		hashOne := mustBcryptHash(t, "provided-password-one")
		secret := mustCreateOpaqueSecret(t, ctx, harness.client, "provided-user-hash", map[string][]byte{"bcryptHash": hashOne})
		resource := newProvidedLocalUser("provided-user", "provided@example.com", secret.Name)
		mustCreate(t, ctx, harness.client, resource)
		managed := awaitReadyLocalUser(t, ctx, harness.client, resource.Name)
		expectedID := credentials.LocalUserID("default", resource.Name)
		if managed.Status.ResolvedUserID != expectedID {
			t.Fatalf("resolved user ID = %q, want %q", managed.Status.ResolvedUserID, expectedID)
		}
		assertRemotePassword(t, ctx, harness, resource.Spec.Email, resource.Spec.Username, expectedID)
		assertPasswordVerification(t, ctx, harness, resource.Spec.Email, "provided-password-one", true)

		hashTwo := mustBcryptHash(t, "provided-password-two")
		secret = getSecret(t, ctx, harness.client, secret.Name)
		secret.Data["bcryptHash"] = hashTwo
		mustUpdate(t, ctx, harness.client, secret)
		awaitLocalUserSecretResourceVersion(t, ctx, harness.client, resource.Name, secret.ResourceVersion)
		assertPasswordVerification(t, ctx, harness, resource.Spec.Email, "provided-password-two", true)

		if notFound, err := harness.dexClient.UpdatePassword(ctx, &dexapi.UpdatePasswordReq{Email: resource.Spec.Email, NewUsername: "Drifted Username"}); err != nil || notFound {
			t.Fatalf("inject username drift: notFound=%t err=%v", notFound, err)
		}
		awaitRemotePassword(t, ctx, harness, resource.Spec.Email, func(observed *dexapi.Password) bool {
			return observed.GetUsername() == resource.Spec.Username && observed.GetUserId() == expectedID
		})

		if _, err := harness.dexClient.DeletePassword(ctx, resource.Spec.Email); err != nil {
			t.Fatal(err)
		}
		if alreadyExists, err := harness.dexClient.CreatePassword(ctx, &dexapi.Password{Email: resource.Spec.Email, Username: resource.Spec.Username, UserId: "drifted-user-id", Hash: hashTwo}); err != nil || alreadyExists {
			t.Fatalf("inject user ID drift: alreadyExists=%t err=%v", alreadyExists, err)
		}
		awaitRemotePassword(t, ctx, harness, resource.Spec.Email, func(observed *dexapi.Password) bool {
			return observed.GetUserId() == expectedID
		})
		assertPasswordVerification(t, ctx, harness, resource.Spec.Email, "provided-password-two", true)

		if _, err := harness.dexClient.DeletePassword(ctx, resource.Spec.Email); err != nil {
			t.Fatal(err)
		}
		awaitRemotePassword(t, ctx, harness, resource.Spec.Email, func(observed *dexapi.Password) bool {
			return observed.GetUserId() == expectedID
		})

		managed = getLocalUser(t, ctx, harness.client, resource.Name)
		mustDelete(t, ctx, harness.client, managed)
		awaitLocalUserDeletion(t, ctx, harness.client, resource.Name)
		awaitRemotePasswordAbsence(t, ctx, harness, resource.Spec.Email)
		if getSecretIfPresent(t, ctx, harness.client, secret.Name) == nil {
			t.Fatal("provided password Secret was deleted")
		}
	})

	t.Run("generated password lifecycle", func(t *testing.T) {
		resource := newGeneratedLocalUser("generated-user", "generated@example.com", "explicit-user-id", "generated-user-secret")
		mustCreate(t, ctx, harness.client, resource)
		managed := awaitReadyLocalUser(t, ctx, harness.client, resource.Name)
		if managed.Status.ResolvedUserID != resource.Spec.UserID {
			t.Fatalf("resolved explicit user ID = %q", managed.Status.ResolvedUserID)
		}
		generated := awaitSecret(t, ctx, harness.client, resource.Spec.Password.Generated.SecretName)
		password := string(generated.Data["password"])
		if len(password) != 20 || bcrypt.CompareHashAndPassword(generated.Data["bcryptHash"], []byte(password)) != nil {
			t.Fatal("generated password Secret is internally inconsistent")
		}
		if owner := metav1.GetControllerOf(generated); owner == nil || owner.UID != managed.UID {
			t.Fatalf("generated password Secret controller owner = %#v", owner)
		}
		assertRemotePassword(t, ctx, harness, resource.Spec.Email, resource.Spec.Username, resource.Spec.UserID)
		assertPasswordVerification(t, ctx, harness, resource.Spec.Email, password, true)

		time.Sleep(600 * time.Millisecond)
		managed = getLocalUser(t, ctx, harness.client, resource.Name)
		noOpSecret := awaitSecret(t, ctx, harness.client, resource.Spec.Password.Generated.SecretName)
		if string(noOpSecret.Data["password"]) != password || managed.Status.AppliedSecretResourceVersion != noOpSecret.ResourceVersion {
			t.Fatal("no-op reconciliation changed or stopped tracking generated credentials")
		}
		assertPasswordVerification(t, ctx, harness, resource.Spec.Email, password, true)

		previousGeneration := managed.Generation
		managed.Spec.Password.Generated.Length = 30
		mustUpdate(t, ctx, harness.client, managed)
		managed = awaitReadyLocalUserAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		unchanged := awaitSecret(t, ctx, harness.client, resource.Spec.Password.Generated.SecretName)
		if string(unchanged.Data["password"]) != password {
			t.Fatal("generated policy change rotated password without a nonce")
		}

		driftHash := mustBcryptHash(t, "out-of-band-password")
		if notFound, err := harness.dexClient.UpdatePassword(ctx, &dexapi.UpdatePasswordReq{Email: resource.Spec.Email, NewHash: driftHash}); err != nil || notFound {
			t.Fatalf("inject password drift: notFound=%t err=%v", notFound, err)
		}
		awaitPasswordVerification(t, ctx, harness, resource.Spec.Email, password, true)

		if _, err := harness.dexClient.DeletePassword(ctx, resource.Spec.Email); err != nil {
			t.Fatal(err)
		}
		awaitRemotePassword(t, ctx, harness, resource.Spec.Email, func(observed *dexapi.Password) bool {
			return observed.GetUserId() == resource.Spec.UserID
		})
		assertPasswordVerification(t, ctx, harness, resource.Spec.Email, password, true)

		generated = awaitSecret(t, ctx, harness.client, resource.Spec.Password.Generated.SecretName)
		manualPassword := "manually-edited-password"
		generated.Data["password"] = []byte(manualPassword)
		generated.Data["bcryptHash"] = mustBcryptHash(t, manualPassword)
		mustUpdate(t, ctx, harness.client, generated)
		awaitLocalUserCondition(t, ctx, harness.client, resource.Name, metav1.ConditionFalse, controller.ReasonConflict)
		assertPasswordVerification(t, ctx, harness, resource.Spec.Email, password, true)

		managed = getLocalUser(t, ctx, harness.client, resource.Name)
		previousGeneration = managed.Generation
		managed.Spec.Password.Generated.RotationNonce = "rotation-1"
		mustUpdate(t, ctx, harness.client, managed)
		managed = awaitReadyLocalUserAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		rotated := awaitSecret(t, ctx, harness.client, resource.Spec.Password.Generated.SecretName)
		rotatedPassword := string(rotated.Data["password"])
		if len(rotatedPassword) != 30 || rotatedPassword == manualPassword || rotatedPassword == password {
			t.Fatal("generated password rotation did not produce fresh policy-compliant material")
		}
		assertPasswordVerification(t, ctx, harness, resource.Spec.Email, rotatedPassword, true)

		oldUID := rotated.UID
		mustDelete(t, ctx, harness.client, rotated)
		awaitLocalUserCondition(t, ctx, harness.client, resource.Name, metav1.ConditionFalse, controller.ReasonConflict)
		if getSecretIfPresent(t, ctx, harness.client, resource.Spec.Password.Generated.SecretName) != nil {
			t.Fatal("lost generated password Secret was recreated without a rotation nonce")
		}
		managed = getLocalUser(t, ctx, harness.client, resource.Name)
		previousGeneration = managed.Generation
		managed.Spec.Password.Generated.RotationNonce = "rotation-2"
		mustUpdate(t, ctx, harness.client, managed)
		managed = awaitReadyLocalUserAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		recovered := awaitSecretUIDChange(t, ctx, harness.client, resource.Spec.Password.Generated.SecretName, oldUID)
		recoveredPassword := string(recovered.Data["password"])
		if len(recoveredPassword) != 30 || recoveredPassword == rotatedPassword {
			t.Fatal("nonce-authorized lost Secret recovery did not generate fresh material")
		}
		assertPasswordVerification(t, ctx, harness, resource.Spec.Email, recoveredPassword, true)

		mustDelete(t, ctx, harness.client, managed)
		awaitLocalUserDeletion(t, ctx, harness.client, resource.Name)
		awaitRemotePasswordAbsence(t, ctx, harness, resource.Spec.Email)
		awaitSecretAbsence(t, ctx, harness.client, resource.Spec.Password.Generated.SecretName)
	})

	t.Run("provided to generated password source transition", func(t *testing.T) {
		hash := mustBcryptHash(t, "source-transition-provided-password")
		provided := mustCreateOpaqueSecret(t, ctx, harness.client, "source-transition-hash", map[string][]byte{"bcryptHash": hash})
		resource := newProvidedLocalUser("source-transition-user", "source-transition@example.com", provided.Name)
		mustCreate(t, ctx, harness.client, resource)
		managed := awaitReadyLocalUser(t, ctx, harness.client, resource.Name)
		assertPasswordVerification(t, ctx, harness, resource.Spec.Email, "source-transition-provided-password", true)

		previousGeneration := managed.Generation
		managed.Spec.Password = dexv1alpha1.DexLocalUserPasswordSpec{Generated: &dexv1alpha1.GeneratedPasswordSpec{
			SecretName:    "source-transition-generated",
			Length:        20,
			CharacterSets: []dexv1alpha1.PasswordCharacterSet{dexv1alpha1.PasswordCharacterSetLetters, dexv1alpha1.PasswordCharacterSetNumbers},
		}}
		mustUpdate(t, ctx, harness.client, managed)
		managed = awaitReadyLocalUserAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		generated := awaitSecret(t, ctx, harness.client, managed.Spec.Password.Generated.SecretName)
		generatedPassword := string(generated.Data["password"])
		assertPasswordVerification(t, ctx, harness, resource.Spec.Email, generatedPassword, true)

		generated.Data["password"] = []byte("source-transition-manual-edit")
		generated.Data["bcryptHash"] = mustBcryptHash(t, "source-transition-manual-edit")
		mustUpdate(t, ctx, harness.client, generated)
		managed = awaitLocalUserCondition(t, ctx, harness.client, resource.Name, metav1.ConditionFalse, controller.ReasonConflict)
		assertPasswordVerification(t, ctx, harness, resource.Spec.Email, generatedPassword, true)

		mustDelete(t, ctx, harness.client, managed)
		awaitLocalUserDeletion(t, ctx, harness.client, resource.Name)
	})

	t.Run("adoption requires matching resolved user ID", func(t *testing.T) {
		const observedID = "existing-subject"
		hash := mustBcryptHash(t, "adopted-password")
		if alreadyExists, err := harness.dexClient.CreatePassword(ctx, &dexapi.Password{Email: "adopted@example.com", Username: "Existing", UserId: observedID, Hash: hash}); err != nil || alreadyExists {
			t.Fatalf("create existing password: alreadyExists=%t err=%v", alreadyExists, err)
		}
		secret := mustCreateOpaqueSecret(t, ctx, harness.client, "adopted-user-hash", map[string][]byte{"bcryptHash": hash})
		resource := newProvidedLocalUser("adopted-user", "adopted@example.com", secret.Name)
		mustCreate(t, ctx, harness.client, resource)
		conflicted := awaitLocalUserCondition(t, ctx, harness.client, resource.Name, metav1.ConditionFalse, controller.ReasonConflict)
		if conflicted.Status.ResolvedUserID != "" {
			t.Fatalf("conflicted resource claimed user ID %q", conflicted.Status.ResolvedUserID)
		}

		previousGeneration := conflicted.Generation
		conflicted.Spec.AdoptExisting = true
		mustUpdate(t, ctx, harness.client, conflicted)
		conflicted = awaitLocalUserConditionAfter(t, ctx, harness.client, resource.Name, previousGeneration, metav1.ConditionFalse, controller.ReasonConflict)
		if conflicted.Status.ResolvedUserID != "" {
			t.Fatalf("mismatched adoption claimed user ID %q", conflicted.Status.ResolvedUserID)
		}

		previousGeneration = conflicted.Generation
		conflicted.Spec.UserID = observedID
		mustUpdate(t, ctx, harness.client, conflicted)
		adopted := awaitReadyLocalUserAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		assertRemotePassword(t, ctx, harness, resource.Spec.Email, resource.Spec.Username, observedID)
		mustDelete(t, ctx, harness.client, adopted)
		awaitLocalUserDeletion(t, ctx, harness.client, resource.Name)
		awaitRemotePasswordAbsence(t, ctx, harness, resource.Spec.Email)
	})

	t.Run("Retain detaches generated Secret", func(t *testing.T) {
		resource := newGeneratedLocalUser("retained-user", "retained@example.com", "retained-subject", "retained-user-secret")
		resource.Spec.DeletionPolicy = dexv1alpha1.DeletionPolicyRetain
		mustCreate(t, ctx, harness.client, resource)
		managed := awaitReadyLocalUser(t, ctx, harness.client, resource.Name)
		mustDelete(t, ctx, harness.client, managed)
		awaitLocalUserDeletion(t, ctx, harness.client, resource.Name)
		retainedSecret := awaitSecret(t, ctx, harness.client, resource.Spec.Password.Generated.SecretName)
		if metav1.GetControllerOf(retainedSecret) != nil {
			t.Fatalf("retained password Secret still has a controller: %#v", retainedSecret.OwnerReferences)
		}
		if remotePassword(t, ctx, harness, resource.Spec.Email) == nil {
			t.Fatal("Retain deleted the remote password")
		}
		_, _ = harness.dexClient.DeletePassword(ctx, resource.Spec.Email)
	})
}

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

		if notFound, err := harness.dexClient.DeleteOAuth2Client(ctx, resource.Spec.ID); err != nil || notFound {
			t.Fatalf("delete provided-secret OAuth2 client out of band: notFound=%t err=%v", notFound, err)
		}
		awaitRemoteOAuth2ClientAbsence(t, ctx, harness, resource.Spec.ID)
		secret = getSecret(t, ctx, harness.client, secret.Name)
		secret.Data["clientSecret"] = []byte("provided-three")
		mustUpdate(t, ctx, harness.client, secret)
		awaitOAuth2Condition(t, ctx, harness.client, resource.Name, metav1.ConditionFalse, controller.ReasonConflict)
		if observed := remoteOAuth2Client(t, ctx, harness, resource.Spec.ID); observed != nil {
			t.Fatal("changed provided Secret recreated Dex without rotation")
		}

		managed = getOAuth2Client(t, ctx, harness.client, resource.Name)
		previousGeneration = managed.Generation
		managed.Spec.Secret.RotationNonce = "rotation-2"
		mustUpdate(t, ctx, harness.client, managed)
		managed = awaitReadyOAuth2ClientAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		assertRemoteOAuth2Client(t, ctx, harness, desiredOAuth2Client(managed, "provided-three"))

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

		generated.Data["consumer-note"] = []byte("preserve")
		mustUpdate(t, ctx, harness.client, generated)
		var settled *corev1.Secret
		eventually(t, func() (bool, error) {
			currentSecret := getSecret(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName)
			currentResource := getOAuth2Client(t, ctx, harness.client, resource.Name)
			if currentResource.Status.AppliedSecretResourceVersion != currentSecret.ResourceVersion || string(currentSecret.Data["consumer-note"]) != "preserve" {
				return false, nil
			}
			settled = currentSecret
			return true, nil
		})
		if string(settled.Data["consumer-note"]) != "preserve" {
			t.Fatal("generated Secret reconciliation deleted unrelated consumer data")
		}

		if notFound, err := harness.dexClient.DeleteOAuth2Client(ctx, resource.Spec.ID); err != nil || notFound {
			t.Fatalf("delete generated OAuth2 client out of band: notFound=%t err=%v", notFound, err)
		}
		awaitRemoteOAuth2ClientAbsence(t, ctx, harness, resource.Spec.ID)
		settled.Data["clientSecret"] = []byte("manual-edit")
		mustUpdate(t, ctx, harness.client, settled)
		awaitOAuth2Condition(t, ctx, harness.client, resource.Name, metav1.ConditionFalse, controller.ReasonConflict)
		if observed := remoteOAuth2Client(t, ctx, harness, resource.Spec.ID); observed != nil {
			t.Fatal("manual generated-Secret edit recreated Dex without rotation")
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

		if notFound, err := harness.dexClient.DeleteOAuth2Client(ctx, resource.Spec.ID); err != nil || notFound {
			t.Fatalf("delete generated OAuth2 client before Secret loss: notFound=%t err=%v", notFound, err)
		}
		awaitRemoteOAuth2ClientAbsence(t, ctx, harness, resource.Spec.ID)
		mustDelete(t, ctx, harness.client, recovered)
		awaitSecretAbsence(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName)
		awaitOAuth2Condition(t, ctx, harness.client, resource.Name, metav1.ConditionFalse, controller.ReasonConflict)
		if observed := remoteOAuth2Client(t, ctx, harness, resource.Spec.ID); observed != nil {
			t.Fatal("simultaneous Dex and generated Secret loss recreated Dex without rotation")
		}

		managed = getOAuth2Client(t, ctx, harness.client, resource.Name)
		previousGeneration = managed.Generation
		managed.Spec.Secret.RotationNonce = "generated-rotation-2"
		mustUpdate(t, ctx, harness.client, managed)
		managed = awaitReadyOAuth2ClientAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		replaced := awaitSecretUIDChange(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName, recovered.UID)
		assertRemoteOAuth2Client(t, ctx, harness, desiredOAuth2Client(managed, string(replaced.Data["clientSecret"])))

		mustDelete(t, ctx, harness.client, managed)
		awaitOAuth2ClientDeletion(t, ctx, harness.client, resource.Name)
		awaitRemoteOAuth2ClientAbsence(t, ctx, harness, resource.Spec.ID)
		awaitSecretAbsence(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName)
	})

	t.Run("generated secret custom keys", func(t *testing.T) {
		resource := newConfidentialOAuth2Client("custom-key-client")
		resource.Spec.Secret = &dexv1alpha1.DexOAuth2ClientSecretSpec{Generated: &dexv1alpha1.GeneratedOAuth2ClientSecretSpec{SecretName: "custom-key-client-secret"}}
		mustCreate(t, ctx, harness.client, resource)
		managed := awaitReadyOAuth2Client(t, ctx, harness.client, resource.Name)
		generatedValue := string(awaitSecret(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName).Data["clientSecret"])

		if notFound, err := harness.dexClient.DeleteOAuth2Client(ctx, resource.Spec.ID); err != nil || notFound {
			t.Fatalf("delete legacy-layout OAuth2 client out of band: notFound=%t err=%v", notFound, err)
		}
		awaitRemoteOAuth2ClientAbsence(t, ctx, harness, resource.Spec.ID)
		previousGeneration := managed.Generation
		managed.Spec.Secret.Generated.ClientIDKey = "OIDC_CLIENT_ID"
		managed.Spec.Secret.Generated.ClientSecretKey = "OIDC_CLIENT_SECRET"
		mustUpdate(t, ctx, harness.client, managed)
		managed = awaitReadyOAuth2ClientAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		generated := awaitSecret(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName)
		if got := string(generated.Data["OIDC_CLIENT_ID"]); got != resource.Spec.ID {
			t.Fatalf("generated client ID = %q, want %q", got, resource.Spec.ID)
		}
		if got := string(generated.Data["OIDC_CLIENT_SECRET"]); got != generatedValue {
			t.Fatal("generated Secret layout migration rotated the client secret")
		}
		if _, exists := generated.Data["clientSecret"]; exists || len(generated.Data) != 2 {
			t.Fatalf("generated Secret data keys = %v, want only custom client ID and secret keys", slices.Sorted(maps.Keys(generated.Data)))
		}
		assertRemoteOAuth2Client(t, ctx, harness, desiredOAuth2Client(managed, generatedValue))

		delete(generated.Data, "OIDC_CLIENT_SECRET")
		mustUpdate(t, ctx, harness.client, generated)
		awaitOAuth2Condition(t, ctx, harness.client, resource.Name, metav1.ConditionFalse, controller.ReasonConflict)
		observed := remoteOAuth2Client(t, ctx, harness, resource.Spec.ID)
		if observed == nil || observed.GetSecret() != generatedValue {
			t.Fatal("missing custom client-secret key mutated Dex without rotation")
		}

		managed = getOAuth2Client(t, ctx, harness.client, resource.Name)
		previousGeneration = managed.Generation
		managed.Spec.Secret.RotationNonce = "custom-key-rotation-1"
		mustUpdate(t, ctx, harness.client, managed)
		managed = awaitReadyOAuth2ClientAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		rotated := awaitSecretKeyValueChange(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName, "OIDC_CLIENT_SECRET", generatedValue)
		if got := string(awaitSecret(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName).Data["OIDC_CLIENT_ID"]); got != resource.Spec.ID {
			t.Fatalf("rotated Secret client ID = %q, want %q", got, resource.Spec.ID)
		}
		assertRemoteOAuth2Client(t, ctx, harness, desiredOAuth2Client(managed, rotated))

		generated = awaitSecret(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName)
		oldUID := generated.UID
		mustDelete(t, ctx, harness.client, generated)
		recovered := awaitSecretUIDChange(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName, oldUID)
		if string(recovered.Data["OIDC_CLIENT_ID"]) != resource.Spec.ID || string(recovered.Data["OIDC_CLIENT_SECRET"]) != rotated {
			t.Fatalf("recovered generated Secret data keys = %v", slices.Sorted(maps.Keys(recovered.Data)))
		}

		managed = getOAuth2Client(t, ctx, harness.client, resource.Name)
		mustDelete(t, ctx, harness.client, managed)
		awaitOAuth2ClientDeletion(t, ctx, harness.client, resource.Name)
		awaitRemoteOAuth2ClientAbsence(t, ctx, harness, resource.Spec.ID)
		awaitSecretAbsence(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName)
	})

	t.Run("generated custom-key promotion fails closed", func(t *testing.T) {
		resource := newConfidentialOAuth2Client("custom-key-promotion-client")
		resource.Spec.Secret = &dexv1alpha1.DexOAuth2ClientSecretSpec{Generated: &dexv1alpha1.GeneratedOAuth2ClientSecretSpec{SecretName: "custom-key-promotion-secret"}}
		mustCreate(t, ctx, harness.client, resource)
		managed := awaitReadyOAuth2Client(t, ctx, harness.client, resource.Name)
		generated := awaitSecret(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName)
		generatedValue := string(generated.Data["clientSecret"])
		generated.Data["OIDC_CLIENT_SECRET"] = []byte("previously-unmanaged")
		mustUpdate(t, ctx, harness.client, generated)
		awaitOAuth2SecretResourceVersion(t, ctx, harness.client, resource.Name, generated.ResourceVersion)

		if notFound, err := harness.dexClient.DeleteOAuth2Client(ctx, resource.Spec.ID); err != nil || notFound {
			t.Fatalf("delete OAuth2 client before custom-key promotion: notFound=%t err=%v", notFound, err)
		}
		awaitRemoteOAuth2ClientAbsence(t, ctx, harness, resource.Spec.ID)
		managed = getOAuth2Client(t, ctx, harness.client, resource.Name)
		previousGeneration := managed.Generation
		managed.Spec.Secret.Generated.ClientIDKey = "OIDC_CLIENT_ID"
		managed.Spec.Secret.Generated.ClientSecretKey = "OIDC_CLIENT_SECRET"
		mustUpdate(t, ctx, harness.client, managed)
		awaitOAuth2Condition(t, ctx, harness.client, resource.Name, metav1.ConditionFalse, controller.ReasonConflict)
		if observed := remoteOAuth2Client(t, ctx, harness, resource.Spec.ID); observed != nil {
			t.Fatal("previously unmanaged Secret key recreated Dex without rotation")
		}

		managed = getOAuth2Client(t, ctx, harness.client, resource.Name)
		previousGeneration = managed.Generation
		managed.Spec.Secret.RotationNonce = "custom-key-promotion-1"
		mustUpdate(t, ctx, harness.client, managed)
		managed = awaitReadyOAuth2ClientAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		rotated := string(awaitSecret(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName).Data["OIDC_CLIENT_SECRET"])
		if rotated == "previously-unmanaged" || rotated == generatedValue {
			t.Fatal("authorized custom-key promotion did not generate a fresh credential")
		}
		assertRemoteOAuth2Client(t, ctx, harness, desiredOAuth2Client(managed, rotated))

		mustDelete(t, ctx, harness.client, managed)
		awaitOAuth2ClientDeletion(t, ctx, harness.client, resource.Name)
		awaitRemoteOAuth2ClientAbsence(t, ctx, harness, resource.Spec.ID)
		awaitSecretAbsence(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName)
	})

	t.Run("generated secret legacy-key client ID", func(t *testing.T) {
		resource := newConfidentialOAuth2Client("legacy-key-id-client")
		resource.Spec.Secret = &dexv1alpha1.DexOAuth2ClientSecretSpec{Generated: &dexv1alpha1.GeneratedOAuth2ClientSecretSpec{SecretName: "legacy-key-id-client-secret"}}
		mustCreate(t, ctx, harness.client, resource)
		managed := awaitReadyOAuth2Client(t, ctx, harness.client, resource.Name)
		generatedValue := string(awaitSecret(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName).Data["clientSecret"])

		previousGeneration := managed.Generation
		managed.Spec.Secret.Generated.ClientIDKey = "clientSecret"
		managed.Spec.Secret.Generated.ClientSecretKey = "OIDC_CLIENT_SECRET"
		mustUpdate(t, ctx, harness.client, managed)
		managed = awaitReadyOAuth2ClientAfter(t, ctx, harness.client, resource.Name, previousGeneration)
		generated := awaitSecret(t, ctx, harness.client, resource.Spec.Secret.Generated.SecretName)
		if got := string(generated.Data["clientSecret"]); got != resource.Spec.ID {
			t.Fatalf("generated client ID = %q, want %q", got, resource.Spec.ID)
		}
		if got := string(generated.Data["OIDC_CLIENT_SECRET"]); got != generatedValue {
			t.Fatal("generated Secret layout migration rotated the client secret")
		}
		assertRemoteOAuth2Client(t, ctx, harness, desiredOAuth2Client(managed, generatedValue))

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
	return awaitReadyConnectorAfter(t, ctx, kube, name, -1)
}

func awaitReadyConnectorAfter(t *testing.T, ctx context.Context, kube client.Client, name string, generation int64) *dexv1alpha1.DexConnector {
	t.Helper()
	var result *dexv1alpha1.DexConnector
	eventually(t, func() (bool, error) {
		resource := &dexv1alpha1.DexConnector{}
		if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, resource); err != nil {
			return false, err
		}
		if resource.Generation > generation && readyConditionSet(resource.Status.Conditions, resource.Generation) {
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
	return awaitReadyOAuth2ClientAfter(t, ctx, kube, name, -1)
}

func awaitReadyOAuth2ClientAfter(t *testing.T, ctx context.Context, kube client.Client, name string, generation int64) *dexv1alpha1.DexOAuth2Client {
	t.Helper()
	var result *dexv1alpha1.DexOAuth2Client
	eventually(t, func() (bool, error) {
		resource := &dexv1alpha1.DexOAuth2Client{}
		if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, resource); err != nil {
			return false, err
		}
		if resource.Generation > generation && readyConditionSet(resource.Status.Conditions, resource.Generation) {
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
	return awaitSecretKeyValueChange(t, ctx, kube, name, "clientSecret", previous)
}

func awaitSecretKeyValueChange(t *testing.T, ctx context.Context, kube client.Client, name, dataKey, previous string) string {
	t.Helper()
	var result string
	eventually(t, func() (bool, error) {
		secret := &corev1.Secret{}
		if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, secret); err != nil {
			return false, ignoreNotFound(err)
		}
		result = string(secret.Data[dataKey])
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

func newProvidedLocalUser(name, email, secretName string) *dexv1alpha1.DexLocalUser {
	return &dexv1alpha1.DexLocalUser{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: dexv1alpha1.DexLocalUserSpec{
			Email:    email,
			Username: "Managed User",
			Password: dexv1alpha1.DexLocalUserPasswordSpec{HashSecretRef: &dexv1alpha1.SecretKeyReference{Name: secretName, Key: "bcryptHash"}},
		},
	}
}

func newGeneratedLocalUser(name, email, userID, secretName string) *dexv1alpha1.DexLocalUser {
	return &dexv1alpha1.DexLocalUser{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: dexv1alpha1.DexLocalUserSpec{
			Email:    email,
			Username: "Managed User",
			UserID:   userID,
			Password: dexv1alpha1.DexLocalUserPasswordSpec{Generated: &dexv1alpha1.GeneratedPasswordSpec{
				SecretName:    secretName,
				Length:        20,
				CharacterSets: []dexv1alpha1.PasswordCharacterSet{dexv1alpha1.PasswordCharacterSetLetters, dexv1alpha1.PasswordCharacterSetNumbers},
			}},
		},
	}
}

func mustBcryptHash(t *testing.T, password string) []byte {
	t.Helper()
	hash, err := credentials.BcryptHash(password)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func getLocalUser(t *testing.T, ctx context.Context, kube client.Client, name string) *dexv1alpha1.DexLocalUser {
	t.Helper()
	resource := &dexv1alpha1.DexLocalUser{}
	if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, resource); err != nil {
		t.Fatal(err)
	}
	return resource
}

func awaitReadyLocalUser(t *testing.T, ctx context.Context, kube client.Client, name string) *dexv1alpha1.DexLocalUser {
	t.Helper()
	return awaitReadyLocalUserAfter(t, ctx, kube, name, -1)
}

func awaitReadyLocalUserAfter(t *testing.T, ctx context.Context, kube client.Client, name string, generation int64) *dexv1alpha1.DexLocalUser {
	t.Helper()
	var result *dexv1alpha1.DexLocalUser
	eventually(t, func() (bool, error) {
		resource := &dexv1alpha1.DexLocalUser{}
		if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, resource); err != nil {
			return false, err
		}
		if resource.Generation > generation && readyConditionSet(resource.Status.Conditions, resource.Generation) {
			result = resource
			return true, nil
		}
		return false, nil
	})
	return result
}

func readyConditionSet(conditions []metav1.Condition, generation int64) bool {
	for _, expected := range []struct {
		conditionType string
		status        metav1.ConditionStatus
	}{
		{dexv1alpha1.ConditionReady, metav1.ConditionTrue},
		{dexv1alpha1.ConditionCompatible, metav1.ConditionTrue},
		{dexv1alpha1.ConditionDrifted, metav1.ConditionFalse},
	} {
		condition := meta.FindStatusCondition(conditions, expected.conditionType)
		if condition == nil || condition.ObservedGeneration != generation || condition.Status != expected.status || condition.Reason != controller.ReasonConverged {
			return false
		}
	}
	return true
}

func awaitLocalUserCondition(t *testing.T, ctx context.Context, kube client.Client, name string, status metav1.ConditionStatus, reason string) *dexv1alpha1.DexLocalUser {
	t.Helper()
	return awaitLocalUserConditionAfter(t, ctx, kube, name, -1, status, reason)
}

func awaitLocalUserConditionAfter(t *testing.T, ctx context.Context, kube client.Client, name string, generation int64, status metav1.ConditionStatus, reason string) *dexv1alpha1.DexLocalUser {
	t.Helper()
	var result *dexv1alpha1.DexLocalUser
	eventually(t, func() (bool, error) {
		resource := &dexv1alpha1.DexLocalUser{}
		if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, resource); err != nil {
			return false, err
		}
		condition := meta.FindStatusCondition(resource.Status.Conditions, dexv1alpha1.ConditionReady)
		if resource.Generation > generation && condition != nil && condition.ObservedGeneration == resource.Generation && condition.Status == status && condition.Reason == reason {
			result = resource
			return true, nil
		}
		return false, nil
	})
	return result
}

func awaitLocalUserSecretResourceVersion(t *testing.T, ctx context.Context, kube client.Client, name, resourceVersion string) {
	t.Helper()
	eventually(t, func() (bool, error) {
		resource := &dexv1alpha1.DexLocalUser{}
		if err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, resource); err != nil {
			return false, err
		}
		return resource.Status.AppliedSecretResourceVersion == resourceVersion, nil
	})
}

func awaitLocalUserDeletion(t *testing.T, ctx context.Context, kube client.Client, name string) {
	t.Helper()
	eventually(t, func() (bool, error) {
		err := kube.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, &dexv1alpha1.DexLocalUser{})
		return apierrors.IsNotFound(err), ignoreNotFound(err)
	})
}

func remotePassword(t *testing.T, ctx context.Context, harness *kubernetesHarness, email string) *dexapi.Password {
	t.Helper()
	response, err := harness.dexClient.ListPasswords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, password := range response.GetPasswords() {
		if password.GetEmail() == email {
			return password
		}
	}
	return nil
}

func assertRemotePassword(t *testing.T, ctx context.Context, harness *kubernetesHarness, email, username, userID string) {
	t.Helper()
	observed := remotePassword(t, ctx, harness, email)
	if observed == nil {
		t.Fatalf("remote password %q is absent", email)
	}
	if observed.GetUsername() != username || observed.GetUserId() != userID {
		t.Fatalf("remote password identity mismatch: username=%q userID=%q", observed.GetUsername(), observed.GetUserId())
	}
	if len(observed.GetHash()) != 0 {
		t.Fatal("ListPasswords unexpectedly exposed a hash")
	}
}

func awaitRemotePassword(t *testing.T, ctx context.Context, harness *kubernetesHarness, email string, check func(*dexapi.Password) bool) {
	t.Helper()
	eventually(t, func() (bool, error) {
		response, err := harness.dexClient.ListPasswords(ctx)
		if err != nil {
			return false, err
		}
		for _, password := range response.GetPasswords() {
			if password.GetEmail() == email {
				return check(password), nil
			}
		}
		return false, nil
	})
}

func awaitRemotePasswordAbsence(t *testing.T, ctx context.Context, harness *kubernetesHarness, email string) {
	t.Helper()
	eventually(t, func() (bool, error) {
		response, err := harness.dexClient.ListPasswords(ctx)
		if err != nil {
			return false, err
		}
		for _, password := range response.GetPasswords() {
			if password.GetEmail() == email {
				return false, nil
			}
		}
		return true, nil
	})
}

func assertPasswordVerification(t *testing.T, ctx context.Context, harness *kubernetesHarness, email, password string, want bool) {
	t.Helper()
	verified, found, err := harness.dexClient.VerifyPassword(ctx, email, password)
	if err != nil {
		t.Fatal(err)
	}
	if !found || verified != want {
		t.Fatalf("password verification = verified=%t found=%t, want verified=%t found=true", verified, found, want)
	}
}

func awaitPasswordVerification(t *testing.T, ctx context.Context, harness *kubernetesHarness, email, password string, want bool) {
	t.Helper()
	eventually(t, func() (bool, error) {
		verified, found, err := harness.dexClient.VerifyPassword(ctx, email, password)
		return found && verified == want, err
	})
}
