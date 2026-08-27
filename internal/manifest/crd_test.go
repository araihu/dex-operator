package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	extensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

func TestCRDContract(t *testing.T) {
	tests := []struct {
		file      string
		kind      string
		required  []string
		immutable []string
	}{
		{
			file:      "dex.araihu.com_dexlocalusers.yaml",
			kind:      "DexLocalUser",
			required:  []string{"email", "username", "password"},
			immutable: []string{"email", "userID"},
		},
		{
			file:      "dex.araihu.com_dexoauth2clients.yaml",
			kind:      "DexOAuth2Client",
			required:  []string{"id", "public", "name"},
			immutable: []string{"id", "public"},
		},
		{
			file:      "dex.araihu.com_dexconnectors.yaml",
			kind:      "DexConnector",
			required:  []string{"id", "type", "name", "configSecretRef"},
			immutable: []string{"id", "type"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			crd := loadCRD(t, tt.file)
			if crd.Spec.Scope != extensionsv1.NamespaceScoped {
				t.Fatalf("scope = %q, want %q", crd.Spec.Scope, extensionsv1.NamespaceScoped)
			}
			if len(crd.Spec.Versions) != 1 || crd.Spec.Versions[0].Name != "v1alpha1" {
				t.Fatalf("versions = %#v, want only v1alpha1", crd.Spec.Versions)
			}
			version := crd.Spec.Versions[0]
			if version.Subresources == nil || version.Subresources.Status == nil {
				t.Fatal("status subresource is not enabled")
			}
			root := version.Schema.OpenAPIV3Schema
			spec := property(t, root, "spec")
			status := property(t, root, "status")
			for _, name := range tt.required {
				if !slices.Contains(spec.Required, name) {
					t.Errorf("spec.%s is not required", name)
				}
			}
			for _, name := range tt.immutable {
				field := property(t, spec, name)
				if !hasValidation(field, "oldSelf") && !hasValidation(spec, "oldSelf."+name) {
					t.Errorf("spec.%s has no immutability validation", name)
				}
			}
			assertCommonSpec(t, spec)
			assertNoSensitiveStatusNames(t, status, "status")
		})
	}

	t.Run("DexLocalUser password and MFA", func(t *testing.T) {
		crd := loadCRD(t, "dex.araihu.com_dexlocalusers.yaml")
		spec := property(t, crd.Spec.Versions[0].Schema.OpenAPIV3Schema, "spec")
		if !hasValidation(spec, "has(self.userID) && self.userID == oldSelf.userID") {
			t.Fatal("userID immutability does not prohibit removing a previously specified value")
		}
		password := property(t, spec, "password")
		if !hasValidation(password, "has(self.hashSecretRef) != has(self.generated)") {
			t.Fatal("password does not require exactly one source")
		}
		generated := property(t, password, "generated")
		length := property(t, generated, "length")
		if length.Minimum == nil || *length.Minimum != 16 || length.Maximum == nil || *length.Maximum != 128 {
			t.Fatalf("generated length bounds = %v..%v, want 16..128", length.Minimum, length.Maximum)
		}
		sets := property(t, generated, "characterSets")
		if sets.MinItems == nil || *sets.MinItems != 1 || sets.XListType == nil || *sets.XListType != "set" {
			t.Fatalf("characterSets must be a non-empty set: %#v", sets)
		}
		if sets.Items == nil || sets.Items.Schema == nil {
			t.Fatal("characterSets has no item schema")
		}
		wantEnums := []string{"letters", "numbers", "symbols"}
		for _, want := range wantEnums {
			if !enumContains(sets.Items.Schema.Enum, want) {
				t.Errorf("characterSets enum lacks %q", want)
			}
		}
		credentialIDs := property(t, property(t, spec, "mfa"), "removeWebAuthnCredentialIDs")
		if credentialIDs.Items == nil || credentialIDs.Items.Schema == nil {
			t.Fatal("removeWebAuthnCredentialIDs has no item schema")
		}
		if credentialIDs.Items.Schema.Pattern != "^[A-Za-z0-9_-]+$" {
			t.Fatalf("WebAuthn credential ID pattern = %q", credentialIDs.Items.Schema.Pattern)
		}
	})

	t.Run("DexOAuth2Client secret modes", func(t *testing.T) {
		crd := loadCRD(t, "dex.araihu.com_dexoauth2clients.yaml")
		spec := property(t, crd.Spec.Versions[0].Schema.OpenAPIV3Schema, "spec")
		postLogoutRedirectURIs := property(t, spec, "postLogoutRedirectURIs")
		if postLogoutRedirectURIs.XListType == nil || *postLogoutRedirectURIs.XListType != "set" {
			t.Fatalf("postLogoutRedirectURIs list type = %v, want set", postLogoutRedirectURIs.XListType)
		}
		if !hasValidation(spec, "self.public") || !hasValidation(spec, "has(self.secret)") {
			t.Fatal("public/confidential secret validation is absent")
		}
		secret := property(t, spec, "secret")
		if !hasValidation(secret, "has(self.providedSecretRef) != has(self.generated)") {
			t.Fatal("confidential secret does not require exactly one source")
		}
		generated := property(t, secret, "generated")
		clientIDKey := property(t, generated, "clientIDKey")
		clientSecretKey := property(t, generated, "clientSecretKey")
		for name, field := range map[string]*extensionsv1.JSONSchemaProps{
			"clientIDKey":     clientIDKey,
			"clientSecretKey": clientSecretKey,
		} {
			if field.Pattern != "^[-._a-zA-Z0-9]+$" || field.MaxLength == nil || *field.MaxLength != 253 {
				t.Errorf("%s is not a valid Kubernetes Secret data key: %#v", name, field)
			}
		}
		if clientSecretKey.Default == nil || string(clientSecretKey.Default.Raw) != `"clientSecret"` {
			t.Errorf("clientSecretKey default = %v, want clientSecret", clientSecretKey.Default)
		}
		if !hasValidation(generated, "self.clientIDKey != self.clientSecretKey") {
			t.Fatal("generated Secret permits client ID and client secret to use the same key")
		}
		labels := property(t, generated, "labels")
		if labels.Type != "object" || labels.AdditionalProperties == nil || labels.AdditionalProperties.Schema == nil || labels.AdditionalProperties.Schema.Type != "string" {
			t.Fatalf("generated Secret labels schema = %#v, want string map", labels)
		}
		for _, forbidden := range []string{"annotations", "ownerReferences", "finalizers", "data"} {
			if _, exists := generated.Properties[forbidden]; exists {
				t.Errorf("generated Secret exposes forbidden metadata/data field %q", forbidden)
			}
		}
	})
}

func loadCRD(t *testing.T, name string) *extensionsv1.CustomResourceDefinition {
	t.Helper()
	path := filepath.Join("..", "..", "config", "crd", "bases", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var crd extensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(data, &crd); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return &crd
}

func property(t *testing.T, schema *extensionsv1.JSONSchemaProps, names ...string) *extensionsv1.JSONSchemaProps {
	t.Helper()
	current := schema
	for _, name := range names {
		next, ok := current.Properties[name]
		if !ok {
			t.Fatalf("schema property %s is absent", strings.Join(names, "."))
		}
		current = &next
	}
	return current
}

func hasValidation(schema *extensionsv1.JSONSchemaProps, fragment string) bool {
	return slices.ContainsFunc(schema.XValidations, func(rule extensionsv1.ValidationRule) bool {
		return strings.Contains(rule.Rule, fragment)
	})
}

func enumContains(values []extensionsv1.JSON, want string) bool {
	quoted := fmt.Sprintf("%q", want)
	return slices.ContainsFunc(values, func(value extensionsv1.JSON) bool {
		return string(value.Raw) == quoted
	})
}

func assertCommonSpec(t *testing.T, spec *extensionsv1.JSONSchemaProps) {
	t.Helper()
	adopt := property(t, spec, "adoptExisting")
	if adopt.Default == nil || string(adopt.Default.Raw) != "false" {
		t.Errorf("adoptExisting default = %v, want false", adopt.Default)
	}
	policy := property(t, spec, "deletionPolicy")
	if policy.Default == nil || string(policy.Default.Raw) != `"Delete"` {
		t.Errorf("deletionPolicy default = %v, want Delete", policy.Default)
	}
	for _, want := range []string{"Delete", "Retain"} {
		if !enumContains(policy.Enum, want) {
			t.Errorf("deletionPolicy enum lacks %q", want)
		}
	}
}

func assertNoSensitiveStatusNames(t *testing.T, schema *extensionsv1.JSONSchemaProps, path string) {
	t.Helper()
	for name, child := range schema.Properties {
		lower := strings.ToLower(name)
		if lower != "appliedsecretresourceversion" {
			for _, forbidden := range []string{"password", "hash", "secret", "config", "certificate", "key"} {
				if strings.Contains(lower, forbidden) {
					t.Errorf("%s.%s contains forbidden status name %q", path, name, forbidden)
				}
			}
		}
		assertNoSensitiveStatusNames(t, &child, path+"."+name)
	}
	if schema.Items != nil && schema.Items.Schema != nil {
		assertNoSensitiveStatusNames(t, schema.Items.Schema, path+"[]")
	}
}
