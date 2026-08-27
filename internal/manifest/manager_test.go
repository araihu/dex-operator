package manifest

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

func TestManagerContract(t *testing.T) {
	managerPath := filepath.Join("..", "..", "config", "manager", "manager.yaml")
	contents, err := os.ReadFile(managerPath)
	if err != nil {
		t.Fatal(err)
	}
	var deployment appsv1.Deployment
	for _, document := range strings.Split(string(contents), "---") {
		if strings.Contains(document, "kind: Deployment") {
			if err := yaml.Unmarshal([]byte(document), &deployment); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(deployment.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("manager containers = %d", len(deployment.Spec.Template.Spec.Containers))
	}
	pod := deployment.Spec.Template.Spec
	container := pod.Containers[0]
	if pod.SecurityContext == nil || pod.SecurityContext.RunAsNonRoot == nil || !*pod.SecurityContext.RunAsNonRoot {
		t.Fatal("manager Pod must run as non-root")
	}
	if container.SecurityContext == nil || container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem ||
		container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation {
		t.Fatalf("manager security context = %#v", container.SecurityContext)
	}
	if got := container.SecurityContext.Capabilities.Drop; !reflect.DeepEqual(got, []corev1.Capability{"ALL"}) {
		t.Fatalf("dropped capabilities = %#v", got)
	}
	if container.Image != "dex-operator:local" {
		t.Fatalf("manager image = %q", container.Image)
	}
	if container.LivenessProbe == nil || container.ReadinessProbe == nil {
		t.Fatal("manager liveness/readiness probes are required")
	}
	if len(container.VolumeMounts) != 1 || container.VolumeMounts[0].Name != "dex-grpc-tls" || container.VolumeMounts[0].MountPath != "/var/run/dex-operator/tls" || !container.VolumeMounts[0].ReadOnly {
		t.Fatalf("manager TLS mount = %#v", container.VolumeMounts)
	}
	if len(pod.Volumes) != 1 || pod.Volumes[0].Name != "dex-grpc-tls" || pod.Volumes[0].Secret == nil || pod.Volumes[0].Secret.SecretName != "dex-operator-grpc-client-tls" {
		t.Fatalf("manager TLS volume = %#v", pod.Volumes)
	}
	wantEnvironment := map[string]string{
		"DEX_EXPECTED_SERVER_VERSION": "v2.46.0-20260806171424-ab64ed77+araihu.password-profile.v1",
		"DEX_GRPC_ADDRESS":            "dex.example.invalid:5557",
		"DEX_GRPC_INSECURE":           "false",
		"DEX_GRPC_SERVER_NAME":        "dex.example.invalid",
		"DEX_RECONCILE_INTERVAL":      "5m",
	}
	gotEnvironment := make(map[string]string, len(container.Env))
	for _, variable := range container.Env {
		if variable.ValueFrom != nil {
			t.Fatalf("manager environment %s uses an undeclared source", variable.Name)
		}
		gotEnvironment[variable.Name] = variable.Value
	}
	if !reflect.DeepEqual(gotEnvironment, wantEnvironment) {
		t.Fatalf("manager environment = %#v", gotEnvironment)
	}

	rolePath := filepath.Join("..", "..", "config", "rbac", "role.yaml")
	roleContents, err := os.ReadFile(rolePath)
	if err != nil {
		t.Fatal(err)
	}
	var role rbacv1.ClusterRole
	if err := yaml.Unmarshal(roleContents, &role); err != nil {
		t.Fatal(err)
	}
	var secretVerbs []string
	for _, rule := range role.Rules {
		if len(rule.APIGroups) == 1 && rule.APIGroups[0] == "" && reflect.DeepEqual(rule.Resources, []string{"secrets"}) {
			secretVerbs = append([]string(nil), rule.Verbs...)
			sort.Strings(secretVerbs)
		}
	}
	wantVerbs := []string{"create", "delete", "get", "list", "patch", "update", "watch"}
	if !reflect.DeepEqual(secretVerbs, wantVerbs) {
		t.Fatalf("cluster-wide Secret verbs = %#v", secretVerbs)
	}
}

func TestPackagingContainsNoInlineSecrets(t *testing.T) {
	for _, name := range []string{
		"dex_v1alpha1_dexconnector.yaml",
		"dex_v1alpha1_dexlocaluser.yaml",
		"dex_v1alpha1_dexoauth2client.yaml",
	} {
		contents, err := os.ReadFile(filepath.Join("..", "..", "config", "samples", name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(contents)
		for _, forbidden := range []string{"kind: Secret", "\ndata:", "\nstringData:"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s contains %q", name, forbidden)
			}
		}
	}

	dockerfile, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"FROM gcr.io/distroless/static:nonroot", "USER 65532:65532", "GOWORK=off go build -trimpath"} {
		if !strings.Contains(string(dockerfile), required) {
			t.Errorf("Dockerfile lacks %q", required)
		}
	}
}
