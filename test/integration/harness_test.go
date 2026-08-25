//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	dexv1alpha1 "github.com/araihu/dex-operator/api/v1alpha1"
	"github.com/araihu/dex-operator/internal/config"
	"github.com/araihu/dex-operator/internal/controller"
	dexclient "github.com/araihu/dex-operator/internal/dex"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	corev1 "k8s.io/api/core/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func TestHarnessCompatibility(t *testing.T) {
	harness := startDexHarness(t, memoryStorage)
	_ = startKubernetesHarness(t, harness)
	runtimeConfig := harness.clientConfig("dex.test")
	client, err := dexclient.NewClient(runtimeConfig, harness.clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	version, err := client.GetVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version.GetServer() != config.SupportedServerVersion || version.GetApi() != 4 {
		t.Fatalf("Dex version = server %q API %d", version.GetServer(), version.GetApi())
	}
	if outcome := dexclient.NewCompatibilityGate(client, config.SupportedServerVersion).Check(context.Background()); outcome.State != dexclient.Compatible {
		t.Fatalf("compatibility = %#v", outcome)
	}

	response, err := (&http.Client{Timeout: 5 * time.Second}).Get(harness.httpURL + "/dex/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("OIDC discovery status = %s", response.Status)
	}

	for _, test := range []struct {
		name       string
		serverName string
		files      dexclient.TLSFiles
	}{
		{name: "wrong CA", serverName: "dex.test", files: dexclient.TLSFiles{CA: harness.wrongCA, Cert: harness.clientTLS.Cert, Key: harness.clientTLS.Key}},
		{name: "wrong server name", serverName: "wrong.test", files: harness.clientTLS},
	} {
		t.Run(test.name, func(t *testing.T) {
			badClient, err := dexclient.NewClient(harness.clientConfig(test.serverName), test.files)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = badClient.Close() })
			if outcome := dexclient.NewCompatibilityGate(badClient, config.SupportedServerVersion).Check(context.Background()); outcome.State != dexclient.Unavailable {
				t.Fatalf("compatibility = %#v, want unavailable", outcome)
			}
		})
	}

	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := dexclient.NewClient(runtimeConfig, dexclient.TLSFiles{CA: harness.clientTLS.CA, Cert: missing + ".crt", Key: missing + ".key"}); err == nil {
		t.Fatal("NewClient() accepted missing client certificate")
	}

	t.Run("SQLite restart", func(t *testing.T) {
		sqlite := startDexHarness(t, sqliteStorage)
		client, err := dexclient.NewClient(sqlite.clientConfig("dex.test"), sqlite.clientTLS)
		if err != nil {
			t.Fatal(err)
		}
		if outcome := dexclient.NewCompatibilityGate(client, config.SupportedServerVersion).Check(context.Background()); outcome.State != dexclient.Compatible {
			t.Fatalf("pre-restart compatibility = %#v", outcome)
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		sqlite.restart(t)
		client, err = dexclient.NewClient(sqlite.clientConfig("dex.test"), sqlite.clientTLS)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		if outcome := dexclient.NewCompatibilityGate(client, config.SupportedServerVersion).Check(context.Background()); outcome.State != dexclient.Compatible {
			t.Fatalf("post-restart compatibility = %#v", outcome)
		}
	})
}

type dexStorage string

const memoryStorage dexStorage = "memory"

const sqliteStorage dexStorage = "sqlite"

const webAuthnBrowserImage = "chromedp/headless-shell@sha256:2d349b544a1ea6b5b5fd7c0fe99215ff662339c57407ee2e8c0a11af93516b04"

type dexHarness struct {
	grpcAddress string
	httpURL     string
	clientTLS   dexclient.TLSFiles
	wrongCA     string
	container   testcontainers.Container
	network     *testcontainers.DockerNetwork
}

func (harness *dexHarness) clientConfig(serverName string) config.Config {
	return config.Config{
		GRPCAddress:           harness.grpcAddress,
		GRPCServerName:        serverName,
		ReconcileInterval:     time.Minute,
		ExpectedServerVersion: config.SupportedServerVersion,
	}
}

func (harness *dexHarness) restart(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := harness.container.Stop(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := harness.container.Start(ctx); err != nil {
		t.Fatal(err)
	}
	host, err := harness.container.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	grpcPort, err := harness.container.MappedPort(ctx, "5557/tcp")
	if err != nil {
		t.Fatal(err)
	}
	httpPort, err := harness.container.MappedPort(ctx, "5556/tcp")
	if err != nil {
		t.Fatal(err)
	}
	harness.grpcAddress = net.JoinHostPort(host, grpcPort.Port())
	harness.httpURL = "http://" + net.JoinHostPort(host, httpPort.Port())
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, err := client.Get(harness.httpURL + "/dex/.well-known/openid-configuration")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			state, stateErr := harness.container.State(context.Background())
			if stateErr != nil {
				t.Fatalf("Dex HTTP endpoint did not become ready after restart; inspect state: %v", stateErr)
			}
			t.Fatalf("Dex HTTP endpoint did not become ready after restart; running=%t exitCode=%d error=%q", state.Running, state.ExitCode, state.Error)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func startDexHarness(t *testing.T, storage dexStorage) *dexHarness {
	t.Helper()
	ensureDockerHost(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tlsFiles := writeHarnessTLS(t)
	configPath := filepath.Join(t.TempDir(), "dex.yaml")
	if err := os.WriteFile(configPath, []byte(dexConfiguration(storage)), 0o600); err != nil {
		t.Fatal(err)
	}

	dexNetwork, err := tcnetwork.New(ctx)
	testcontainers.CleanupNetwork(t, dexNetwork)
	if err != nil {
		t.Fatal(err)
	}
	options := []testcontainers.ContainerCustomizer{
		testcontainers.WithEnv(map[string]string{
			"DEX_API_CONNECTORS_CRUD":          "true",
			"DEX_API_SESSIONS_IDENTITIES_CRUD": "true",
		}),
		testcontainers.WithExposedPorts("5556/tcp", "5557/tcp"),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{HostFilePath: configPath, ContainerFilePath: "/etc/dex/test.yaml", FileMode: 0o444},
			testcontainers.ContainerFile{HostFilePath: tlsFiles.serverCert, ContainerFilePath: "/etc/dex/tls.crt", FileMode: 0o444},
			testcontainers.ContainerFile{HostFilePath: tlsFiles.serverKey, ContainerFilePath: "/etc/dex/tls.key", FileMode: 0o444},
			testcontainers.ContainerFile{HostFilePath: tlsFiles.clientTLS.CA, ContainerFilePath: "/etc/dex/client-ca.crt", FileMode: 0o444},
		),
		testcontainers.WithCmd("dex", "serve", "/etc/dex/test.yaml"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5557/tcp").WithStartupTimeout(30 * time.Second)),
		tcnetwork.WithNetwork([]string{"dex"}, dexNetwork),
	}
	volumeName := ""
	if storage == sqliteStorage {
		volumeName = fmt.Sprintf("dex-operator-test-%d", time.Now().UnixNano())
		options = append(options, testcontainers.WithMounts(testcontainers.VolumeMount(volumeName, "/var/dex")))
	}

	container, err := testcontainers.Run(ctx, "dex-operator-test-dex:ab64ed778070", options...)
	cleanupOptions := []testcontainers.TerminateOption{}
	if volumeName != "" {
		cleanupOptions = append(cleanupOptions, testcontainers.RemoveVolumes(volumeName))
	}
	testcontainers.CleanupContainer(t, container, cleanupOptions...)
	if err != nil {
		t.Fatal(err)
	}
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	grpcPort, err := container.MappedPort(ctx, "5557/tcp")
	if err != nil {
		t.Fatal(err)
	}
	httpPort, err := container.MappedPort(ctx, "5556/tcp")
	if err != nil {
		t.Fatal(err)
	}
	return &dexHarness{
		grpcAddress: net.JoinHostPort(host, grpcPort.Port()),
		httpURL:     "http://" + net.JoinHostPort(host, httpPort.Port()),
		clientTLS:   tlsFiles.clientTLS,
		wrongCA:     tlsFiles.wrongCA,
		container:   container,
		network:     dexNetwork,
	}
}

func ensureDockerHost(t *testing.T) {
	t.Helper()
	if os.Getenv("DOCKER_HOST") != "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("resolve Docker context: %v: %s", err, strings.TrimSpace(string(output)))
	}
	host := strings.TrimSpace(string(output))
	if host == "" {
		t.Fatal("Docker context returned an empty endpoint")
	}
	t.Setenv("DOCKER_HOST", host)
}

func dexConfiguration(storage dexStorage) string {
	storageConfig := "  type: memory\n"
	if storage == sqliteStorage {
		storageConfig = "  type: sqlite3\n  config:\n    file: /var/dex/dex.db\n"
	}
	return "issuer: http://dex:5556/dex\n" +
		"storage:\n" + storageConfig +
		"web:\n  http: 0.0.0.0:5556\n" +
		"grpc:\n  addr: 0.0.0.0:5557\n  tlsCert: /etc/dex/tls.crt\n  tlsKey: /etc/dex/tls.key\n  tlsClientCA: /etc/dex/client-ca.crt\n" +
		"enablePasswordDB: true\n" +
		"oauth2:\n  skipApprovalScreen: true\n" +
		"staticClients:\n- id: integration-client\n  secret: integration-secret\n  name: Integration Client\n  redirectURIs:\n  - http://127.0.0.1/callback\n"
}

type harnessTLSFiles struct {
	clientTLS  dexclient.TLSFiles
	serverCert string
	serverKey  string
	wrongCA    string
}

func writeHarnessTLS(t *testing.T) harnessTLSFiles {
	t.Helper()
	directory := t.TempDir()
	caCertificate, caKey, caPEM := newCertificateAuthority(t, "Dex test CA")
	serverCert, serverKey := issueCertificate(t, caCertificate, caKey, "dex.test", true)
	clientCert, clientKey := issueCertificate(t, caCertificate, caKey, "dex-operator", false)
	_, _, wrongCAPEM := newCertificateAuthority(t, "Wrong test CA")
	return harnessTLSFiles{
		clientTLS: dexclient.TLSFiles{
			CA:   writeFile(t, directory, "ca.crt", caPEM),
			Cert: writeFile(t, directory, "tls.crt", clientCert),
			Key:  writeFile(t, directory, "tls.key", clientKey),
		},
		serverCert: writeFile(t, directory, "server.crt", serverCert),
		serverKey:  writeFile(t, directory, "server.key", serverKey),
		wrongCA:    writeFile(t, directory, "wrong-ca.crt", wrongCAPEM),
	}
}

func newCertificateAuthority(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func issueCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, commonName string, server bool) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"dex", "dex.test", "localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

func writeFile(t *testing.T, directory, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type kubernetesHarness struct {
	client    client.Client
	dexClient *dexclient.Client
}

func startKubernetesHarness(t *testing.T, dexHarness *dexHarness) *kubernetesHarness {
	t.Helper()
	repository := repositoryRoot(t)
	assets := envtestAssets(t, repository)
	testEnvironment := &envtest.Environment{
		BinaryAssetsDirectory: assets,
		CRDDirectoryPaths:     []string{filepath.Join(repository, "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	restConfig, err := testEnvironment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := testEnvironment.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	})

	scheme := k8sruntime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := dexv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	manager, err := ctrl.NewManager(restConfig, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.RegisterSecretIndexes(context.Background(), manager.GetFieldIndexer()); err != nil {
		t.Fatal(err)
	}
	runtimeConfig := dexHarness.clientConfig("dex.test")
	runtimeConfig.ReconcileInterval = 200 * time.Millisecond
	dexAPI, err := dexclient.NewClient(runtimeConfig, dexHarness.clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dexAPI.Close() })
	compatibilityGate := dexclient.NewCompatibilityGate(dexAPI, config.SupportedServerVersion)
	for name, setup := range map[string]func() error{
		"local user": func() error {
			return (&controller.DexLocalUserReconciler{
				Client:            manager.GetClient(),
				Scheme:            scheme,
				Dex:               dexAPI,
				CompatibilityGate: compatibilityGate,
				ReconcileInterval: runtimeConfig.ReconcileInterval,
			}).SetupWithManager(manager)
		},
		"OAuth2 client": func() error {
			return (&controller.DexOAuth2ClientReconciler{
				Client:            manager.GetClient(),
				Scheme:            scheme,
				Dex:               dexAPI,
				CompatibilityGate: compatibilityGate,
				ReconcileInterval: runtimeConfig.ReconcileInterval,
			}).SetupWithManager(manager)
		},
		"connector": func() error {
			return (&controller.DexConnectorReconciler{
				Client:            manager.GetClient(),
				Scheme:            scheme,
				Dex:               dexAPI,
				CompatibilityGate: compatibilityGate,
				ReconcileInterval: runtimeConfig.ReconcileInterval,
			}).SetupWithManager(manager)
		},
	} {
		if err := setup(); err != nil {
			t.Fatalf("setup %s controller: %v", name, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- manager.Start(ctx) }()
	if !manager.GetCache().WaitForCacheSync(ctx) {
		cancel()
		t.Fatal("controller manager cache failed to sync")
	}
	t.Cleanup(func() {
		cancel()
		if err := <-errCh; err != nil {
			t.Errorf("stop controller manager: %v", err)
		}
	})
	return &kubernetesHarness{client: manager.GetClient(), dexClient: dexAPI}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("locate harness source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func envtestAssets(t *testing.T, repository string) string {
	t.Helper()
	if assets := os.Getenv("KUBEBUILDER_ASSETS"); assets != "" {
		return assets
	}
	cache := filepath.Join(repository, ".cache", "envtest")
	command := exec.Command("go", "tool", "setup-envtest", "--bin-dir", cache, "use", "1.36.x", "-p", "path")
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("resolve envtest assets: %v: %s", err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output))
}
