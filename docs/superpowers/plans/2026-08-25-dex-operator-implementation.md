# Dex Operator Implementation Plan

> **For implementation:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` and execute this plan task-by-task only after explicit plan approval.

**Goal:** Create `/Users/guilhermecastro/repos/araihu/dex-operator` as a small Go Kubernetes operator that declaratively manages local users, OAuth2 clients, and connectors through the supported Dex gRPC API, with real-Dex tests and no PostgreSQL ownership.

**Architecture:** One cluster-wide controller-manager targets one externally deployed Dex instance. Three namespaced `dex.araihu.com/v1alpha1` CRDs have concrete reconcilers that share a typed runtime configuration, an mTLS Dex client, a compatibility gate, credential helpers, and small status/finalizer helpers. Helm/GitOps remains responsible for Dex, PostgreSQL/CNPG, certificates, networking, and deployment.

**Tech Stack:** Go module `github.com/araihu/dex-operator`; Go `1.26.0` with toolchain `go1.26.5`; Kubebuilder `v4.15.0`; controller-runtime `v0.24.1`; Kubernetes libraries `v0.36.0`; Dex API `v2.4.1-0.20260806151424-ab64ed778070`; `caarlos0/env/v11` `v11.4.1`; `envdoc` `v1.12.0`; `testcontainers-go` `v0.44.0`; `chromedp` `v0.16.0`; `gozxing` `v0.1.1` for test-only QR decoding; `x/crypto` `v0.55.0`; standard-library `testing`.

**Approved spec:** `docs/superpowers/specs/2026-08-25-dex-operator-design.md`.

## Global constraints

- Do not create the local repository until this plan is explicitly approved.
- Initialize exactly `/Users/guilhermecastro/repos/araihu/dex-operator`; do not substitute a worktree or another path for the first repository.
- Configure local Git identity as `Guilherme de Castro <guilherme.castro@totvs.com.br>`, matching current AraiHu repositories, and verify it before the first commit.
- Do not add a remote, create `github.com/araihu/dex-operator`, push, publish an image, create a release, deploy, or edit `/Users/guilhermecastro/repos/home-lab` without separate authorization.
- Treat `/Users/guilhermecastro/repos/home-lab` only as read-only handoff context.
- Never import a PostgreSQL driver, CloudNativePG (CNPG) API, Dex storage package, or Dex Kubernetes-storage CRD. Tests must not seed or inspect Dex tables.
- Use only Dex gRPC and OIDC/login interfaces for Dex state.
- Pin Dex source SHA `ab64ed778070e983cbb10cfc07ea4bb397d14312`, API module `v2.4.1-0.20260806151424-ab64ed778070`, numeric API `4`, and server version `v2.46.0-20260806171424-ab64ed77` as one reviewed tuple.
- Test Dex images are built locally from the pinned SHA with that exact `VERSION`; no test target pushes them.
- Production gRPC is mTLS. Plaintext is accepted only when every resolved target address is loopback and `DEX_GRPC_INSECURE=true` is explicit.
- Secret, connector JSON, password hash/plaintext, OAuth secret, TLS key/certificate, and MFA material must never be placed in status, events, metrics labels, traces, logs, or formatted errors.
- Use `GOWORK=off` for Go dependency, generation, and verification commands.
- Use standard-library tests. Do not keep the generated Ginkgo/Gomega or Kind e2e scaffold.
- Each behavioral task follows RED, GREEN, focused verification, then one local commit. Local commits do not authorize any remote lifecycle action.

## File map

### Project and generated Kubernetes surface

- `go.mod`, `go.sum`: pinned runtime and Go-tool dependencies.
- `PROJECT`: Kubebuilder `go/v4`, domain `araihu.com`, group `dex`, version `v1alpha1`, and the three namespaced resources.
- `Makefile`: local build, generation, fast tests, envtest, real-Dex integration, race, and aggregate verification only; no push/deploy target.
- `Dockerfile`: non-root controller-manager image build; local build only.
- `api/v1alpha1/groupversion_info.go`: `dex.araihu.com/v1alpha1` registration.
- `api/v1alpha1/common_types.go`: common deletion policy, Secret-key reference, and condition names.
- `api/v1alpha1/dexlocaluser_types.go`: local-user desired state and non-secret status.
- `api/v1alpha1/dexoauth2client_types.go`: client desired state and non-secret status.
- `api/v1alpha1/dexconnector_types.go`: connector desired state and non-secret status.
- `api/v1alpha1/zz_generated.deepcopy.go`: generated deep-copy methods.
- `config/crd/bases/*.yaml`: generated structural CRDs and CEL validation.
- `config/rbac/role.yaml`: generated cluster role for the three CRDs, status/finalizers, and Secrets.
- `config/manager/manager.yaml`: generic manager deployment with the fixed TLS mount contract; no real Secret or image registry.
- `config/default/kustomization.yaml`: generic install composition.
- `config/samples/*.yaml`: secret-free examples.

### Runtime packages

- `cmd/main.go`: parse configuration, construct manager/Dex gate, wire reconcilers and probes.
- `internal/config/config.go`: typed environment contract and generated documentation directive.
- `internal/config/config_test.go`: validation, loopback, defaults, and generated-doc contract tests.
- `internal/dex/client.go`: concrete gRPC connection, sanitized operation errors, CRUD calls, and MFA calls.
- `internal/dex/compatibility.go`: exact version/API/feature-flag gate and readiness checker.
- `internal/dex/normalize.go`: list normalization, client comparison, and semantic connector JSON comparison.
- `internal/dex/*_test.go`: deterministic client-side tests only; no mock Dex service.
- `internal/credentials/generate.go`: UUIDv5, unbiased password/client-secret generation, bcrypt cost 12.
- `internal/credentials/generate_test.go`: deterministic invariants and statistical boundary checks without testing randomness distribution.
- `internal/controller/common.go`: finalizer, status conditions, ownership preclaim, Secret loading/indexing, and sanitized result helpers.
- `internal/controller/dexconnector_controller.go`: connector reconciliation.
- `internal/controller/dexoauth2client_controller.go`: OAuth2-client reconciliation.
- `internal/controller/dexlocaluser_controller.go`: local-user/password reconciliation.
- `internal/controller/mfa.go`: local-user MFA inventory/reset/removal.
- `internal/controller/common_test.go`, `internal/controller/mfa_test.go`: deterministic local helpers only; no fake Dex service.

### Test harness, generation, and documentation

- `test/integration/harness_test.go`: pinned Dex container, memory/SQLite modes, mTLS certificates, OIDC browser helpers, and manager startup.
- `test/integration/resources_test.go`: end-to-end CR scenarios for all three resources.
- `test/integration/mfa_test.go`: real local-login TOTP/WebAuthn enrollment, inventory, removal, and reset.
- `hack/update-codegen.sh`: controller-gen deep-copy/CRD/RBAC generation and envdoc generation.
- `hack/verify-generated.sh`: generate into temporary locations and compare without mutating tracked output.
- `hack/build-test-dex.sh`: local-only Docker build from the exact Dex Git SHA and version.
- `docs/configuration.md`: envdoc-generated runtime variables.
- `docs/compatibility.md`: exact Dex tuple and upgrade procedure.
- `docs/security.md`: trust boundary, RBAC, mTLS, Secret handling, and emergency finalizer removal.
- `docs/backup-recovery.md`: Git/etcd/CNPG state planes and restore order.
- `docs/homelab-handoff.md`: read-only integration handoff with no live names, credentials, or edits.
- `docs/superpowers/specs/2026-08-25-dex-operator-design.md`: approved design copied unchanged except approval status.
- `docs/superpowers/plans/2026-08-25-dex-operator-implementation.md`: this approved plan.

## Task 1: Initialize the exact local repository and trim the scaffold

**Files:**
- Create: all Kubebuilder base files listed in the file map.
- Delete from generated scaffold: `.devcontainer/**`, `.github/workflows/**`, generated `AGENTS.md`, `test/e2e/**`, `test/utils/**`, Ginkgo controller suite/tests, push/deploy/buildx Make targets.
- Create: approved spec and plan under `docs/superpowers/**`.

**Interfaces:**
- Consumes: empty exact path, Kubebuilder `v4.15.0`, neighboring AraiHu Git identity.
- Produces: clean `main` branch, no remote, compiling Go `1.26.0` module with toolchain `go1.26.5`.

- [ ] Confirm the target remains absent and neighboring repositories still use the approved identity:

```bash
test ! -e /Users/guilhermecastro/repos/araihu/dex-operator
git -C /Users/guilhermecastro/repos/araihu/xisnove log -1 --format='%an <%ae>'
git -C /Users/guilhermecastro/repos/araihu/margo log -1 --format='%an <%ae>'
```

Expected: both identities are `Guilherme de Castro <guilherme.castro@totvs.com.br>`.

- [ ] Create the directory and Git repository, then freeze local identity without adding a remote:

```bash
mkdir /Users/guilhermecastro/repos/araihu/dex-operator
cd /Users/guilhermecastro/repos/araihu/dex-operator
git init -b main
git config user.name 'Guilherme de Castro'
git config user.email 'guilherme.castro@totvs.com.br'
git var GIT_AUTHOR_IDENT
test -z "$(git remote)"
```

- [ ] Generate the current Kubebuilder layout and three APIs:

```bash
GOWORK=off go run sigs.k8s.io/kubebuilder/v4@v4.15.0 init --domain araihu.com --repo github.com/araihu/dex-operator --plugins go/v4 --project-name dex-operator
for kind in DexLocalUser DexOAuth2Client DexConnector; do
  GOWORK=off go run sigs.k8s.io/kubebuilder/v4@v4.15.0 create api --group dex --version v1alpha1 --kind "$kind" --resource --controller --make=false
done
```

- [ ] Patch out the unused generated surface named above. Replace the generated Makefile with only `generate`, `verify-generated`, `test`, `envtest`, `test-integration`, `race`, `build`, and `verify`. All Go commands set `GOWORK=off`; no target pushes, deploys, installs, or mutates a cluster.
- [ ] Pin the Go version, toolchain, and direct dependencies:

```bash
GOWORK=off go mod edit -go=1.26.0 -toolchain=go1.26.5
GOWORK=off go get github.com/dexidp/dex/api/v2@v2.4.1-0.20260806151424-ab64ed778070
GOWORK=off go get github.com/caarlos0/env/v11@v11.4.1
GOWORK=off go get github.com/testcontainers/testcontainers-go@v0.44.0
GOWORK=off go get github.com/chromedp/chromedp@v0.16.0
GOWORK=off go get github.com/makiuchi-d/gozxing@v0.1.1
GOWORK=off go get golang.org/x/crypto@v0.55.0
GOWORK=off go get k8s.io/api@v0.36.0 k8s.io/apimachinery@v0.36.0 k8s.io/client-go@v0.36.0 sigs.k8s.io/controller-runtime@v0.24.1
GOWORK=off go get -tool github.com/g4s8/envdoc@v1.12.0
GOWORK=off go get -tool sigs.k8s.io/controller-tools/cmd/controller-gen@v0.21.0
GOWORK=off go get -tool sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.24.1
GOWORK=off go mod tidy
```

- [ ] Copy the approved spec and approved plan into the new repository with an `apply_patch` edit, not a shell copy shortcut.
- [ ] Verify the scaffold compiles and contains no forbidden dependency:

```bash
GOWORK=off go test ./... -run '^$'
rg -n '"(database/sql|github.com/jackc/pgx|github.com/lib/pq|github.com/cloudnative-pg|github.com/dexidp/dex/storage)' --glob '*.go' . && exit 1 || true
git status --short
```

- [ ] Commit locally:

```bash
git add .
git commit -m 'chore: initialize dex operator'
```

## Task 2: Define the three CRDs and generated contract

**Files:**
- Create: `api/v1alpha1/common_types.go`
- Modify: the three `api/v1alpha1/*_types.go` files.
- Create: `internal/manifest/crd_test.go`
- Create: `hack/update-codegen.sh`, `hack/verify-generated.sh`
- Generate: `api/v1alpha1/zz_generated.deepcopy.go`, `config/crd/bases/*.yaml`, `config/rbac/role.yaml`

**Interfaces:**
- Consumes: approved field shapes and Kubernetes structural-schema/CEL rules.
- Produces: namespaced `dex.araihu.com/v1alpha1` CRDs with status subresources and immutable identity fields.

- [ ] Write table-driven manifest tests that load the three generated CRDs and assert:
  - namespaced scope and status subresource;
  - required keys and enum/default/min/max constraints;
  - immutable `email`, `userID` once present, client `id`/`public`, connector `id`/`type`;
  - exactly one local-user password mode;
  - generated password length `16..128` and at least one character set;
  - confidential/public client secret CEL rules;
  - base64url syntax for WebAuthn credential IDs;
  - no status schema field named or containing `password`, `hash`, `secret`, `config`, `certificate`, or `key` except non-sensitive `appliedSecretResourceVersion`.
- [ ] Run the focused test and confirm it fails against the untouched scaffold CRDs:

```bash
GOWORK=off go test ./internal/manifest -run TestCRDContract -count=1
```

- [ ] Implement the exact API types:
  - every spec has `adoptExisting` and `deletionPolicy`; common `DeletionPolicy` values are `Delete` and `Retain`, and `SecretKeyReference` is exactly `{name,key}`;
  - `DexLocalUserSpec` fields are immutable `email`, mutable `username`, optional-once `userID`, `password`, `mfa`, `adoptExisting`, and `deletionPolicy`;
  - `password` has exactly one of `hashSecretRef` or `generated`; generated fields are `secretName`, `length`, set-like `characterSets` with enum values `letters`, `numbers`, `symbols`, and `rotationNonce`;
  - `mfa` fields are `resetNonce`, set-like `removeAuthenticatorIDs`, and set-like `removeWebAuthnCredentialIDs`;
  - `DexLocalUserStatus` has `resolvedUserID`, ownership preclaim, handled nonce values, `appliedSecretResourceVersion`, non-secret MFA metadata, `observedGeneration`, and conditions;
  - `DexOAuth2ClientSpec` fields are immutable required `id`/`public`, mutable `name`/`logoURL`/set-like `redirectURIs`/`trustedPeers`/`allowedConnectors`, `secret`, `adoptExisting`, and `deletionPolicy`; confidential `secret` contains exactly one of `providedSecretRef` or `generated {secretName}` plus sibling `rotationNonce`, while public clients reject `secret` entirely;
  - `DexConnectorSpec` fields are immutable `id`/`type`, mutable `name`, opaque JSON `configSecretRef`, set-like `grantTypes`, `adoptExisting`, and `deletionPolicy`;
  - client/connector status has external-ID ownership preclaim, handled nonce/resource version where applicable, `observedGeneration`, and conditions named `Ready`, `Compatible`, and `Drifted`.
- [ ] Use `metav1.Time` only for API timestamps. Represent WebAuthn credential IDs in specs/status as unpadded base64url strings; decode only at the gRPC boundary.
- [ ] Generate deep-copy, CRD, and RBAC output with the scripts. The update script runs `controller-gen object`, `controller-gen crd`, and `controller-gen rbac` from the repository root. The verify script generates into `mktemp -d` and compares every tracked generated file without modifying it.
- [ ] Run focused and generated checks:

```bash
./hack/update-codegen.sh
./hack/verify-generated.sh
GOWORK=off go test ./internal/manifest -count=1
GOWORK=off go test ./api/... -count=1
```

- [ ] Commit locally:

```bash
git add api config hack internal/manifest
git commit -m 'feat: define dex management APIs'
```

## Task 3: Parse runtime configuration and establish secure Dex connectivity

**Files:**
- Create: `internal/config/config.go`, `internal/config/config_test.go`
- Create: `internal/dex/client.go`, `internal/dex/client_test.go`
- Create: `docs/configuration.md` (generated)
- Modify: `go.mod`, `go.sum`, `hack/update-codegen.sh`, `hack/verify-generated.sh`

**Interfaces:**
- Consumes: five approved environment variables and fixed cert-manager-shaped files.
- Produces: validated `config.Config` and concrete `dex.Client` with bounded, sanitized RPC calls.

- [ ] Write failing tests for defaults, required variables, duration parsing, rejection of any expected server value other than `v2.46.0-20260806171424-ab64ed77`, TLS file errors, `localhost`/literal loopback acceptance, non-loopback plaintext rejection, and sanitized gRPC errors.
- [ ] Run RED:

```bash
GOWORK=off go test ./internal/config ./internal/dex -count=1
```

Expected: compile failure because `Load` and `NewClient` do not exist.

- [ ] Implement one `config.Config` parsed with `env.Parse(&cfg)` before startup side effects:

```go
type Config struct {
    GRPCAddress          string        `env:"DEX_GRPC_ADDRESS,required"`
    GRPCServerName       string        `env:"DEX_GRPC_SERVER_NAME"`
    GRPCInsecure         bool          `env:"DEX_GRPC_INSECURE" envDefault:"false"`
    ReconcileInterval    time.Duration `env:"DEX_RECONCILE_INTERVAL" envDefault:"5m"`
    ExpectedServerVersion string       `env:"DEX_EXPECTED_SERVER_VERSION,required"`
}
```

Validation requires a positive reconcile interval and the compiled supported server value `v2.46.0-20260806171424-ab64ed77`; TLS mode requires a server name; insecure mode resolves the host with `net.DefaultResolver` and requires every result to be loopback. The environment variable remains explicit deployment evidence, not a way to widen binary compatibility.
- [ ] Fix production TLS paths under `/var/run/dex-operator/tls/{ca.crt,tls.crt,tls.key}`. Pass them to the concrete client as a `TLSFiles{CA,Cert,Key}` value so tests can provide `t.TempDir` files without adding environment variables. Load the CA pool and client keypair, set `ServerName`, require TLS 1.2 or newer, and use `grpc.NewClient` with TLS credentials. Never fall back to plaintext.
- [ ] Give every Dex wrapper call a fixed 10-second child deadline. Return an `OperationError` whose printable form contains only the operation and gRPC status code; do not expose or unwrap the raw message through controller logs/status.
- [ ] Add `//go:generate go tool envdoc -output ../../docs/configuration.md` immediately above `Config`, then include envdoc output in both update/verify scripts.
- [ ] Run GREEN:

```bash
./hack/update-codegen.sh
./hack/verify-generated.sh
GOWORK=off go test ./internal/config ./internal/dex -count=1 -race
```

- [ ] Commit locally:

```bash
git add internal/config internal/dex docs/configuration.md hack go.mod go.sum
git commit -m 'feat: add secure dex client configuration'
```

## Task 4: Add exact compatibility and readiness gating

**Files:**
- Create: `internal/dex/compatibility.go`, `internal/dex/compatibility_test.go`
- Modify: `cmd/main.go`

**Interfaces:**
- Consumes: `GetVersion`, `ListConnectors`, `ListUserIdentities` on the real client.
- Produces: shared `CompatibilityGate.Check(context.Context)` and controller-manager readiness checker.

- [ ] Write failing tests for classification logic using ordinary response/error values, not a fake Dex server: exact tuple compatible; server mismatch; API mismatch including newer API; connector probe disabled; identities probe disabled; transient unavailable.
- [ ] Run RED:

```bash
GOWORK=off go test ./internal/dex -run 'TestCompatibility' -count=1
```

- [ ] Implement a concrete gate around `Client`. Every readiness evaluation and every reconcile checks fresh state; the homelab scale does not justify caching a mutation-safety decision. A check performs, in order:
  1. `GetVersion` equals configured server version and numeric API `4` exactly;
  2. read-only `ListConnectors` succeeds;
  3. read-only `ListUserIdentities` succeeds.
  Probe payloads are discarded and never logged. Inside the gRPC boundary, recognize only Dex's exact disabled-feature responses and convert them to typed, sanitized capability failures before discarding the raw message.
- [ ] Return typed outcomes `Compatible`, `Incompatible`, and `Unavailable`. Only `Compatible` permits mutations. Newer Dex is deliberately incompatible until the pinned tuple is reviewed.
- [ ] Wire `/healthz` to `healthz.Ping` and `/readyz` to a checker that requires `Compatible`. Perform an initial read-only check before `mgr.Start`; log only the outcome/reason and continue so reconcilers can report status during Dex outages.
- [ ] Run GREEN:

```bash
GOWORK=off go test ./internal/dex ./cmd/... -count=1 -race
```

- [ ] Commit locally:

```bash
git add internal/dex cmd/main.go
git commit -m 'feat: gate mutations on dex compatibility'
```

## Task 5: Implement shared reconciliation and credential primitives

**Files:**
- Create: `internal/credentials/generate.go`, `internal/credentials/generate_test.go`
- Create: `internal/dex/normalize.go`, `internal/dex/normalize_test.go`
- Create: `internal/controller/common.go`, `internal/controller/common_test.go`

**Interfaces:**
- Consumes: CR identity, Secret names/keys, Dex response models.
- Produces: deterministic UUID, generated credentials, semantic comparisons, ownership/finalizer/status helpers, indexed Secret mapping.

- [ ] Write failing tests covering:
  - UUIDv5 namespace `e67d2ae2-f9a7-53db-bdff-875b72f09166` and frozen `DexLocalUser/default/admin` result `3f1a2d83-655d-5c4c-864c-ff4b8b83a31e`;
  - password lengths `16` and `128`, rejection outside bounds, every selected class present, characters restricted to approved sets;
  - 64-character URL-safe OAuth secret;
  - bcrypt cost exactly 12 and hash verification;
  - set-like normalization and connector JSON semantic equality without printing JSON on error;
  - condition observed generation/reason transitions;
  - ownership preclaim before external creation/adoption;
  - same-namespace named Secret loading and indexed Secret-to-CR mapping;
  - generated Secret owner conflict and Retain owner-reference detachment.
- [ ] Run RED:

```bash
GOWORK=off go test ./internal/credentials ./internal/dex ./internal/controller -run 'Test(UUID|Generate|Normalize|Condition|Ownership|Secret)' -count=1
```

- [ ] Implement UUIDv5 with `crypto/sha1` only for RFC 9562 namespace derivation; do not add a UUID dependency.
- [ ] Generate characters with `crypto/rand.Int`, force one character from each selected class, then perform a cryptographically random Fisher-Yates shuffle. Use the exact symbol set `!@#$%^&*()-_=+[]{}:,.?` and bcrypt cost 12.
- [ ] Implement list sorting/deduplication and semantic JSON comparison by decoding to `any` and using `reflect.DeepEqual`. Validation errors name only the resource and Secret key, never raw bytes.
- [ ] Implement one finalizer `dex.araihu.com/finalizer`. Before creating a missing remote record, or mutating an explicitly adopted one, persist the resolved external ID as an ownership preclaim in status. This closes the create/status crash window: a retry can distinguish its own preclaimed record from an unowned existing record.
- [ ] Implement Secret field indexes per CRD so only CRs that name a changed referenced/generated Secret are enqueued. No cross-namespace reference type exists.
- [ ] Use only three conditions with stable reasons: `Ready`, `Compatible`, `Drifted`; reasons include `Reconciling`, `Converged`, `Conflict`, `InvalidInput`, `DexUnavailable`, `IncompatibleDex`, `DriftCorrectionFailed`, and `DeletionBlocked`.
- [ ] Run GREEN:

```bash
GOWORK=off go test ./internal/credentials ./internal/dex ./internal/controller -count=1 -race
```

- [ ] Commit locally:

```bash
git add internal/credentials internal/dex/normalize* internal/controller/common*
git commit -m 'feat: add reconciliation primitives'
```

## Task 6: Build the exact real-Dex test harness

**Files:**
- Create: `hack/build-test-dex.sh`
- Create: `test/integration/harness_test.go`
- Modify: `Makefile`, `.gitignore`, `go.mod`, `go.sum`

**Interfaces:**
- Consumes: Docker, pinned Dex Git SHA/version, envtest Kubernetes `1.36.x`.
- Produces: disposable memory Dex, restartable SQLite Dex, mTLS gRPC, OIDC HTTP endpoint, and controller manager for integration tests.

- [ ] Write an integration-tagged harness smoke test that expects:
  - a local image named `dex-operator-test-dex:ab64ed778070`;
  - `GetVersion.server == v2.46.0-20260806171424-ab64ed77` and API `4`;
  - successful mTLS with cert-manager-shaped client files;
  - failed connections for wrong CA, wrong server name, or missing client cert;
  - successful read-only feature probes.
- [ ] Run RED:

```bash
GOWORK=off go test -tags=integration ./test/integration -run TestHarnessCompatibility -count=1
```

Expected: failure because the image/harness does not exist.

- [ ] Implement `hack/build-test-dex.sh` as a local-only build:

```bash
docker build \
  --build-arg VERSION=v2.46.0-20260806171424-ab64ed77 \
  --tag dex-operator-test-dex:ab64ed778070 \
  'https://github.com/dexidp/dex.git?ref=ab64ed778070e983cbb10cfc07ea4bb397d14312'
```

The script verifies the Git SHA/version constants before building and contains no login, push, registry, or publication command.
- [ ] In Go, generate a test CA, Dex server cert, and operator client cert with `crypto/x509`; write only to `t.TempDir`; mount the server files into Dex and expose HTTP/gRPC ports.
- [ ] Set both Dex feature flags to true. Generate Dex YAML in the test temp directory. Use memory storage for disposable tests and a Docker volume-backed SQLite file for stop/start persistence tests. Set `enablePasswordDB: true` and local-only issuer/client settings.
- [ ] Start envtest through the pinned `go tool setup-envtest` assets and run the real controller manager against the container. Do not import Dex server/storage code into the operator process.
- [ ] Pin the optional WebAuthn browser image by digest as `chromedp/headless-shell@sha256:2d349b544a1ea6b5b5fd7c0fe99215ff662339c57407ee2e8c0a11af93516b04`; connect through its remote debugging endpoint only in MFA tests.
- [ ] Run GREEN:

```bash
./hack/build-test-dex.sh
GOWORK=off go test -tags=integration ./test/integration -run TestHarnessCompatibility -count=1 -v
```

- [ ] Commit locally:

```bash
git add hack/build-test-dex.sh test/integration/harness_test.go Makefile .gitignore go.mod go.sum
git commit -m 'test: add pinned dex integration harness'
```

## Task 7: Reconcile connectors

**Files:**
- Modify: `internal/dex/client.go`
- Modify: `internal/controller/dexconnector_controller.go`
- Create: `test/integration/resources_test.go`
- Modify: `cmd/main.go`, `config/rbac/role.yaml`

**Interfaces:**
- Consumes: `DexConnector`, referenced JSON Secret, compatibility gate.
- Produces: Dex `CreateConnector`, `UpdateConnector`, `DeleteConnector`, and non-secret status.

- [ ] Write integration-tagged tests against envtest and the real Dex harness that assert missing Secret, invalid JSON, create, no-op idempotency, explicit adoption, unapproved conflict, mutable name/config/grant types, semantic JSON no-op, remote drift repair, missing-remote recreation, Delete, Retain, and Dex-unavailable finalizer blocking.
- [ ] Run RED:

```bash
GOWORK=off go test -tags=integration ./test/integration -run TestDexConnector -count=1 -v
```

- [ ] Implement observation through `ListConnectors` filtered in memory by ID. Never format returned config bytes. Create missing state; update only changed name/config/grant types; interpret absent/empty grant types as unrestricted; treat `already_exists`/`not_found` as signals to re-observe.
- [ ] Existing remote state without matching ownership preclaim is `Conflict` unless `adoptExisting=true`. Adoption preclaims status before the first mutation.
- [ ] Implement Delete/Retain finalization exactly as the spec. Requeue successful resources after the configured interval.
- [ ] Wire field index, Secret watch, controller, and RBAC. Do not add connector-type schema code.
- [ ] Run GREEN and generated checks:

```bash
GOWORK=off go test -tags=integration ./test/integration -run TestDexConnector -count=1 -v
GOWORK=off go test ./internal/controller ./internal/dex -count=1
./hack/verify-generated.sh
```

- [ ] Commit locally:

```bash
git add internal/controller internal/dex cmd/main.go config/rbac/role.yaml test/integration/resources_test.go
git commit -m 'feat: reconcile dex connectors'
```

## Task 8: Reconcile OAuth2 clients and secret lifecycles

**Files:**
- Modify: `internal/dex/client.go`
- Modify: `internal/controller/dexoauth2client_controller.go`
- Modify: `test/integration/resources_test.go`
- Modify: `cmd/main.go`, `config/rbac/role.yaml`

**Interfaces:**
- Consumes: `DexOAuth2Client`, provided/generated Secret, rotation nonce, compatibility gate.
- Produces: Dex client CRUD and generated `clientSecret` Secret.

- [ ] Write failing tests for public create/update, confidential provided/generated create, no-op, adoption/conflict, field drift, Secret resource-version drift, explicit rotation, generated Secret manual edit, generated Secret loss/recovery, logo removal, remote loss, Delete, and Retain.
- [ ] Run RED:

```bash
GOWORK=off go test -tags=integration ./test/integration -run TestDexOAuth2Client -count=1 -v
```

- [ ] Observe with `GetClient`. Normalize URI/peer/connector lists. Use `UpdateClient` for name, logo set/change, redirect URIs, trusted peers, and allowed connectors.
- [ ] For confidential clients, read exactly one provided/generated mode. Initial generated material is 64 URL-safe characters in `clientSecret`; create the Secret with a controller owner reference and persist its resource version only after remote convergence.
- [ ] A provided/generated Secret value change does not authorize a disruptive remote secret change. Report drift and fail closed until `rotationNonce` changes. On an authorized rotation, delete/recreate the Dex client, then mark the nonce handled. A public client never reads or writes a secret.
- [ ] Logo removal also uses delete/recreate because Dex cannot clear it. This path is authorized by the explicit CR field change and does not require the secret rotation nonce.
- [ ] If an owned generated Secret is lost but Dex survives, recover `GetClient.client.secret` into a new owned Secret only after ownership/adoption is established. Never log or stage the value elsewhere.
- [ ] Generated Secret edits with an unchanged rotation nonce fail closed. On Retain, remove the Secret owner reference before finalizer removal; on Delete, remove client and generated Secret.
- [ ] Run focused gates:

```bash
GOWORK=off go test -tags=integration ./test/integration -run TestDexOAuth2Client -count=1 -v
GOWORK=off go test ./internal/controller ./internal/dex ./internal/credentials -count=1 -race
./hack/verify-generated.sh
```

- [ ] Commit locally:

```bash
git add internal/controller internal/dex cmd/main.go config/rbac/role.yaml test/integration/resources_test.go
git commit -m 'feat: reconcile dex oauth clients'
```

## Task 9: Reconcile local users and password lifecycles

**Files:**
- Modify: `internal/dex/client.go`
- Modify: `internal/controller/dexlocaluser_controller.go`
- Modify: `test/integration/resources_test.go`
- Modify: `cmd/main.go`, `config/rbac/role.yaml`

**Interfaces:**
- Consumes: `DexLocalUser`, provided bcrypt hash or generated policy, compatibility gate.
- Produces: Dex password CRUD/verification and generated `password`/`bcryptHash` Secret.

- [ ] Write failing tests for deterministic omitted user ID; explicit user ID; provided hash create/update; generated create/no-op/rotation; generated Secret edit/loss; username drift; password verification drift; adoption/conflict; managed external user-ID drift; missing remote recreation; Delete; Retain.
- [ ] Run RED:

```bash
GOWORK=off go test -tags=integration ./test/integration -run TestDexLocalUser -count=1 -v
```

- [ ] Observe users through `ListPasswords`, filtering by immutable email. Derive omitted IDs once from namespace/name and persist the resolved ID ownership preclaim before creation.
- [ ] Validate provided bcrypt hashes and apply a new hash whenever the named Secret resource version changes. Record only its resource version. Do not claim later out-of-band hash drift detection because Dex omits hashes from `ListPasswords`.
- [ ] For generated mode, create `password` and cost-12 `bcryptHash` atomically in one owned Secret. Verify remote drift using `VerifyPassword`; only a changed `rotationNonce` generates and applies a new credential.
- [ ] A manually edited generated Secret fails closed until nonce rotation. If an owned generated Secret disappears while its remote user survives, fail closed until nonce rotation because plaintext is unrecoverable.
- [ ] Adoption requires the observed Dex user ID to equal the resolved desired ID. On mismatch, report Conflict and instruct the user to set the optional `userID` to the observed value before adoption; never silently change an existing OIDC subject during takeover.
- [ ] After ownership is established, observable out-of-band user-ID drift is repaired by deleting the password and old `local` identity, then recreating the password with the immutable desired ID. Mark `Drifted=True` during the repair because sessions/identity are disrupted.
- [ ] Delete policy calls both `DeletePassword(email)` and `DeleteUserIdentity(resolvedID,"local")`, then deletes the generated Secret. Retain detaches any generated Secret owner reference and leaves Dex unchanged.
- [ ] Run focused gates:

```bash
GOWORK=off go test -tags=integration ./test/integration -run TestDexLocalUser -count=1 -v
GOWORK=off go test ./internal/controller ./internal/dex ./internal/credentials -count=1 -race
./hack/verify-generated.sh
```

- [ ] Commit locally:

```bash
git add internal/controller internal/dex cmd/main.go config/rbac/role.yaml test/integration/resources_test.go
git commit -m 'feat: reconcile dex local users'
```

## Task 10: Add MFA inventory, reset, and removal

**Files:**
- Create: `internal/controller/mfa.go`, `internal/controller/mfa_test.go`
- Modify: `internal/dex/client.go`
- Modify: `internal/controller/dexlocaluser_controller.go`

**Interfaces:**
- Consumes: resolved local user ID, `mfa.resetNonce`, durable removal lists.
- Produces: non-secret MFA status plus `ListMFADevices`, `ResetMFA`, `DeleteMFASecret`, `DeleteWebAuthnCredential` calls.

- [ ] Write failing mapping/idempotency tests for empty inventory, TOTP metadata, WebAuthn metadata, unpadded base64url IDs, invalid credential IDs, reset nonce replay, authenticator removal replay, credential removal replay, and secret-safe errors.
- [ ] Run RED:

```bash
GOWORK=off go test ./internal/controller -run 'TestMFA' -count=1
```

- [ ] After password convergence, call `ListMFADevices(resolvedID,"local")`. Store only authenticator ID/type/confirmed/created time and credential ID/display name/transports/backup flags/clone warning/created time. Do not store MFA secret values, public keys, attestation objects, or AAGUID.
- [ ] When `resetNonce` differs from status, call `ResetMFA` once and persist the handled nonce only after re-observation shows no devices. Treat not-found as success.
- [ ] Treat authenticator and credential removal lists as durable desired absence. Decode credential IDs with `base64.RawURLEncoding`; replay removal each reconcile; not-found is success; re-observe before Ready.
- [ ] Run GREEN:

```bash
GOWORK=off go test ./internal/controller ./internal/dex -count=1 -race
```

- [ ] Commit locally:

```bash
git add internal/controller internal/dex
git commit -m 'feat: manage local user mfa lifecycle'
```

## Task 11: Prove all resource reconciliation against real Dex

**Files:**
- Modify: `test/integration/resources_test.go`
- Modify: controller integration tests as needed.

**Interfaces:**
- Consumes: envtest CRDs/Secrets and real Dex gRPC.
- Produces: end-to-end evidence for create/update/adopt/drift/delete/restart behavior.

- [ ] Add table-driven real-Dex cases for each resource:
  - create and observe `Ready=True`, `Compatible=True`, `Drifted=False`;
  - second reconcile emits no remote mutation;
  - supported mutable update;
  - unowned external collision, then explicit adoption;
  - external drift repair and missing-object recreation;
  - Delete finalization and Retain finalization;
  - referenced/generated Secret update mapping enqueues only named consumers;
  - compatibility mismatch and each disabled feature flag block mutations;
  - Dex stop/restart replays safely with SQLite persistence.
- [ ] Add client-specific provided/generated Secret rotation, logo removal, and lost-generated-Secret recovery cases.
- [ ] Add local-user provided/generated password, `VerifyPassword` drift, lost-plaintext fail-closed, deterministic ID, and login acceptance cases.
- [ ] Add connector semantic JSON, grant-type, and opaque-config cases. Test setup creates external records only through Dex gRPC, never through storage.
- [ ] Place unique sentinel secret values in every secret-bearing case. Capture controller logs/status and Kubernetes Events, then assert no sentinel appears. Assert no custom metric or trace contains resource payloads; the MVP emits none.
- [ ] Run focused GREEN:

```bash
GOWORK=off go test -tags=integration ./test/integration -run 'Test(Resources|Compatibility|Restart|SecretSafety)' -count=1 -v
```

- [ ] Commit locally:

```bash
git add test/integration internal/controller
git commit -m 'test: verify dex resource reconciliation'
```

## Task 12: Prove MFA with real supported login flows

**Files:**
- Create: `test/integration/mfa_test.go`
- Modify: `test/integration/harness_test.go`

**Interfaces:**
- Consumes: Dex OIDC/local-login pages, TOTP and WebAuthn enrollment, operator MFA fields.
- Produces: real device inventory/removal/reset evidence without database access or mocked Dex.

- [ ] Implement an OIDC authorization-code test client in the harness using `net/http`, cookie jars, and HTML form parsing limited to Dex's login forms. Create the OAuth client and local password through the operator CRDs.
- [ ] For TOTP, follow the real local-login enrollment page, decode the base64 PNG QR with test-only `gozxing` to obtain the `otpauth` URI, compute the current code with a tiny RFC 6238 helper using `crypto/hmac`/`sha1`, submit it, and complete the OIDC flow. Do not persist or log the URI or seed.
- [ ] Assert the operator status lists the TOTP authenticator without secret material. Add its authenticator ID to `removeAuthenticatorIDs`, wait for Ready, and verify the device is absent through both status and `ListMFADevices`.
- [ ] For WebAuthn, run the digest-pinned headless Chrome container, enable the Chrome DevTools `WebAuthn` domain, add a virtual authenticator with automatic presence, and complete Dex's real registration page. Record only the returned credential ID from operator status.
- [ ] Add that ID to `removeWebAuthnCredentialIDs`, wait for Ready, and verify absence. Re-add devices, change `resetNonce`, and verify all devices are absent. Replay each desired removal/reset and assert no failure.
- [ ] Assert captured status/logs/events contain no TOTP URI/seed, WebAuthn public key, client secret, password, certificate, or private key sentinel.
- [ ] Run GREEN:

```bash
GOWORK=off go test -tags=integration ./test/integration -run TestMFA -count=1 -v
```

- [ ] Commit locally:

```bash
git add test/integration/mfa_test.go test/integration/harness_test.go
git commit -m 'test: verify real dex mfa lifecycle'
```

## Task 13: Finish manifests and operational handoff documentation

**Files:**
- Modify: `config/manager/manager.yaml`, `config/default/kustomization.yaml`, `config/rbac/role.yaml`, `config/samples/*.yaml`, `Dockerfile`, `README.md`
- Create: `docs/compatibility.md`, `docs/security.md`, `docs/backup-recovery.md`, `docs/homelab-handoff.md`
- Modify: `Makefile`, `hack/verify-generated.sh`

**Interfaces:**
- Consumes: implemented runtime/API and approved ownership boundary.
- Produces: generic, secret-free packaging and an explicit read-only homelab handoff.

- [ ] Add manifest tests that assert the manager runs non-root/read-only, drops capabilities, mounts `/var/run/dex-operator/tls` read-only, has liveness/readiness probes, declares only the approved environment variables, and has cluster-wide Secret RBAC plus namespaced same-name behavior enforced in code.
- [ ] Run RED:

```bash
GOWORK=off go test ./internal/manifest -run TestManagerContract -count=1
```

- [ ] Patch the generic manager manifest and Dockerfile to satisfy the test. Use the fixed local-only image name `dex-operator:local`; do not select a registry or production digest. Samples reference fake Secret names and never inline data.
- [ ] Document:
  - the exact Dex SHA/API/server tuple and reviewed upgrade checklist;
  - required feature flags and image override, explicitly noting the custom Dex image is not published by this project task;
  - cert-manager-shaped `ca.crt`, `tls.crt`, `tls.key`, exact server name, NetworkPolicy, and Reloader restart ownership;
  - cluster-wide Secret RBAC risk and same-namespace code restriction;
  - Git/etcd/CNPG backup planes, restore order, client-secret recovery, unrecoverable generated password plaintext, explicit adoption after status loss;
  - future homelab mapping for existing CNPG `<cluster>-rw` and application Secret, without selecting/provisioning either;
  - removal of static resource conflicts and Argo ordering;
  - emergency manual finalizer removal consequences.
- [ ] State prominently that the operator does not provision CNPG, receive PostgreSQL credentials, touch Dex tables, or own Dex Deployment/config.
- [ ] Add README quick-start only for local tests and CR examples. Do not include `kubectl apply` against a real cluster, image push, GitHub creation, or release steps.
- [ ] Run GREEN:

```bash
./hack/update-codegen.sh
./hack/verify-generated.sh
GOWORK=off go test ./internal/manifest -count=1
```

- [ ] Commit locally:

```bash
git add config Dockerfile README.md docs Makefile hack
git commit -m 'docs: add secure dex operator handoff'
```

## Task 14: Fresh verification and scoped self-review

**Files:**
- Modify only files required by defects found during verification/review.

**Interfaces:**
- Consumes: complete local implementation.
- Produces: reproducible green evidence and a clean local `main`, without remote/deployment side effects.

- [ ] Confirm lifecycle boundaries and repository identity:

```bash
git status --short
git remote -v
git var GIT_AUTHOR_IDENT
test ! -e /Users/guilhermecastro/repos/araihu/dex-operator/.github/workflows
```

Expected: clean before verification, no remote, approved identity, no workflow directory.

- [ ] Run generation and fast gates from scratch:

```bash
./hack/verify-generated.sh
GOWORK=off go test ./... -count=1
GOWORK=off go test -race ./... -count=1
GOWORK=off go vet ./...
GOWORK=off go build ./cmd/...
git diff --check
```

- [ ] Rebuild the exact Dex image fresh, then run integration tests without cached results:

```bash
./hack/build-test-dex.sh
GOWORK=off go test -tags=integration ./test/integration -count=1 -v
```

- [ ] Run a forbidden-boundary audit:

```bash
rg -n '"(database/sql|github.com/jackc/pgx|github.com/lib/pq|github.com/cloudnative-pg|github.com/dexidp/dex/storage)' --glob '*.go' . && exit 1 || true
rg -n 'password|bcryptHash|clientSecret|tls.key|MFASecret|connector.*config' internal cmd --glob '*.go'
rg -n 'kubectl|docker push|gh repo create|git push|cnpg|postgres' Makefile hack cmd internal --glob '*'
```

Review every match: secret terms are allowed only as field/key handling without value formatting; forbidden lifecycle/storage commands must be absent.

- [ ] Self-review the full diff against every acceptance criterion in the approved spec, with special attention to:
  - crash windows around ownership preclaim, external creation, Secret creation, and status update;
  - deletion finalizers under Dex outage;
  - provided versus generated Secret rotation authority;
  - status loss/adoption and backup recovery;
  - compatibility cache invalidation and mutation blocking;
  - no secret-bearing `%v`, structured log field, event, condition message, metric label, or test failure output.
- [ ] Fix defects with a new failing regression first, rerun the smallest relevant gate, then rerun all fresh gates above.
- [ ] If fixes were needed, commit them locally:

```bash
git add .
git commit -m 'fix: address dex operator self-review'
```

- [ ] Record final evidence without performing any remote or homelab action:

```bash
git status --short
git log --oneline --decorate -15
git remote -v
```

Expected: clean local repository, no remote, all gates green. Stop and ask separately before GitHub creation, push, image publication, release, deployment, or home-lab integration.

## Deferred by design

- A `DexInstance` CRD or ownership of Dex Deployment/config.
- CNPG provisioning, database credentials, backup controllers, PostgreSQL integration tests, or direct Dex storage access.
- Connector-specific schemas and the remaining Dex client/session/config fields.
- MFA enrollment APIs; enrollment stays in Dex login.
- Certificate hot reload; the live handoff uses Reloader/restarts.
- GitHub Actions, remote creation, image registry selection/publication, releases, and homelab manifests. Add only after separate authorization and concrete integration inputs.
