# Dex Operator Design

**Status:** Written specification approved on 2026-08-25; implementation plan remains approval-gated.

## Summary

`dex-operator` is a small Go Kubernetes operator that manages selected Dex resources through Dex's supported gRPC API. It manages local users, OAuth2 clients, and connectors. Helm/GitOps continues to own the Dex runtime, static configuration, PostgreSQL connection, certificates, network policy, and rollout lifecycle.

The operator never provisions CloudNativePG, receives PostgreSQL credentials, accesses Dex tables, or reconciles Dex's Kubernetes-storage CRDs. PostgreSQL is Dex's production storage backend; tests may use Dex memory storage or SQLite because database behavior is outside the operator boundary.

## Evidence and compatibility baseline

Research snapshot: 2026-08-25.

- Current Dex `master` commit: `ab64ed778070e983cbb10cfc07ea4bb397d14312`.
- That commit exposes Dex `api/v2` numeric API version `4` and adds MFA inventory/reset/removal methods not present in released Dex `v2.45.1`.
- Connector CRUD and session/identity/MFA CRUD are disabled by default behind `DEX_API_CONNECTORS_CRUD` and `DEX_API_SESSIONS_IDENTITIES_CRUD`.
- The official Dex Helm chart at the research snapshot is chart `0.24.1`, with Dex app version `2.44.0`; it must use an image override for this project.
- The tracked homelab GitOps state no longer contains Dex. Dex was decommissioned in commit `c894b1d`; the future handoff is a reintroduction, not an in-place takeover.
- Homelab CNPG conventions use `<cluster>-rw` for writes, CNPG-generated application Secrets, plugin-backed scheduled backups, and explicit restore tests.

Primary sources:

- [Dex gRPC API documentation](https://dexidp.io/docs/configuration/api/)
- [Pinned Dex `api/v2` schema](https://github.com/dexidp/dex/blob/ab64ed778070e983cbb10cfc07ea4bb397d14312/api/v2/api.proto)
- [Official Dex Helm chart](https://github.com/dexidp/helm-charts/tree/master/charts/dex)
- [Kubebuilder finalizer guidance](https://book.kubebuilder.io/reference/using-finalizers.html)
- [Kubernetes custom-resource guidance](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)

## Goals

1. Declaratively manage local Dex users, OAuth2 clients, and connectors.
2. Use only Dex gRPC and OIDC/login interfaces for Dex state.
3. Reconcile idempotently, detect observable drift, and self-heal it.
4. Keep passwords, client secrets, connector configuration, MFA secrets, certificates, and keys out of CR status, events, metrics labels, traces, and logs.
5. Support local-user MFA inventory, full reset, authenticator removal, and WebAuthn credential removal through current Dex `master` APIs.
6. Fit the existing Helm/GitOps and CNPG ownership model without modifying the homelab repository during operator development.

## Non-goals

- Owning the Dex Deployment, Service, HTTP route, config Secret, certificates, or rollout.
- Provisioning or owning CNPG clusters, databases, users, Services, Secrets, backups, or restore jobs.
- Reading or writing Dex database tables directly, including in tests.
- Reconciliation of Dex internal Kubernetes-storage CRDs.
- Wrapping every Dex config or connector-specific field.
- Managing MFA enrollment. Enrollment remains part of Dex's supported login flow.
- Publishing images, creating a GitHub repository, pushing, deploying, releasing, or editing `home-lab` without separate authorization.

## Considered approaches

### Management-only operator — selected

Helm/GitOps owns Dex runtime configuration. The operator owns three CRDs and reconciles their desired state through Dex gRPC.

This keeps runtime rollout, PostgreSQL, networking, and certificates out of the controller's failure domain. It also reuses the official chart rather than duplicating it.

### Full Dex operator — rejected

A full operator would additionally own the Dex Deployment, config, Service, storage wiring, probes, upgrades, and rollouts. It would duplicate the Helm chart, expand RBAC, couple identity reconciliation to runtime rollout failures, and create CNPG ownership ambiguity. No approved requirement needs that scope.

## Runtime architecture and ownership

One cluster-wide controller-manager watches three namespaced CRDs and referenced/generated Secrets. Three reconcilers share one authenticated Dex `api/v2` client and common compatibility, status, finalizer, and secret-handling helpers.

There is no `DexInstance` CRD. One operator installation targets one Dex instance.

Helm/GitOps owns:

- Dex Deployment and Service;
- issuer, HTTP/OIDC settings, `enablePasswordDB`, and MFA configuration;
- gRPC listener and server-side mTLS configuration;
- required Dex feature flags;
- PostgreSQL storage configuration using an existing CNPG write Service and application Secret;
- restart annotations for certificate/config rotation;
- the operator Deployment, TLS volume, NetworkPolicy, CRDs, and RBAC.

The operator owns:

- external Dex records represented by its CRs;
- generated password and client Secrets;
- status and finalizers on its CRs.

The operator has no PostgreSQL or CNPG client. Dex alone performs schema creation, migration, and data access.

## Runtime configuration

Runtime configuration is read once into one typed Go struct before startup side effects. Parsing uses `github.com/caarlos0/env/v11`; documentation is generated from the same struct with `github.com/g4s8/envdoc`.

| Variable | Required/default | Meaning |
|---|---|---|
| `DEX_GRPC_ADDRESS` | required | Dex gRPC host and port |
| `DEX_GRPC_SERVER_NAME` | required with TLS | Certificate name verified by the client |
| `DEX_GRPC_INSECURE` | `false` | Allows plaintext only when the target resolves to loopback |
| `DEX_RECONCILE_INTERVAL` | `5m` | Periodic remote-drift reconciliation |
| `DEX_EXPECTED_SERVER_VERSION` | required | Exact commit-derived value expected from `GetVersion` |

Live TLS material is mounted at fixed paths from a cert-manager-shaped Secret:

- `ca.crt`
- `tls.crt`
- `tls.key`

Missing or invalid TLS material fails startup. TLS errors never fall back to plaintext.

## Kubernetes API

All resources are namespaced and use `dex.araihu.com/v1alpha1`. CRDs use the status subresource, structural schemas, and CEL validation. Version 1 does not require admission or conversion webhooks.

Common fields:

- `spec.adoptExisting`: default `false`; explicitly authorizes takeover of a record that exists without operator ownership status.
- `spec.deletionPolicy`: `Delete` or `Retain`, default `Delete`.
- Secret references contain only required `name` and `key`; cross-namespace references do not exist.
- Immutable identity fields use CRD validation.

### `DexLocalUser`

Spec:

- `email`: required and immutable; Dex password-record natural key.
- `username`: required and mutable.
- `userID`: optional and immutable when specified. Dex accepts an opaque non-empty string; UUID form is recommended.
- `password`: exactly one of:
  - `hashSecretRef {name, key}` for a provided bcrypt hash;
  - `generated {secretName, length, characterSets, rotationNonce}`.
- `mfa.resetNonce`: changing the value requests one full MFA reset.
- `mfa.removeAuthenticatorIDs`: authenticator IDs that must remain absent.
- `mfa.removeWebAuthnCredentialIDs`: base64url-encoded credential IDs that must remain absent.

When `userID` is omitted, the operator derives an RFC 9562 UUIDv5 deterministically:

1. Namespace UUID: UUIDv5 of DNS namespace and `dex.araihu.com`.
2. User UUID: UUIDv5 of that namespace and `DexLocalUser/<namespace>/<name>`.

The same namespace/name therefore preserves the OIDC `sub` claim after manifest-based recovery. Renaming the CR changes the derived subject.

Generated-password policy:

- length must be between 16 and 128;
- `characterSets` must select at least one of `letters`, `numbers`, `symbols`;
- generation uses `crypto/rand` with unbiased selection;
- output includes at least one character from every selected set;
- `letters` means `A-Z` and `a-z`, `numbers` means `0-9`, and `symbols` means `!@#$%^&*()-_=+[]{}:,.?`;
- generated hashes use bcrypt cost 12;
- the managed Secret contains `password` and matching `bcryptHash`;
- changing policy alone does not rotate credentials;
- a new `rotationNonce` creates and applies a replacement.

Status includes the resolved user ID, observed generation, handled nonces, applied Secret resource version, conditions, and MFA device metadata. Device status may contain authenticator ID, type, confirmation state, creation time, WebAuthn credential ID, display name, transport, and security flags returned by Dex. It never contains a TOTP seed, MFA secret, WebAuthn public key, password, or bcrypt hash.

### `DexOAuth2Client`

Spec:

- `id`: required and immutable.
- `public`: required and immutable.
- `name`: required, non-empty, and mutable.
- mutable `logoURL`, `redirectURIs`, `postLogoutRedirectURIs`, `trustedPeers`, and `allowedConnectors`.
- confidential clients require exactly one secret mode:
  - provided same-namespace Secret reference;
- generated Secret with a requested name, optional client-ID key, configurable client-secret key, and optional declarative labels.
- generated client secrets contain 64 characters from `A-Z`, `a-z`, `0-9`, `_`, and `-`, selected with `crypto/rand`.
- `rotationNonce` explicitly authorizes secret rotation.
- public clients reject all secret fields.

Dex cannot update client secrets, switch public/confidential mode, clear a previously set logo URL, or represent removal of all post-logout redirects through `UpdateClient`. Secret drift, an authorized rotation, logo removal, or post-logout redirect removal is reconciled through delete/recreate, producing a brief client-authentication interruption. Other mutable non-secret fields use `UpdateClient`.

The generated Secret contains `clientSecret` by default. `clientIDKey` optionally adds the non-secret client ID, and `clientSecretKey` changes the secret data key for direct consumer compatibility. `labels` declaratively owns only the named Secret label keys; labels outside that set are preserved. Arbitrary annotations, owner references, finalizers, and data templates are not exposed. No client secret appears in status.

### `DexConnector`

Spec:

- `id`: required and immutable.
- `type`: required and immutable from the Kubernetes API perspective.
- `name`: required and mutable.
- `configSecretRef`: required; selected Secret key contains the exact connector JSON document.
- `grantTypes`: optional common restriction. Omitted or empty means unrestricted.

The operator validates JSON syntax but does not model connector-specific schemas. Dex remains responsible for connector-type validation. Raw desired or observed configuration never appears in status or diagnostics.

## Reconciliation

For each CR, the reconciler:

1. Adds its finalizer before creating or adopting Dex state.
2. Loads referenced Secret data and validates the desired object.
3. Verifies the global Dex compatibility gate.
4. Observes the external record by natural key.
5. Creates a missing record or evaluates adoption for a pre-existing record.
6. Normalizes and compares desired and actual state.
7. Applies the minimum supported gRPC mutation needed to converge.
8. Updates status only after observing the final external state.
9. Requeues after `DEX_RECONCILE_INTERVAL`.

CR and indexed Secret events enqueue immediate reconciliation. Unrelated Secret changes do not enqueue all resources.

Idempotency rules:

- Dex `already_exists` and `not_found` responses are interpreted according to current observed state rather than treated as fatal by default.
- Set-like redirect URI, post-logout redirect URI, peer, connector, and grant-type lists compare in normalized order.
- Connector JSON compares semantically in memory.
- No remote write occurs when normalized state already matches.
- Each RPC has a bounded deadline; controller-runtime rate limiting handles retries.
- A missing managed remote object is recreated.
- Observable out-of-band mutation is self-healed.

Password limitation: `ListPasswords` intentionally omits hashes. A provided hash can be applied and its Secret version tracked, but out-of-band hash drift cannot be observed. Generated passwords can be checked through `VerifyPassword` over mTLS because the managed Secret retains plaintext.

Client comparison uses `GetClient`, which returns a secret. That value is held only long enough for comparison or lost-Secret recovery and is never logged or persisted outside the intended Secret.

Connector comparison uses `ListConnectors`, which returns raw config. Raw bytes remain in bounded memory and are never formatted into errors.

## Adoption and static configuration

If a natural key exists but the CR has no ownership status, reconciliation reports `Conflict` unless `adoptExisting` is true. Adoption converges the existing object to the CR.

Dex static and dynamic resources share identifiers and storage behavior. The operator cannot reliably prove a record's static origin. Helm config must remove every operator-managed user, client, and connector before adoption. Reintroducing a static entry may overwrite operator state on Dex restart and is unsupported.

If Kubernetes status is lost while Dex data survives, affected CRs require explicit adoption before convergence resumes. Keeping `adoptExisting: true` after an intentional migration is permitted.

## MFA lifecycle

MFA enrollment remains in Dex's supported login flow. Operator behavior is limited to current `api/v2` capabilities:

- inventory devices with `ListMFADevices`;
- clear all devices with `ResetMFA` after a new `resetNonce`;
- remove one authenticator with `DeleteMFASecret`;
- remove one WebAuthn credential with `DeleteWebAuthnCredential`.

The local connector ID is `local`. Removal lists are durable desired absence and are safe to replay. Dex `not_found` is success for removal/reset idempotency. MFA operations require `DEX_API_SESSIONS_IDENTITIES_CRUD=true` in Dex.

## Status and conditions

Every CR reports:

- `observedGeneration`;
- external/resolved identifier where useful;
- last handled rotation/reset nonce and applied Secret resource version where relevant;
- standard `metav1.Condition` entries: `Ready`, `Compatible`, `Drifted`.

Each condition carries `observedGeneration`, transition time, stable CamelCase reason, and sanitized human message. `Ready=True` means the current generation has been observed and converged. `Compatible=False` blocks mutations. `Drifted=True` means drift was observed but could not be corrected.

Status does not retain historical error streams or secret fingerprints.

## Deletion and finalizers

`Delete` policy:

- `DexOAuth2Client` calls `DeleteClient`.
- `DexConnector` calls `DeleteConnector`.
- `DexLocalUser` calls both `DeletePassword` and `DeleteUserIdentity`. The identity purge removes session-linked identity and MFA state when present; deleting the password separately handles users who never completed a login.
- Generated Secrets are removed.

External deletion is idempotent. The finalizer is removed only after successful cleanup or a confirmed absent record.

`Retain` policy removes the finalizer without deleting external state. Generated Secret ownership is detached so Kubernetes garbage collection does not remove it.

If Dex is unavailable, deletion remains blocked and status reports a sanitized failure. Manual finalizer removal is the documented emergency escape hatch.

## Compatibility strategy

The initial reviewed build contract is exact:

- Dex source SHA `ab64ed778070e983cbb10cfc07ea4bb397d14312`;
- matching `github.com/dexidp/dex/api/v2` pseudo-version;
- image identity remains Helm/GitOps-owned and may use any syntactically valid, digest-pinned OCI reference.

The runtime compatibility gate is limited to values Dex exposes over gRPC: numeric API version `4`, the exact commit-derived `GetVersion.server` value configured in the operator, and successful read-only `ListConnectors` and `ListUserIdentities` capability probes. A version, API, or capability mismatch fails readiness, sets `Compatible=False` on reconciled resources, and blocks mutations. Probe results are discarded and never logged. The operator does not assume that a newer API is compatible.

Dex must set:

```text
DEX_API_CONNECTORS_CRUD=true
DEX_API_SESSIONS_IDENTITIES_CRUD=true
```

Moving to another Dex commit requires one reviewed change that updates the API dependency, expected server/API versions, compatibility tests, and documented behavior changes. Changing only registry or repository identity does not require an operator change when the runtime tuple remains compatible.

The operator does not receive or inspect the Dex image reference, source SHA, or API-module provenance. Reference syntax validation, digest pinning, signed provenance verification against the recorded source SHA, image publication, and rollout belong to Helm/GitOps integration and are mandatory for every supported deployment. Operator tests build the reviewed source locally without publishing it.

## Security boundaries

- Production gRPC uses mTLS. Dex provides no additional admin API authorization.
- The client certificate, key, and CA come from a cert-manager-shaped Secret.
- `DEX_GRPC_INSECURE=true` is accepted only for loopback development targets; no silent fallback exists.
- A NetworkPolicy should allow Dex gRPC traffic only from operator pods.
- Cluster-wide CR support requires cluster-wide Secret read/write RBAC. This risk is accepted. Code reads only named same-namespace references and writes only generated Secrets.
- Secret values, connector JSON, password hashes, MFA material, and certificates never enter status, events, metrics labels, traces, logs, or panic formatting.
- Generated Secret manual edits fail closed unless the applicable rotation contract authorizes them.
- Certificate rotation uses Helm-owned restart annotations or the homelab Reloader instead of custom hot-reload code.

## Testing and verification

Dex is never mocked.

Fast tests cover local deterministic behavior only:

- normalization and semantic comparisons;
- UUIDv5 derivation;
- password generation and character-set guarantees;
- bcrypt validation;
- config validation and generated environment documentation;
- secret-safe error/status formatting.

Docker integration tests use `testcontainers-go` to start the exact locally built Dex image. Dex uses memory storage for disposable cases and SQLite on a test volume for restart/persistence cases. PostgreSQL is intentionally absent because the operator never uses its interface.

`envtest` supplies a real Kubernetes API server while reconcilers communicate with the real Dex container. The suite covers:

- create, update, adoption, drift repair, deletion, and retention for all CRDs;
- provided/generated Secret lifecycles and rotations;
- mTLS success and certificate failures;
- incompatible version and disabled feature flags;
- Dex stop/restart and reconciliation replay;
- MFA inventory, reset, authenticator removal, and WebAuthn credential removal through supported Dex login/gRPC flows;
- secret absence from status, events, and captured logs.

Tests never seed or inspect Dex tables. Test setup mutates Dex only through supported Dex interfaces.

Verification gates:

- generated code and CRD manifests are current;
- `go test ./...`;
- Docker integration suite under an explicit integration build tag/target;
- race tests;
- `go vet ./...`;
- generated environment documentation has no drift;
- `git diff --check`.

## Backup and recovery

Three state planes require separate protection:

1. Git stores CR desired state and provided SealedSecrets.
2. Kubernetes/etcd backup protects generated Secrets, live CR status, and finalizers.
3. CNPG backup protects Dex passwords/hashes, clients, connector config, signing keys, sessions, tokens, identities, and MFA material.

Recovery order:

1. Restore and validate CNPG.
2. Start Dex against the restored CNPG write Service and Secret.
3. Confirm Dex health, discovery, gRPC mTLS, and compatibility tuple.
4. Start the operator and restore/apply CRs and Secrets.
5. Explicitly adopt surviving Dex records when CR status was not restored.
6. Confirm `Ready=True` and perform local-user login checks.

Recovery behavior:

- Deterministic omitted user IDs preserve OIDC subjects for the same namespace/name.
- A missing generated client Secret can be reconstructed from Dex `GetClient` after ownership/adoption is established.
- A missing generated user-password Secret cannot recover plaintext from Dex. Reconciliation fails closed until the user changes `rotationNonce` and accepts a new password.
- Missing provided or connector Secrets fail closed; Dex data is not silently copied back into those inputs.
- MFA enrollment material is restored only by CNPG recovery. If unavailable, users must re-enroll after an explicit reset.

The operator neither schedules CNPG backups nor performs restores.

## Homelab integration handoff

No `home-lab` files change during operator implementation. The operator repository will document a separately authorized handoff containing:

- exact Dex source SHA, API pseudo-version, a syntactically valid digest-pinned image reference, and feature flags;
- official chart image override and gRPC enablement;
- PostgreSQL config mapping from an externally supplied CNPG application Secret and `<cluster>-rw` Service;
- cert-manager server/client certificates and cert-manager-shaped Secrets;
- NetworkPolicy and Reloader annotations;
- operator CRDs, cluster-wide RBAC, Deployment, TLS mount, and Argo ordering;
- removal of conflicting static Dex users, clients, and connectors;
- CNPG scheduled-backup, restore-test, retention, and post-restore login acceptance requirements;
- sample operator CRs containing no real secrets.

Selecting or provisioning the actual CNPG cluster, database, Secret, registry, image publication path, routes, and rollout remains home-lab integration scope and requires separate authorization.

## Repository and lifecycle gates

After this written specification is reviewed:

1. Write an implementation plan; do not create code yet.
2. Obtain explicit implementation-plan approval.
3. Only then create `/Users/guilhermecastro/repos/araihu/dex-operator` and initialize Git.
4. Before the first commit, verify exact AraiHu author identity and conventions from current neighboring repositories rather than copying homelab identity.
5. Implement and verify the minimum working operator.
6. Ask before creating `github.com/araihu/dex-operator` or pushing anywhere because repository visibility is unspecified.

Green local tests do not authorize publication, deployment, release, image publication, or homelab changes.

## Acceptance criteria

- Three namespaced `v1alpha1` CRDs reconcile through real Dex gRPC.
- Users support provided bcrypt hashes, generated passwords, deterministic omitted user IDs, MFA inventory/reset/removal, adoption, drift correction, retention, and deletion.
- Clients support the approved field subset, provided/generated secrets, explicit disruptive rotation, adoption, drift correction, retention, and deletion.
- Connectors support opaque Secret JSON plus common grant-type restrictions, adoption, drift correction, retention, and deletion.
- Production gRPC is cert-manager-shaped mTLS; insecure mode is loopback-only.
- Exact Dex compatibility mismatch blocks mutation.
- No operator path accesses PostgreSQL, CNPG APIs, Dex tables, or Dex Kubernetes-storage CRDs.
- Testcontainers integration uses real pinned Dex with memory/SQLite, never a Dex mock.
- Secret material is absent from logs, events, metrics labels, traces, and status.
- Home-lab remains unchanged until separately authorized.
