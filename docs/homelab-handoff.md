# Homelab integration handoff

This is a future, approval-gated mapping. No `home-lab` file was changed and no cluster was queried or mutated. A verified Dex image reference is recorded below, but selecting it for the homelab and rolling it out remain separate actions.

## Ownership

Helm/GitOps must continue to own the Dex Deployment, Service, issuer/config, image override, PostgreSQL storage block, gRPC listener, MFA authenticators/chains, certificates, NetworkPolicies, probes, and rollout annotations. It also owns the operator installation and ordering.

The operator owns only supported dynamic Dex records represented by its CRs, generated credential Secrets, CR status, and finalizers. It does not provision CNPG, receive the Dex database credentials, touch Dex tables, or own Dex configuration/Deployment.

## Placeholder mapping

When integration is separately authorized, map Dex PostgreSQL configuration to:

- write host: `<dex-cnpg-cluster>-rw`;
- application credentials: existing CNPG-generated `<dex-db-app-secret>`;
- database/name/SSL fields: values already owned by that Secret and the CNPG integration contract.

Do not teach the operator these values and do not grant it access to the application Secret. Select the actual cluster and Secret only during the homelab change review.

GitOps may select a Dex build from any registry or repository; the operator has no registry or repository allowlist. GitOps must configure a syntactically valid, digest-pinned OCI reference and verify signed image provenance against the reviewed source commit. The verified `linux/amd64` default candidate for the current compatibility tuple is `ghcr.io/araihu/dex:v0.0.1@sha256:d9ff9b6c2eccd1b59f2c082e61b07fbdc9df4279ad69cf5db19d2b2d51918d23`.

Regardless of image identity, Dex must report the exact server/API tuple described in [compatibility](compatibility.md), with `DEX_API_CONNECTORS_CRUD=true`, `DEX_API_SESSIONS_IDENTITIES_CRUD=true`, and `DEX_SESSIONS_ENABLED=true` when MFA is enabled.

The operator client certificate Secret must have cert-manager keys `ca.crt`, `tls.crt`, and `tls.key`; the configured gRPC server name must exactly match the server certificate. Add Reloader/checksum ownership so Dex and operator restart on the certificate/config Secret changes they consume.

## Suggested Argo ordering

1. Existing CNPG cluster, application Secret, and successful restore evidence.
2. Dex certificate/config Secrets and NetworkPolicies.
3. Dex Deployment/Service with PostgreSQL storage; wait for database migration, OIDC readiness, and gRPC compatibility.
4. Operator CRDs, RBAC, TLS Secret, and Deployment; wait for readiness.
5. Dynamic `DexConnector`, `DexOAuth2Client`, and `DexLocalUser` resources.

For existing confidential clients, use `providedSecretRef` during initial adoption when the current secret must remain authoritative. For operator-generated clients, select `clientIDKey` and `clientSecretKey` to match each consumer's existing Secret contract; omitted fields preserve the legacy `clientSecret`-only shape. Moving a legacy generated Secret to configured keys preserves the client secret; later key loss fails closed, while `rotationNonce` authorizes replacement.

Current `DexLocalUser` resources cannot replace Zitadel-managed full name, preferred username, verified-email, groups, or disabled state. The pinned Dex gRPC password API does not expose those storage fields for mutation. Keep any consumer migration depending on those claims blocked until Dex and this operator receive the API extension documented in [compatibility](compatibility.md).

Before step 5, remove matching connectors, clients, and local users from static Dex configuration and finish the Dex rollout. Never let static and dynamic ownership overlap. Use sync waves/health gates so a transient rollout cannot cause premature adoption or deletion.

## Integration review checklist

- Replace every `.invalid` address and fake Secret name in the generic manifests.
- Select syntactically valid, immutable operator and Dex image references pinned by digest, and verify the Dex image's signed provenance against the reviewed source commit.
- Narrow egress/ingress with the policy in [security](security.md).
- Review cluster-wide Secret RBAC and who may create each CRD.
- Confirm Git, Kubernetes/etcd, and CNPG backup/restore coverage.
- Stage one non-critical resource per kind, then test drift, deletion policy, login, client authentication, connector behavior, and MFA reset.
- Document the break-glass finalizer procedure and its orphaning consequences.

Do not deploy, publish images, create releases, or edit `home-lab` from this handoff alone.
