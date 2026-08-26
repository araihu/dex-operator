# Dex compatibility

The operator intentionally supports one reviewed Dex build contract and one exact runtime compatibility gate. It fails closed before every mutation when the runtime values or required capabilities differ.

| Component | Supported value |
|---|---|
| Dex source commit | `ab64ed778070e983cbb10cfc07ea4bb397d14312` |
| Dex server version | `v2.46.0-20260806171424-ab64ed77` |
| Go API module | `github.com/dexidp/dex/api/v2 v2.4.1-0.20260806151424-ab64ed778070` |
| Numeric gRPC API | `4` |

The operator does not receive or inspect the Dex image reference and imposes no registry or repository allowlist. Helm/GitOps may configure a build from any registry or repository, but must configure a syntactically valid, digest-pinned OCI image reference and verify signed image provenance against the reviewed source commit above.

The verified `linux/amd64` handoff image for the supported contract is `ghcr.io/araihu/dex:v0.0.1@sha256:d9ff9b6c2eccd1b59f2c082e61b07fbdc9df4279ad69cf5db19d2b2d51918d23`. Image identity does not replace runtime compatibility checks: the connected server must report the exact server and numeric API versions above and expose the required capabilities. The source commit and Go API module are review/build provenance inputs that gRPC cannot prove, so provenance verification is a mandatory GitOps boundary. This project also creates the local-only test image `dex-operator-test-dex:ab64ed778070`.

Dex must enable:

- `DEX_API_CONNECTORS_CRUD=true`;
- `DEX_API_SESSIONS_IDENTITIES_CRUD=true`.

Dex also needs `DEX_SESSIONS_ENABLED=true` when its Helm-owned configuration enables TOTP or WebAuthn. MFA authenticators and each client's effective MFA chain remain Dex configuration, not operator fields.

`DEX_EXPECTED_SERVER_VERSION` must equal the server value above. The readiness gate calls `GetVersion`, `ListConnectors`, and `ListUserIdentities`; any mismatch, disabled capability, or unavailable call blocks reconciliation mutations.

## Upgrade checklist

1. Select a syntactically valid, digest-pinned OCI image reference, record its immutable digest and Dex source commit, and verify signed provenance connects them.
2. Review the upstream `api/v2` schema and server implementations for every RPC used by the operator.
3. Confirm the numeric API version, server version string, feature-flag names, disabled-error behavior, and MFA/login behavior.
4. Update the API module, supported server constant, test-image builder, and this document together.
5. Regenerate code and run unit, race, vet, build, real-Dex reconciliation, restart, TOTP, and WebAuthn tests.
6. Review Dex storage migration and rollback notes. Dex/Helm owns migrations; the operator never touches tables.
7. Take and verify the Git, Kubernetes/etcd, and CNPG backups described in [backup and recovery](backup-recovery.md).
8. Exercise the exact image/config against a restored non-production database before changing GitOps.

Do not widen compatibility to a version range without repeating the API and behavioral review for every admitted version.
