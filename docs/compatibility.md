# Dex compatibility

The operator intentionally supports one reviewed Dex tuple. It fails closed before every mutation when the tuple or required capabilities differ.

| Component | Supported value |
|---|---|
| Dex source commit | `ab64ed778070e983cbb10cfc07ea4bb397d14312` |
| Dex server version | `v2.46.0-20260806171424-ab64ed77` |
| Go API module | `github.com/dexidp/dex/api/v2 v2.4.1-0.20260806151424-ab64ed778070` |
| Numeric gRPC API | `4` |

The Dex image must be built from that commit and supplied to the Helm/GitOps-owned Dex Deployment as an explicit image override. This project creates only the local test image `dex-operator-test-dex:ab64ed778070`; it does not publish a deployable Dex image.

Dex must enable:

- `DEX_API_CONNECTORS_CRUD=true`;
- `DEX_API_SESSIONS_IDENTITIES_CRUD=true`.

Dex also needs `DEX_SESSIONS_ENABLED=true` when its Helm-owned configuration enables TOTP or WebAuthn. MFA authenticators and each client's effective MFA chain remain Dex configuration, not operator fields.

`DEX_EXPECTED_SERVER_VERSION` must equal the server value above. The readiness gate calls `GetVersion`, `ListConnectors`, and `ListUserIdentities`; any mismatch, disabled capability, or unavailable call blocks reconciliation mutations.

## Upgrade checklist

1. Select and record an immutable Dex commit and image digest.
2. Review the upstream `api/v2` schema and server implementations for every RPC used by the operator.
3. Confirm the numeric API version, server version string, feature-flag names, disabled-error behavior, and MFA/login behavior.
4. Update the API module, supported server constant, test-image builder, and this document together.
5. Regenerate code and run unit, race, vet, build, real-Dex reconciliation, restart, TOTP, and WebAuthn tests.
6. Review Dex storage migration and rollback notes. Dex/Helm owns migrations; the operator never touches tables.
7. Take and verify the Git, Kubernetes/etcd, and CNPG backups described in [backup and recovery](backup-recovery.md).
8. Exercise the exact image/config against a restored non-production database before changing GitOps.

Do not widen compatibility to a version range without repeating the API and behavioral review for every admitted version.
