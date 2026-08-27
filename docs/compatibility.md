# Dex compatibility

The operator intentionally supports one reviewed Dex build contract and one exact runtime compatibility gate. It fails closed before every mutation when the runtime values or required capabilities differ.

| Component | Supported value |
|---|---|
| AraiHu Dex overlay commit | `92f1cd0f2beccb87613d211b7b19125d57039494` |
| Upstream Dex source commit | `ab64ed778070e983cbb10cfc07ea4bb397d14312` |
| Dex server version | `v2.46.0-20260806171424-ab64ed77+araihu.password-profile.v1` |
| Go API module | `github.com/araihu/dex/api/v2 v2.0.0-20260827142126-92f1cd0f2bec` |
| Numeric gRPC API | `4` |

The operator does not receive or inspect the Dex image reference and imposes no registry or repository allowlist. Helm/GitOps may configure a build from any registry or repository, but must configure a syntactically valid, digest-pinned OCI image reference and verify signed image provenance against the reviewed source commit above.

The verified `linux/amd64` handoff image for the supported contract is `ghcr.io/araihu/dex:sha-92f1cd0f2beccb87613d211b7b19125d57039494@sha256:e56eefe5a0aa1f2f9b614465f1cbd4ad84ffde34618400ea1d6ce16dc670debc`. Image identity does not replace runtime compatibility checks: the connected server must report the exact server and numeric API versions above and expose the required capabilities. The source commits and Go API module are review/build provenance inputs that gRPC cannot prove, so provenance verification is a mandatory GitOps boundary. Integration also fixes the official upstream image `ghcr.io/dexidp/dex@sha256:af9469509350ff3f6ca70127175a58e5ab085b9d18740fa4a590d9f03f0a026b` and requires `ServerVersionMismatch` in both crossed directions: old gate/new Dex and new gate/upstream Dex.

Dex must enable:

- `DEX_API_CONNECTORS_CRUD=true`;
- `DEX_API_SESSIONS_IDENTITIES_CRUD=true`.

Dex also needs `DEX_SESSIONS_ENABLED=true` when its Helm-owned configuration enables TOTP or WebAuthn. MFA authenticators and each client's effective MFA chain remain Dex configuration, not operator fields.

`DEX_EXPECTED_SERVER_VERSION` must equal the server value above. The readiness gate calls `GetVersion`, `ListConnectors`, and `ListUserIdentities`; any mismatch, disabled capability, or unavailable call blocks reconciliation mutations.

This API tuple exposes `post_logout_redirect_uris` on client create/get/list/update. Non-empty changes use `UpdateClient`. A repeated protobuf field cannot preserve explicit presence for an empty list, while the pinned server updates this field only when it receives a non-nil slice. The operator therefore uses delete/recreate when removing all post-logout redirects; this preserves the configured client secret but briefly interrupts client authentication.

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

## Local-user attribute boundary

The AraiHu API additively exposes `name`, `preferred_username`, optional `email_verified`, and `groups` on password create/list/update. `DexLocalUser` claims each field independently only after it appears in spec. Omitted fields on old or newly adopted CRs remain unmanaged and preserve remote data. Once claimed, an explicit zero or later field removal clears the remote value and ownership remains in `status.managedProfileFields`, so restart and later drift still converge.

Dex emits these values on local-password login. With `DEX_SESSIONS_ENABLED=true`, refresh tokens preserve the identity cached at login; profile changes require a new login to reach new tokens. With sessions disabled, the pinned Dex refresh implementation invokes the local connector from inside its refresh-token storage update while that connector rereads the password record, so live post-login profile reload is not part of this supported contract. The integration suite proves login claims and session-backed refresh claims without simulating storage behavior.

Blocking and disabling remain unsupported. The identity API's `blocked_until` observation is not a declarative account-disable mutation, so the operator does not expose it, invent arbitrary claims, or write Dex storage directly.
