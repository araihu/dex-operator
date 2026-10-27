# Dex compatibility

The operator intentionally supports one reviewed Dex build contract and one exact runtime compatibility gate. It fails closed before every mutation when the runtime values or required capabilities differ.

| Component | Supported value |
|---|---|
| Dex source commit | `b02ead0ba87a320f3328c6860ea45f5b6314e6bd` |
| Dex server version | `v2.47.0-20261026150406-b02ead0b` |
| Go API module | `github.com/dexidp/dex/api/v2 v2.4.1-0.20261026140406-b02ead0ba87a` |
| Numeric gRPC API | `4` |

The operator does not receive or inspect the Dex image reference and imposes no registry or repository allowlist. Helm/GitOps may configure a build from any registry or repository, but must configure a syntactically valid, digest-pinned OCI image reference and verify signed image provenance against the reviewed source commit above.

The verified official base for this contract is `ghcr.io/dexidp/dex:master@sha256:3cea00341c073adcf45b6f8ae9d3c26e5e1201316e3a5793c9129d8373f7bee6`. Its Cosign signature and SLSA provenance bind it to the reviewed source commit above. The image's OCI version label is `master`, while `dex version` reports the exact server version in the table. The AraiHu overlay records that runtime version separately in its source lock and embeds it when rebuilding Dex.

No AraiHu release image has been published for this updated contract. The previous `ghcr.io/araihu/dex:v0.0.1` image belongs to the older August contract and will fail this operator's version gate. This project creates the local-only test image `dex-operator-test-dex:b02ead0ba87a`.

Image identity does not replace runtime compatibility checks: the connected server must report the exact server and numeric API versions above and expose the required capabilities. Source commit and Go API module are review/build provenance inputs that gRPC cannot prove, so provenance verification remains a mandatory GitOps boundary.

## Changes reviewed for the October update

The API adds `Password.groups` and `UpdatePasswordReq.new_groups`; the numeric API remains `4`. The operator continues managing its existing user fields. Omitting `new_groups` preserves existing groups during username/password updates. Connector/session RPCs and their feature-flag gates retain their previous contract. Authentication templates and the WebAuthn inline script are unchanged.

The SQL migration inventory is unchanged from the August source commit; the added API fields expose existing password groups. Dex remains responsible for opening and migrating storage. Keep the backup and restored non-production validation steps below for rollout and rollback.

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
