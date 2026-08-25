# Backup and recovery

Recovery spans three independent planes:

1. **Git**: Dex Helm/GitOps configuration, operator CR desired state, encrypted/provisioned Secret definitions, certificates, ordering, and NetworkPolicies.
2. **Kubernetes/etcd**: CR status/ownership preclaims, finalizers, generated password/client Secrets, and cert-manager Secrets.
3. **CNPG**: Dex's PostgreSQL records, sessions, OAuth state, local password hashes, connector/client state, and MFA material.

CNPG backups do not contain generated password plaintext held only in Kubernetes Secrets. Kubernetes backups do not replace the Dex database. Git alone normally has neither plane's runtime secret material.

## Restore order

1. Restore and verify the existing CNPG cluster using its separately owned procedure.
2. Restore the Dex application Secret and make the existing `<cluster>-rw` Service reachable by Dex.
3. Restore the exact compatible Dex image/configuration and confirm PostgreSQL migrations, OIDC health, gRPC mTLS, and the required feature flags.
4. Restore operator TLS material, CRDs/RBAC/Deployment, generated Secrets, and CRs with their status where possible.
5. Keep dynamic CR creation paused until static Dex resources with the same IDs have been removed.
6. Reconcile one resource class at a time and verify `Compatible=True`, `Ready=True`, and `Drifted=False`.

## Lost state

- **CR status lost, Dex record remains:** ownership is no longer proven. Reconciliation fails with `Conflict`; inspect the external record and set `adoptExisting: true` explicitly. For local users, the requested/resolved user ID must match to preserve `sub`.
- **Generated password Secret lost:** Dex retains only the bcrypt hash; plaintext is unrecoverable. The operator does not extract it from Dex or the database. Set a new rotation nonce to generate and apply a replacement.
- **Generated OAuth2 client Secret lost:** do not copy it from status or logs. Set a new rotation nonce; Dex requires delete/recreate for secret replacement, causing a brief client-authentication interruption.
- **Provided Secret lost:** restore it from its external/GitOps secret source. The operator never becomes the backup source.
- **CNPG restored without Kubernetes state:** recreate desired CRs carefully and use explicit adoption after verifying IDs and values.
- **Kubernetes restored without CNPG state:** the operator can recreate supported Dex records, but sessions/MFA and other Dex-owned database state are not reconstructed from CRs.

After recovery, test login, client authentication, connectors, MFA inventory, and one controlled backup/restore cycle. Do not use direct SQL as a recovery shortcut; Dex alone owns its schema and tables.
