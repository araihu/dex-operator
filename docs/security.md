# Security boundary

The operator is a management client of one Dex instance. It does not own the Dex Deployment/configuration, provision CloudNativePG, receive PostgreSQL credentials, access Dex tables, or reconcile Dex's internal Kubernetes-storage CRDs.

## Dex transport

Production gRPC uses mutual TLS. The fixed mount `/var/run/dex-operator/tls` must come from a cert-manager-shaped Secret containing:

- `ca.crt`: CA that issued the Dex gRPC server certificate;
- `tls.crt`: operator client certificate accepted by Dex;
- `tls.key`: operator client private key.

`DEX_GRPC_SERVER_NAME` must exactly match a DNS SAN on the Dex server certificate. Missing/invalid files or verification failures stop startup; there is no plaintext fallback. `DEX_GRPC_INSECURE=true` is accepted only for loopback test targets.

The generic manifest names `dex-operator-grpc-client-tls` and uses `.invalid` Dex addresses. Integration must replace them through GitOps. Certificate renewal does not hot-reload the gRPC client: the Dex and operator rollouts remain GitOps-owned, and the live setup should use Reloader (or an equivalent checksum rollout) to restart the affected Deployment when its certificate Secret changes.

## Kubernetes permissions

One cluster-wide manager watches namespaced CRs in all namespaces. Kubernetes RBAC cannot restrict Secret reads to only names referenced by CRs, so the manager ClusterRole has cluster-wide Secret CRUD/watch permissions. This is a material trust boundary.

The code enforces same-namespace references, indexes Secrets by exact name, and creates generated Secrets in the CR namespace. It never accepts a Secret namespace field. Namespace tenants able to create these CRs can cause the operator to read a Secret in their own namespace; access to CR creation and Secret creation must therefore be governed together.

The manager runs as non-root with a read-only root filesystem, RuntimeDefault seccomp, no privilege escalation, and all Linux capabilities dropped. The TLS mount is read-only.

## Network policy

The integration owner should supply a default-deny policy plus narrowly scoped allowances for:

- Kubernetes API egress;
- DNS egress where cluster DNS is required;
- Dex gRPC egress on its exact Service/port;
- health/metrics ingress only from approved probes and monitoring namespaces.

The operator needs no PostgreSQL, CNPG API, Dex HTTP/login, or general internet egress in production.

## Secret handling

Passwords, bcrypt hashes, OAuth2 client secrets, connector JSON, TLS keys, TOTP enrollment URIs/seeds, and WebAuthn private/public keys are prohibited from status, conditions, Events, metric labels, traces, and logs. Errors use operation names and resource identifiers only. MFA status intentionally exposes credential IDs and non-secret device metadata so removal can be declared.

`DexLocalUser.status.managedProfileFields` contains only field names. It persists declarative ownership so old/adopted CRs preserve omitted remote profile values while previously claimed fields continue to clear and correct drift after restarts; it never stores profile values or credentials.

Generated credentials change only when a new rotation nonce authorizes it. Moving a legacy generated OAuth2 client Secret from `clientSecret` to configured data keys or adding declarative labels preserves the Dex secret; these are layout/metadata changes, not credential rotation. The operator records its managed label keys in an internal annotation, removes only previously managed keys omitted from the CR, and preserves other labels. Invalid labels or malformed internal ownership metadata fail closed. The CR does not expose arbitrary annotations, owner references, finalizers, or data templating. Later key loss or credential edits in an operator-owned generated Secret fail closed. If a previously converged confidential client is absent from Dex, recovery requires the input Secret resource version and recorded managed key to still prove the last credential; the operator may then apply a configured layout-only patch. A changed provided Secret, promotion of divergent previously unmanaged data, or simultaneous loss of Dex and its generated Secret requires a new rotation nonce. Losing generated password plaintext also fails closed until a new nonce authorizes replacement.

## Static/dynamic ownership and deletion

A connector, local password, or OAuth2 client must not exist in Dex static configuration and an operator CR at the same time. Remove the static entry and complete the Dex rollout before enabling the matching dynamic CR, or use explicit `adoptExisting` only after verifying the external identity.

`Delete` finalizers keep a CR terminating while Dex is unavailable rather than silently orphaning the remote record. Emergency manual finalizer removal is a break-glass action: it abandons remote cleanup, may leave generated Secrets or Dex records, and requires later inventory plus explicit adoption or manual gRPC cleanup.
