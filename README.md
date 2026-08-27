# dex-operator

`dex-operator` is a small, management-only Kubernetes operator for selected Dex resources. It reconciles namespaced `DexLocalUser`, `DexOAuth2Client`, and `DexConnector` resources through Dex's supported gRPC API.

Dex's Deployment, configuration, PostgreSQL storage, certificates, NetworkPolicy, and rollout remain Helm/GitOps-owned. The operator does not provision CloudNativePG, receive PostgreSQL credentials, access Dex tables, reconcile Dex storage CRDs, or own the Dex runtime.

## Supported API

The MVP exposes `dex.araihu.com/v1alpha1` resources for:

- local users with provided bcrypt hashes or one-time generated passwords;
- TOTP/WebAuthn inventory, reset, and device removal for local users;
- public or confidential OAuth2 clients, including post-logout redirects, generated consumer-ready Secrets, and explicit secret rotation;
- connectors with opaque JSON configuration read from a same-namespace Secret.

Passwords, client secrets, connector configuration, TLS keys, TOTP seeds, and WebAuthn keys never belong in CR status. See [security](docs/security.md), [compatibility](docs/compatibility.md), and [backup/recovery](docs/backup-recovery.md) before integration.

## Local development

Prerequisites are Go 1.26, Docker, and network access for the first dependency and pinned Dex-source fetch.

```sh
GOWORK=off go test ./... -count=1
GOWORK=off go test -race ./... -count=1
./hack/build-test-dex.sh
GOWORK=off go test -tags=integration ./test/integration -count=1 -v
```

The integration suite builds the exact reviewed Dex commit into the local-only image `dex-operator-test-dex:ab64ed778070`. The WebAuthn test uses a digest-pinned headless Chrome image. Neither image is pushed or published by this project.

Build the operator image locally with:

```sh
make docker-build
```

The generic manager manifest also uses `dex-operator:local` and deliberately contains `.invalid` Dex placeholders. It is not a deploy-ready homelab manifest.

## CR examples

Secret-free examples live under [`config/samples`](config/samples). Referenced Secret names are intentionally fake and the examples do not inline secret data. Generated credentials are written only to the named Secret.

Generated OAuth2 client Secrets preserve the legacy `clientSecret`-only shape by default. Set `clientIDKey` to also write the non-secret client ID and `clientSecretKey` to rename the generated secret key. Common mappings are:

| Consumer | `clientIDKey` | `clientSecretKey` |
|---|---|---|
| Envoy | `client-id` | `client-secret` |
| Argo CD | `clientID` | `clientSecret` |
| Forgejo | `key` | `secret` |
| Generic environment import | `OIDC_CLIENT_ID` | `OIDC_CLIENT_SECRET` |

Adding configured keys to a legacy `clientSecret` Secret rewrites the owned Secret without rotating the Dex client secret. Later removal or corruption of the configured secret key fails closed. Changing `rotationNonce` generates a new secret and recreates the Dex client. `providedSecretRef` remains the migration path when an existing client secret must be retained.

`postLogoutRedirectURIs` declares the browser destinations accepted after RP-initiated logout. Generated Secrets also accept a `labels` string map. The operator updates and removes only labels declared through that field, preserves unrelated labels, and does not expose arbitrary annotations, owner references, finalizers, or data templating.

Runtime environment variables and defaults are generated in [configuration](docs/configuration.md). The future, approval-gated homelab wiring is documented in [homelab handoff](docs/homelab-handoff.md).

## Project status

This repository is local only. No GitHub repository, registry image, release, deployment, or homelab integration is created by this implementation.
