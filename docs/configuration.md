# Environment Variables

## Config

Config contains the complete dex-operator runtime environment.

 - `DEX_GRPC_ADDRESS` (**required**, non-empty) - Dex gRPC host and port.
 - `DEX_GRPC_SERVER_NAME` - Certificate name verified by the gRPC TLS client.
 - `DEX_GRPC_INSECURE` (default: `false`) - Allow plaintext gRPC only when every target address is loopback.
 - `DEX_RECONCILE_INTERVAL` (default: `5m`) - Periodic remote-drift reconciliation interval.
 - `DEX_EXPECTED_SERVER_VERSION` (**required**, non-empty) - Exact Dex server version expected by this binary.
