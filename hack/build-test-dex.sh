#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
dex_sha=ab64ed778070e983cbb10cfc07ea4bb397d14312
dex_api_version=v2.4.1-0.20260806151424-ab64ed778070
dex_server_version=v2.46.0-20260806171424-ab64ed77

grep -F "const SupportedServerVersion = \"$dex_server_version\"" "$repository_dir/internal/config/config.go" >/dev/null
grep -F "github.com/dexidp/dex/api/v2 $dex_api_version" "$repository_dir/go.mod" >/dev/null

docker buildx build --load \
	--progress=plain \
	--build-arg "VERSION=$dex_server_version" \
	--tag dex-operator-test-dex:ab64ed778070 \
	"https://github.com/dexidp/dex.git?ref=$dex_sha"
