#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
dex_sha=b02ead0ba87a320f3328c6860ea45f5b6314e6bd
dex_api_version=v2.4.1-0.20261026140406-b02ead0ba87a
dex_server_version=v2.47.0-20261026150406-b02ead0b

grep -F "const SupportedServerVersion = \"$dex_server_version\"" "$repository_dir/internal/config/config.go" >/dev/null
grep -F "github.com/dexidp/dex/api/v2 $dex_api_version" "$repository_dir/go.mod" >/dev/null

docker buildx build --load \
	--progress=plain \
	--build-arg "VERSION=$dex_server_version" \
	--tag dex-operator-test-dex:b02ead0ba87a \
	"https://github.com/dexidp/dex.git?ref=$dex_sha"
