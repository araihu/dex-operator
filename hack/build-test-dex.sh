#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
araihu_api_version=v2.0.0-20260827142126-92f1cd0f2bec
araihu_server_version=v2.46.0-20260806171424-ab64ed77+araihu.password-profile.v1
araihu_image=ghcr.io/araihu/dex@sha256:e56eefe5a0aa1f2f9b614465f1cbd4ad84ffde34618400ea1d6ce16dc670debc
upstream_image=ghcr.io/dexidp/dex@sha256:af9469509350ff3f6ca70127175a58e5ab085b9d18740fa4a590d9f03f0a026b

grep -F "const SupportedServerVersion = \"$araihu_server_version\"" "$repository_dir/internal/config/config.go" >/dev/null
grep -F "github.com/araihu/dex/api/v2 $araihu_api_version" "$repository_dir/go.mod" >/dev/null

docker pull --platform linux/amd64 "$araihu_image"
docker pull --platform linux/amd64 "$upstream_image"
