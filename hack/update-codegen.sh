#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)

cd "$repository_dir"
GOWORK=off go tool controller-gen object:headerFile=hack/boilerplate.go.txt paths=./api/...
GOWORK=off go tool controller-gen crd:crdVersions=v1 paths=./api/... output:crd:artifacts:config=config/crd/bases
GOWORK=off go tool controller-gen rbac:roleName=manager-role paths=./... output:rbac:artifacts:config=config/rbac
GOWORK=off go generate ./internal/config
perl -0pi -e 's/\n+\z/\n/' docs/configuration.md
