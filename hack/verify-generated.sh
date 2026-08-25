#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/dex-operator-generated.XXXXXX")
generated_file="$repository_dir/api/v1alpha1/zz_generated.deepcopy.go"

restore() {
	cp "$temporary_dir/zz_generated.deepcopy.go" "$generated_file"
	rm -rf "$temporary_dir"
}
trap restore EXIT HUP INT TERM

cp "$generated_file" "$temporary_dir/zz_generated.deepcopy.go"
cd "$repository_dir"
GOWORK=off go tool controller-gen object:headerFile=hack/boilerplate.go.txt paths=./api/...
cmp "$temporary_dir/zz_generated.deepcopy.go" "$generated_file"

mkdir -p "$temporary_dir/crds" "$temporary_dir/rbac"
GOWORK=off go tool controller-gen crd:crdVersions=v1 paths=./api/... output:crd:artifacts:config="$temporary_dir/crds"
GOWORK=off go tool controller-gen rbac:roleName=manager-role paths=./... output:rbac:artifacts:config="$temporary_dir/rbac"
(
	cd internal/config
	GOFILE=config.go GOLINE=19 GOWORK=off go tool envdoc -files config.go -types Config -output "$temporary_dir/configuration.md"
)
perl -0pi -e 's/\n+\z/\n/' "$temporary_dir/configuration.md"

for name in \
	dex.araihu.com_dexconnectors.yaml \
	dex.araihu.com_dexlocalusers.yaml \
	dex.araihu.com_dexoauth2clients.yaml; do
	cmp "$temporary_dir/crds/$name" "$repository_dir/config/crd/bases/$name"
done
cmp "$temporary_dir/rbac/role.yaml" "$repository_dir/config/rbac/role.yaml"
cmp "$temporary_dir/configuration.md" "$repository_dir/docs/configuration.md"
