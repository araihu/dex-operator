.PHONY: generate verify-generated test envtest test-integration race build verify

ENVTEST_CACHE ?= .cache/envtest

generate:
	./hack/update-codegen.sh

verify-generated:
	./hack/verify-generated.sh

test:
	GOWORK=off go test ./... -count=1

envtest:
	mkdir -p "$(ENVTEST_CACHE)"
	KUBEBUILDER_ASSETS="$$(GOWORK=off go tool setup-envtest --bin-dir "$(ENVTEST_CACHE)" use 1.36.x -p path)" GOWORK=off go test ./internal/controller -count=1

test-integration:
	GOWORK=off go test -tags=integration ./test/integration -count=1 -v

race:
	GOWORK=off go test -race ./... -count=1

build:
	GOWORK=off go build ./cmd/...

verify: verify-generated test race
	GOWORK=off go vet ./...
	GOWORK=off go build ./cmd/...
	git diff --check
