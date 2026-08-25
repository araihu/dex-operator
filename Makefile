.PHONY: generate verify-generated test envtest build-test-dex test-integration race build docker-build verify

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

build-test-dex:
	./hack/build-test-dex.sh

test-integration: build-test-dex
	GOWORK=off go test -tags=integration ./test/integration -count=1 -v

race:
	GOWORK=off go test -race ./... -count=1

build:
	mkdir -p bin
	GOWORK=off go build -trimpath -o bin/manager ./cmd

docker-build:
	docker build -t dex-operator:local .

verify: verify-generated test race
	GOWORK=off go vet ./...
	$(MAKE) build
	git diff --check
