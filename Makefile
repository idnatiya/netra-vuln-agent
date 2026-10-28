VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
TRIVY_VERSION ?= 0.72.0

.DEFAULT_GOAL := help
.PHONY: help test build-linux npm-pack

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_\/-]+:.*## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: ## Vet + unit tests
	go vet ./...
	go test ./...

build-linux: ## Build vuln-agent for linux amd64 + arm64 into dist/
	@for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath \
			-ldflags "-s -w -X main.version=$(VERSION) -X main.trivyVersion=$(TRIVY_VERSION)" \
			-o dist/vuln-agent-linux-$$arch ./cmd/vuln-agent || exit 1; \
	done

npm-pack: ## Build both binaries at package.json's version and pack the npm tarball
	$(MAKE) build-linux VERSION=v$$(node -p "require('./package.json').version")
	npm pack
