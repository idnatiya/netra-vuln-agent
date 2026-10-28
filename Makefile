VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
TRIVY_VERSION ?= 0.72.0

.DEFAULT_GOAL := help
.PHONY: help test build-linux npm-pack deploy

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

deploy: ## Update vuln-agent on VMs over SSH: make deploy HOSTS="user@vm1 vm2"
	@test -n "$(HOSTS)" || { echo 'usage: make deploy HOSTS="user@vm1 vm2"'; exit 2; }
	@$(MAKE) --no-print-directory build-linux
	@for h in $(HOSTS); do \
		m=$$(ssh $$h uname -m) || exit 1; \
		case $$m in x86_64) a=amd64;; aarch64|arm64) a=arm64;; *) echo "$$h: unsupported arch $$m"; exit 1;; esac; \
		echo "==> $$h ($$a)"; \
		scp -q dist/vuln-agent-linux-$$a $$h:vuln-agent.new || exit 1; \
		ssh -t $$h 'sudo ./vuln-agent.new install; rc=$$?; rm -f vuln-agent.new; vuln-agent version; exit $$rc' || exit 1; \
	done
