VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
ANSIBLE_DIR := deploy/ansible

.DEFAULT_GOAL := help
.PHONY: help test build-linux fakecentral deploy-dev scan-dev

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_\/-]+:.*## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: ## Vet + unit tests
	go vet ./...
	go test ./...

build-linux: ## Build vuln-agent for linux amd64 + arm64 into dist/
	@for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath \
			-ldflags "-s -w -X main.version=$(VERSION)" \
			-o dist/vuln-agent-linux-$$arch ./cmd/vuln-agent || exit 1; \
	done

fakecentral: ## Stand-in central that logs payloads, e.g. make fakecentral ARGS=-fail-reports
	go run ./deploy/dev/fakecentral $(ARGS)

# --- Sample VM (Ansible) -----------------------------------------------------

deploy-dev: build-linux ## Install the agent on the dev inventory (enrolls when central_url is set)
	cd $(ANSIBLE_DIR) && ansible-playbook site.yml $(ARGS)

scan-dev: build-linux ## deploy-dev + run one scan
	cd $(ANSIBLE_DIR) && ansible-playbook site.yml -e vuln_agent_run_scan=true $(ARGS)
