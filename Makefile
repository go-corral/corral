# corral — Makefile
#
# GOTOOLCHAIN=local avoids silently fetching a different toolchain than the one
# installed; CGO off builds a static binary. No GOPATH redirect is needed: inside the
# dev sandbox the cache provider points GOMODCACHE/GOCACHE at the writable ~/.cache/corral,
# and on a bare host the default GOPATH is writable — so the default works everywhere.

export GOTOOLCHAIN := local
export CGO_ENABLED := 0

GO       ?= go
VALE     ?= vale
BIN_DIR  := bin
BIN      := $(BIN_DIR)/corral
PKG      := ./...
# Strip the leading "v" so the binary reports bare semver (e.g. 0.1.0), matching the
# released binary (GoReleaser stamps {{ .Version }}, which is also v-stripped). The
# git tag still carries the "v" (Go's module convention); only the reported string is bare.
# Strip via sed, not the shell's "$${v#v}": make 3.81 (macOS default) treats the '#'
# inside a $(shell ...) call as a comment and fails to parse the line.
VERSION  ?= $(shell v=$$(git describe --tags --always --dirty 2>/dev/null || echo dev); echo "$$v" | sed 's/^v//')
LDFLAGS  := -s -w -X main.version=$(VERSION)

.PHONY: all build test test-update lint vale vale-sync vet fmt tidy clean run help

all: build

build: ## Build the corral binary into ./bin
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/corral

test: ## Run all tests
	$(GO) test $(PKG)

test-update: ## Regenerate golden files (only packages that define a -update flag)
	@pkgs=$$(git grep -lF 'flag.Bool("update"' -- '*_test.go' | xargs -n1 dirname | sort -u | sed 's|^|./|'); \
	 [ -n "$$pkgs" ] || { echo "test-update: no golden packages found"; exit 1; }; \
	 echo "regenerating goldens in:"; echo "$$pkgs" | sed 's/^/  /'; \
	 $(GO) test $$pkgs -run . -update

lint: ## Run golangci-lint (skips only when not installed; fails on findings)
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed; skipping"; \
	fi

vale-sync: ## Download the pinned Vale style packages
	@command -v $(VALE) >/dev/null 2>&1 || { echo "vale not installed"; exit 1; }
	$(VALE) sync

vale: vale-sync ## Lint maintained prose and source comments
	VALE=$(VALE) sh scripts/lint-vale.sh

vet: ## go vet
	$(GO) vet $(PKG)

fmt: ## gofmt -w
	$(GO) fmt $(PKG)

tidy: ## go mod tidy
	$(GO) mod tidy

clean: ## Remove build artifacts (keeps the module cache)
	rm -rf $(BIN_DIR) dist

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n", $$1, $$2}'
