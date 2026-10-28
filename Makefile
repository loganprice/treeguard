BINARY_NAME := treeguard
GO := go
CGO_ENABLED := 1

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X github.com/loganprice/treeguard/internal/version.Version=$(VERSION) \
	-X github.com/loganprice/treeguard/internal/version.Commit=$(COMMIT) \
	-X github.com/loganprice/treeguard/internal/version.Date=$(DATE)

.PHONY: all build test test-fast test-coverage vet lint validate rule-test fmt clean help

all: fmt vet lint test validate rule-test build ## Run formatting, vet, lint, tests, validation, and build

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: ## Build the TreeGuard binary with Cgo
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -ldflags "$(LDFLAGS)" -v -o $(BINARY_NAME) ./cmd/treeguard


test: ## Run unit tests with race detection and atomic coverage
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -v -race -covermode=atomic -coverprofile=coverage.txt ./...

test-fast: ## Run unit tests without race detector
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./...

test-coverage: test ## Run unit tests and generate an HTML coverage report
	$(GO) tool cover -html=coverage.txt -o coverage.html
	@echo "Coverage report written to coverage.html"

vet: ## Run go vet across all packages
	$(GO) vet ./...

lint: ## Run golangci-lint
	golangci-lint run ./...

validate: build ## Validate Rego security rules in rules/
	./$(BINARY_NAME) validate rules/

rule-test: build ## Run fixture tests against rules
	./$(BINARY_NAME) test test/fixtures

fmt: ## Format all Go source files
	$(GO) fmt ./...

clean: ## Remove built binary and test artifacts
	rm -f $(BINARY_NAME) coverage.txt coverage.html audit-report.html
