.PHONY: build test clean pre-commit check-all unit-tests integration-tests lint coverage install-hooks help docgen

# Build variables
BINARY_NAME=aflock
BUILD_DIR=bin
VERSION?=0.1.0

# Go variables
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

# Colors for output
GREEN=\033[0;32m
RED=\033[0;31m
YELLOW=\033[0;33m
NC=\033[0m # No Color

#############################################################################
# CI Guard Rails - Run these before pushing
#############################################################################

# Fast checks for pre-commit (build + unit tests + lint)
pre-commit: build unit-tests lint
	@echo ""
	@echo "$(GREEN)Pre-commit checks passed!$(NC)"

# Full CI checks (everything that runs in GitHub Actions)
check-all: build lint unit-tests integration-tests coverage
	@echo ""
	@echo "$(GREEN)All CI checks passed!$(NC)"

#############################################################################
# Build
#############################################################################

build:
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/aflock
	@echo "$(GREEN)Built $(BUILD_DIR)/$(BINARY_NAME)$(NC)"

build-all:
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/aflock
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/aflock
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/aflock
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/aflock

#############################################################################
# Testing
#############################################################################

# Run all tests
test: unit-tests integration-tests

# Unit tests only (fast)
unit-tests:
	@echo "Running unit tests..."
	$(GOTEST) -v ./internal/... ./pkg/...

# Integration tests (hooks, verify, etc.)
integration-tests: build
	@echo "Running integration tests..."
	$(GOTEST) -v ./test/...

# Test hooks manually (useful for development)
test-hooks: build
	@echo "Testing SessionStart hook..."
	@echo '{"session_id":"test1","cwd":"$(PWD)/test-project"}' | $(BUILD_DIR)/$(BINARY_NAME) hook SessionStart | jq .
	@echo ""
	@echo "Testing PreToolUse (allowed - Read in src/)..."
	@echo '{"session_id":"test1","cwd":"$(PWD)/test-project","tool_name":"Read","tool_use_id":"t1","tool_input":{"file_path":"src/main.go"}}' | $(BUILD_DIR)/$(BINARY_NAME) hook PreToolUse | jq .
	@echo ""
	@echo "Testing PreToolUse (denied - Task tool)..."
	@echo '{"session_id":"test1","cwd":"$(PWD)/test-project","tool_name":"Task","tool_use_id":"t2","tool_input":{"prompt":"test"}}' | $(BUILD_DIR)/$(BINARY_NAME) hook PreToolUse 2>&1 || true
	@echo ""
	@echo "Testing PreToolUse (denied - .env file)..."
	@echo '{"session_id":"test1","cwd":"$(PWD)/test-project","tool_name":"Read","tool_use_id":"t3","tool_input":{"file_path":"src/.env"}}' | $(BUILD_DIR)/$(BINARY_NAME) hook PreToolUse 2>&1 || true
	@echo ""
	@echo "Testing PreToolUse (requires approval - rm command)..."
	@echo '{"session_id":"test1","cwd":"$(PWD)/test-project","tool_name":"Bash","tool_use_id":"t4","tool_input":{"command":"rm -rf /tmp/test"}}' | $(BUILD_DIR)/$(BINARY_NAME) hook PreToolUse | jq .

#############################################################################
# Linting & Coverage
#############################################################################

lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "$(YELLOW)golangci-lint not installed, skipping lint$(NC)"; \
		echo "Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -coverprofile=coverage.out -covermode=atomic ./internal/... ./pkg/...
	@echo ""
	@echo "Coverage by package:"
	@$(GOCMD) tool cover -func=coverage.out | tail -20
	@echo ""
	@total=$$($(GOCMD) tool cover -func=coverage.out | grep total | awk '{print $$3}'); \
	echo "$(GREEN)Total coverage: $$total$(NC)"

#############################################################################
# Git Hooks
#############################################################################

install-hooks:
	@echo "Installing git pre-commit hook..."
	@chmod +x scripts/pre-commit.sh
	@cp scripts/pre-commit.sh .git/hooks/pre-commit
	@echo "$(GREEN)Pre-commit hook installed!$(NC)"
	@echo "Run 'git commit --no-verify' to skip hooks if needed"

#############################################################################
# Cleanup & Utilities
#############################################################################

clean:
	rm -rf $(BUILD_DIR)
	rm -rf plugin/bin
	rm -f coverage.out
	$(GOCMD) clean -cache

tidy:
	$(GOMOD) tidy

#############################################################################
# Documentation Generation
#############################################################################

docgen: ## Generate CLI reference and JSON schemas
	go run ./docgen
	@echo "$(GREEN)Documentation generated in docs/$(NC)"

docgen-verify: ## Verify generated docs are up-to-date (for CI)
	./docgen/verify.sh

#############################################################################
# Plugin Packaging
#############################################################################

plugin: build-all
	@mkdir -p plugin/bin
	cp $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 plugin/bin/
	cp $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 plugin/bin/
	cp $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 plugin/bin/

install: build
	@mkdir -p ~/.claude-plugins/aflock
	cp -r plugin/* ~/.claude-plugins/aflock/
	cp $(BUILD_DIR)/$(BINARY_NAME) ~/.claude-plugins/aflock/bin/aflock-$$(uname -s | tr '[:upper:]' '[:lower:]')-$$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')
	@echo "$(GREEN)Installed aflock plugin to ~/.claude-plugins/aflock$(NC)"

#############################################################################
# Help
#############################################################################

help:
	@echo "aflock - Cryptographically signed policy enforcement for AI agents"
	@echo ""
	@echo "$(YELLOW)CI Guard Rails (run before pushing):$(NC)"
	@echo "  pre-commit     Fast checks: build + unit-tests + lint"
	@echo "  check-all      Full CI: build + lint + all tests + coverage"
	@echo ""
	@echo "$(YELLOW)Build:$(NC)"
	@echo "  build          Build the aflock binary"
	@echo "  build-all      Build for all platforms"
	@echo ""
	@echo "$(YELLOW)Testing:$(NC)"
	@echo "  test           Run all tests"
	@echo "  unit-tests     Run unit tests only (fast)"
	@echo "  integration-tests  Run integration tests"
	@echo "  test-hooks     Test hooks manually with sample JSON"
	@echo ""
	@echo "$(YELLOW)Quality:$(NC)"
	@echo "  lint           Run golangci-lint"
	@echo "  coverage       Run tests with coverage report"
	@echo ""
	@echo "$(YELLOW)Setup:$(NC)"
	@echo "  install-hooks  Install git pre-commit hook"
	@echo "  tidy           Tidy go modules"
	@echo ""
	@echo "$(YELLOW)Packaging:$(NC)"
	@echo "  plugin         Package plugin binaries"
	@echo "  install        Install plugin locally"
	@echo ""
	@echo "$(YELLOW)Cleanup:$(NC)"
	@echo "  clean          Clean build artifacts"
