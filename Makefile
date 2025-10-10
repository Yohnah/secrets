# Variables
APP_NAME := secrets

# Version detection: use semantic versioning git tags if available, otherwise development version
# Only consider tags that match semantic versioning pattern (v0.0.0, v1.2.3, etc.)
GIT_TAG := $(shell git describe --tags --exact-match 2>/dev/null | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' || echo "")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_DIRTY := $(shell git diff --quiet 2>/dev/null || echo "-dirty")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

# Version logic (following semantic versioning):
# - If on exact semantic version git tag: use tag (e.g., v1.2.3)
# - If development: use v0.1.0-dev+YYYYMMDD.commit
# - If dirty: add -dirty suffix
ifdef GIT_TAG
    VERSION := $(GIT_TAG)$(GIT_DIRTY)
else
    VERSION := v0.1.0-dev+$(shell date -u '+%Y%m%d').$(GIT_COMMIT)$(GIT_DIRTY)
endif

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod

# Build flags
LDFLAGS := -X 'main.Version=$(VERSION)' -X 'main.BuildTime=$(BUILD_TIME)' -X 'main.GitCommit=$(GIT_COMMIT)'
BUILD_FLAGS := -ldflags "$(LDFLAGS)" -trimpath

# Directorios
GO_DIR := ./go
SRC_DIR := ./cmd/$(APP_NAME)
BIN_DIR := ./bin
DIST_DIR := ./dist

# Targets for all platforms
PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64

##@ Development Commands

# Default target
.PHONY: default
default: help ## Show help (default target)

# Build the application
.PHONY: build
build: deps ## Build the secrets binary for current platform
	@echo "Building $(APP_NAME) for current platform..."
	@mkdir -p $(BIN_DIR)
	cd $(GO_DIR) && $(GOBUILD) $(BUILD_FLAGS) -o ../$(BIN_DIR)/$(APP_NAME) $(SRC_DIR)
	@echo "Binary built successfully: $(BIN_DIR)/$(APP_NAME)"

# Install dependencies
.PHONY: deps
deps: 
	@echo "Installing Go dependencies..."
	cd $(GO_DIR) && $(GOMOD) download
	cd $(GO_DIR) && $(GOMOD) tidy
	@echo "Installing development tools..."
	@which richgo >/dev/null 2>&1 || (echo "Installing richgo..." && $(GOCMD) install github.com/kyoh86/richgo@latest)
	@if [ -f "$$HOME/go/bin/richgo" ] && [ ! -f "/usr/local/bin/richgo" ]; then \
		sudo ln -sf $$HOME/go/bin/richgo /usr/local/bin/richgo; \
	fi
	@echo "Dependencies installed successfully"

# Run tests with verbose output for debugging and colored output
.PHONY: tests
tests: ## Run all tests with verbose output and colors
	@echo "Running all tests..."
	@cd $(GO_DIR) && go test -v ./... | sed \
		-e 's/^=== RUN.*/\x1b[36m&\x1b[0m/' \
		-e 's/^--- PASS.*/\x1b[32m&\x1b[0m/' \
		-e 's/^--- FAIL.*/\x1b[31m&\x1b[0m/' \
		-e 's/^PASS$$/\x1b[32;1m&\x1b[0m/' \
		-e 's/^FAIL.*/\x1b[31;1m&\x1b[0m/' \
		-e 's/^ok .*/\x1b[32m&\x1b[0m/' \
		-e 's/^\?.*\[no test files\]/\x1b[90m&\x1b[0m/' \
		|| (printf "\033[31m✗ Tests failed\033[0m\n" && exit 1)
	@echo ""
	@printf "\033[32;1m✓ All tests completed successfully\033[0m\n"

.PHONY: clean
clean: ## Clean test artifacts, temporary files and binaries
	@echo "Cleaning test artifacts and binaries..."
	@rm -rf .trash/*
	@rm -rf $(BIN_DIR)/*
	@rm -rf $(DIST_DIR)/*
	@echo "Artifacts cleaned"

# Build for all platforms
.PHONY: build-all
build-all: deps ## Build binaries for all supported platforms
	@echo "Building $(APP_NAME) for all platforms..."
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		OS=$$(echo $$platform | cut -d'/' -f1); \
		ARCH=$$(echo $$platform | cut -d'/' -f2); \
		OUTPUT_NAME=$(APP_NAME); \
		if [ $$OS = "windows" ]; then OUTPUT_NAME=$$OUTPUT_NAME.exe; fi; \
		echo "Building for $$OS/$$ARCH..."; \
		cd $(GO_DIR) && GOOS=$$OS GOARCH=$$ARCH $(GOBUILD) $(BUILD_FLAGS) -o ../$(DIST_DIR)/$(APP_NAME)-$$OS-$$ARCH/$$OUTPUT_NAME $(SRC_DIR); \
	done
	@echo "All binaries built successfully in $(DIST_DIR)/"

##@ Help

# Show help
.PHONY: help
help: ## Show available commands with descriptions
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)