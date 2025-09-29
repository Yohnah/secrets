# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/devcontainers/base:debian

# Install essential build tools and dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    libc6-dev \
    make \
    pkg-config \
    curl \
    wget \
    git \
    binutils \
    binutils-gold \
    binutils-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Go with version control and update notifications
ARG GO_VERSION=1.21.5
ARG AUTO_UPDATE_GO=false

RUN echo "Checking Go version configuration..." && \
    if [ "$AUTO_UPDATE_GO" = "true" ]; then \
        echo "AUTO_UPDATE_GO enabled - fetching latest Go version..."; \
        LATEST_GO=$(curl -s https://go.dev/VERSION?m=text | head -n1 | sed 's/go//'); \
        echo "Latest Go version available: $LATEST_GO"; \
        GO_VERSION=$LATEST_GO; \
    else \
        echo "Using fixed Go version: $GO_VERSION"; \
        echo "Checking for newer versions..."; \
        LATEST_GO=$(curl -s https://go.dev/VERSION?m=text | head -n1 | sed 's/go//' || echo "unknown"); \
        if [ "$LATEST_GO" != "unknown" ] && [ "$LATEST_GO" != "$GO_VERSION" ]; then \
            echo ""; \
            echo "========================================"; \
            echo "GO VERSION UPDATE AVAILABLE!"; \
            echo "========================================"; \
            echo "Current: $GO_VERSION"; \
            echo "Latest:  $LATEST_GO"; \
            echo ""; \
            echo "To update, change GO_VERSION in Dockerfile"; \
            echo "Or set AUTO_UPDATE_GO=true in devcontainer.json"; \
            echo "========================================"; \
            echo ""; \
        else \
            echo "Go version is up to date!"; \
        fi; \
    fi && \
    echo "Detecting system architecture..." && \
    ARCH=$(dpkg --print-architecture) && \
    echo "Detected architecture: $ARCH" && \
    case $ARCH in \
        amd64) GO_ARCH="amd64" ;; \
        arm64) GO_ARCH="arm64" ;; \
        armhf|armv7l) GO_ARCH="armv6l" ;; \
        *) echo "Unsupported architecture: $ARCH"; exit 1 ;; \
    esac && \
    echo "Downloading Go $GO_VERSION for linux-$GO_ARCH..." && \
    wget -O - https://dl.google.com/go/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz | tar -xzC /usr/local && \
    echo "Go $GO_VERSION installed successfully for $GO_ARCH!"
ENV PATH="/usr/local/go/bin:${PATH}"
# Configure Go to use more stable linker settings for ARM64
ENV CGO_ENABLED=1
ENV GOOS=linux

# Install additional tools for Go development
RUN echo "Installing Go development tools..." && \
    CGO_ENABLED=1 go install golang.org/x/tools/gopls@latest && \
    CGO_ENABLED=1 go install github.com/go-delve/delve/cmd/dlv@latest && \
    CGO_ENABLED=0 go install honnef.co/go/tools/cmd/staticcheck@latest && \
    CGO_ENABLED=0 go install golang.org/x/tools/cmd/goimports@latest && \
    echo "Installing golangci-lint (may take longer)..." && \
    (CGO_ENABLED=0 go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest || \
     echo "Warning: golangci-lint installation failed, will be available for manual install") && \
    echo "Go tools installation completed"

# Set working directory
WORKDIR /workspaces/secrets
