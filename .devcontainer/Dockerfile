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

# Setup Go environment directories with proper permissions
RUN echo "Setting up Go environment directories..." && \
    mkdir -p /go && \
    chmod 777 /go && \
    mkdir -p /go/bin && \
    echo "Go environment directories created with proper permissions"

# Install additional tools for Go development
RUN echo "Installing Go development tools..." && \
    export GOPATH=/go && \
    CGO_ENABLED=1 go install golang.org/x/tools/gopls@latest && \
    CGO_ENABLED=1 go install github.com/go-delve/delve/cmd/dlv@latest && \
    CGO_ENABLED=0 go install honnef.co/go/tools/cmd/staticcheck@latest && \
    CGO_ENABLED=0 go install golang.org/x/tools/cmd/goimports@latest && \
    echo "Installing golangci-lint (may take longer)..." && \
    (CGO_ENABLED=0 go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest || \
     echo "Warning: golangci-lint installation failed, will be available for manual install") && \
    echo "Go tools installation completed"

# Configure Go environment variables for all users
ENV GOPATH="/go"
ENV PATH="/usr/local/go/bin:/go/bin:${PATH}"

# Create symbolic links for VS Code compatibility (fallback for user installations)
RUN echo "Setting up VS Code Go tools compatibility..." && \
    mkdir -p /go/bin && \
    echo "#!/bin/bash" > /usr/local/bin/setup-go-tools && \
    echo "# Setup Go tools for user session" >> /usr/local/bin/setup-go-tools && \
    echo "if [ -d \"\$HOME/go/bin\" ]; then" >> /usr/local/bin/setup-go-tools && \
    echo "  export PATH=\"\$PATH:\$HOME/go/bin\"" >> /usr/local/bin/setup-go-tools && \
    echo "  for tool in gopls golangci-lint dlv staticcheck goimports; do" >> /usr/local/bin/setup-go-tools && \
    echo "    if [ -f \"\$HOME/go/bin/\$tool\" ] && [ ! -f \"/go/bin/\$tool\" ]; then" >> /usr/local/bin/setup-go-tools && \
    echo "      ln -sf \"\$HOME/go/bin/\$tool\" \"/go/bin/\$tool\" 2>/dev/null || true" >> /usr/local/bin/setup-go-tools && \
    echo "    fi" >> /usr/local/bin/setup-go-tools && \
    echo "  done" >> /usr/local/bin/setup-go-tools && \
    echo "fi" >> /usr/local/bin/setup-go-tools && \
    chmod +x /usr/local/bin/setup-go-tools && \
    echo "Go tools compatibility script created"

# Set working directory
WORKDIR /workspaces/secrets
