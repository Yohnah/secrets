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
ARG GO_VERSION=1.25.2
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
    chown -R 1000:1000 /go && \
    echo "Go environment directories created with proper permissions"

# Configure Go environment variables for all users
ENV GOPATH="/go"
ENV PATH="/usr/local/go/bin:/go/bin:${PATH}"

# Install Task (Taskfile) before using it
RUN sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin

RUN mkdir -p /go/tmp_build

# Copy Taskfile and tools for development environment setup
#COPY Taskfile.yml /go/tmp_build/Taskfile.yml
#COPY tools /go/tmp_build/tools
#COPY go/go.mod /go/tmp_build/go.mod
#COPY go/go.sum /go/tmp_build/go.sum
#
## Install Go development tools using Taskfile
#RUN cd /go/tmp_build && \
#    task prepare-development-environment && \
#    rm -rf /tmp/Taskfile.yml /tmp/tools /go/tmp_build

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

# Fix Go module cache permissions automatically on container start
RUN echo "Creating permission fix script..." && \
    echo "#!/bin/bash" > /usr/local/bin/fix-go-permissions && \
    echo "# Fix Go module cache and bin permissions" >> /usr/local/bin/fix-go-permissions && \
    echo "if [ -d /go/pkg ]; then" >> /usr/local/bin/fix-go-permissions && \
    echo "  sudo chown -R vscode:vscode /go/pkg /go/bin 2>/dev/null || true" >> /usr/local/bin/fix-go-permissions && \
    echo "fi" >> /usr/local/bin/fix-go-permissions && \
    chmod +x /usr/local/bin/fix-go-permissions && \
    echo "Permission fix script created"

# Set working directory
WORKDIR /workspaces/secrets
