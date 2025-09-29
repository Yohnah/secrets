# Secrets

A multiplatform and multi-architecture application for secrets management.

## Project Structure

This repository is organized by languages and technologies to facilitate polyglot development:

```
.
├── go/                     # Main Go application
│   ├── cmd/               # Entry points
│   ├── internal/          # Private Go code
│   ├── pkg/               # Public Go libraries
│   ├── api/               # API definitions
│   ├── go.mod             # Go module
│   └── .golangci.yml      # Go linting configuration
├── python/                # Future Python tools (scripts, CLI)
├── rust/                  # Future Rust components (critical performance)
├── web/                   # Web frontend (React, Vue, etc.)
├── docs/                  # General project documentation
├── configs/               # General configurations
├── deployments/           # IaC, Docker, Kubernetes, etc.
├── scripts/               # Cross-platform automation scripts
├── test/                  # Integration and e2e tests
└── examples/              # Usage examples
```

## Technologies

### 🟢 Currently Implemented
- **Go**: Main application, APIs, core services

### 🟡 Planned
- **Python**: Automation scripts, development tools
- **Rust**: High-performance components, native libraries
- **JavaScript/TypeScript**: Web frontend, development tools
- **Shell**: Deployment and automation scripts

## Development

### Prerequisites

- VS Code with Dev Containers extension
- Docker

### Environment Setup

1. Open the project in VS Code
2. When VS Code detects the devcontainer, click "Reopen in Container"
3. The container will automatically build with Go and all necessary tools

### Main Commands

```bash
# Go application
make build              # Build Go application
make build-all         # Cross-platform build
make test              # Go tests
make lint              # Go linting

# General development
make help              # See all available commands
```

## Project Components

### Go (`/go`)
- **Main application**: Secrets management, APIs, services
- **Platforms**: Linux, macOS, Windows (amd64, arm64)
- **Features**: CLI, HTTP server, secure storage

### Future Extensions

- **Python (`/python`)**: Automation scripts, development tools
- **Rust (`/rust`)**: Performance-critical components, native libraries
- **Web (`/web`)**: Web interface, dashboard, visual configuration

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Go Core       │    │   Extensions    │
│   (Web/CLI)     │────│   Application   │────│   (Python/Rust) │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Deployments   │
                    │  (Docker/K8s)   │
                    └─────────────────┘
```

## Contributing

1. Fork the project
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Develop in the appropriate language directory
4. Ensure all tests pass
5. Commit your changes (`git commit -am 'Add new feature'`)
6. Push to the branch (`git push origin feature/new-feature`)
7. Open a Pull Request

## License

[MIT](LICENSE)
