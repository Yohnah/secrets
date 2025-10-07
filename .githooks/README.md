# Git Hooks

This directory contains custom Git hooks for the secrets project.

## Setup

The hooks are automatically configured if you have set up the project correctly. To manually configure:

```bash
git config core.hooksPath .githooks
```

## Available Hooks

### pre-commit

Runs before each commit and performs the following checks:

- Runs all Go tests (`go test ./...`)
- Runs vulnerability check (`govulncheck ./...`)
- Runs static analysis (`go vet ./...`)

If any check fails, the commit is aborted.

## Testing Hooks

You can test hooks manually:

```bash
.githooks/pre-commit
```

## Skipping Hooks

In emergency situations, you can skip hooks with:

```bash
git commit --no-verify
```

However, this should only be used when absolutely necessary.