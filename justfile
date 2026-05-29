# List all available commands
default:
    @just --list

# List all available commands
help:
    @just --list

# Run formatting, clippy lint checks, and unit/integration tests
check:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test --workspace --all-features

# Bump version and tag across the workspace. By default, auto-bumps patch version. Override by passing version (e.g., just version 0.1.1).
version new_version="":
    @rustc scripts/bump-version.rs -o scripts/bump-version
    @scripts/bump-version "{{new_version}}"
    @rm scripts/bump-version

# Run a specific core example (e.g. `just example totp`, `just example magic_link`, `just example oauth`)
example name:
    #!/usr/bin/env bash
    set -euo pipefail
    # Normalize dashes to underscores
    name_clean=$(echo "{{name}}" | tr '-' '_')
    case "$name_clean" in
        "totp" | "magic_link" | "oauth")
            echo "Running $name_clean example..."
            cargo run --example "$name_clean" -p wasi-auth-core
            ;;
        *)
            echo "Error: Example '${name_clean}' not found."
            echo "Available examples: totp, magic_link, oauth"
            exit 1
            ;;
    esac
