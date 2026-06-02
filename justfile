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
        "totp" | "magic_link" | "oauth" | "otp" | "storage_backends" | "passkey_demo")
            echo "Running $name_clean example..."
            cargo run --example "$name_clean" -p wasi-auth-core --all-features
            ;;
        "leptos_auth_demo" | "leptos_auth_demo_passkey" | "leptos_auth_demo_passkeys" | "leptos-auth-demo")
            echo "Compiling interceptor & demo to wasm32-wasip2..."
            cargo build -p wasi-auth-interceptor --target wasm32-wasip2
            cargo build -p leptos-auth-demo --target wasm32-wasip2 --features passkey
            cargo build -p mock-auth-server

            if ! command -v wac &> /dev/null; then
                echo "Error: 'wac' tool is not installed. Please run 'cargo install wac-cli'."
                exit 1
            fi
            if ! command -v wasmtime &> /dev/null; then
                echo "Error: 'wasmtime' tool is not installed. Please download it from https://wasmtime.dev/."
                exit 1
            fi

            echo "Composing components..."
            wac plug \
              target/wasm32-wasip2/debug/wasi_auth_interceptor.wasm \
              --plug target/wasm32-wasip2/debug/leptos_auth_demo.wasm \
              -o target/composed_demo.wasm

            echo "Starting mock auth server on port 8080..."
            target/debug/mock-auth-server 8080 &
            MOCK_PID=$!

            cleanup() {
                echo "Stopping mock auth server (PID $MOCK_PID)..."
                kill $MOCK_PID 2>/dev/null || true
            }
            trap cleanup EXIT

            echo "Serving composed app on http://127.0.0.1:8080 via wasmtime..."
            # Setup JWT config using default key pair of leptos-auth-demo
            mkdir -p target
            echo "            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+avXn8b3RyMHN52c7j3b
            iIbH/M4W5wFDQQHH9XKtTdreQvDb3tmmFAXuYEIZxbNZcYnugzQEWQVpz5xVeJ9o
            sSCfN1aScK6aRA+gsXF6hTMGQt9OBUpPlGDYZAjmjnNa8WYKRvsmA9MEfp93iach
            Je96m5W73Is7+ktevEOQiJkKdJ/uEVwdC6/OypYTh4bhNSbG+cAXMTie9iJTyqRF
            P/Vy1eIWWAJDM/Xj+IPah/EZOca015Ubf6lw8BxEycHBJkLjok2bjootPLLfrP9e
            yPvt4oKW4RoGm0iscmHopoxwKMH3myEAR0cq081lVOE1BgQvZTTH/KSszfhRImGP
            IQIDAQAB
            -----END PUBLIC KEY-----" | sed 's/^[[:space:]]*//' > target/public_key_demo.pem
            export JWT_PUBLIC_KEY="$(cat target/public_key_demo.pem)"
            export JWT_AUDIENCE="client-id-123"
            export JWT_ISSUER="leptos-auth-demo"

            wasmtime serve target/composed_demo.wasm \
              --addr 127.0.0.1:8080 \
              -S inherit-network=y \
              -S cli=y \
              -S inherit-env=y
            ;;
        *)
            echo "Error: Example '${name_clean}' not found."
            echo "Available examples: totp, magic_link, oauth, otp, storage_backends, passkey_demo, leptos-auth-demo"
            exit 1
            ;;
    esac
