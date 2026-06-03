# WASI Auth Middleware

A modular, WebAssembly-compatible (WASI Preview 2) authentication framework for Rust. 
Provides JWT session management, OAuth2/OIDC client logic, email OTP flows, and a composable HTTP proxy middleware — all targeting `wasm32-wasip2`.

---

## Core Features Highlight

- **WebAssembly-Native Cryptography**: Native token signing/verifying targeting WASI Preview 2 (`wasm32-wasip2`) without relying on unsafe external JavaScript runtimes.
- **Pluggable Component Middleware**: A standalone proxy component (`wasi-auth-interceptor`) that can be plugged in front of any downstream WASI HTTP handler via standard component composition.
- **Comprehensive Auth Protocols**: Built-in support for passwordless authentication, OAuth2/OIDC presets, TOTP Multi-Factor Authentication, and WebAuthn (Passkeys).
- **Leptos Integration**: Pre-built Leptos middleware, routing guards, and styled, responsive UI auth components ready for Server-Side Rendering (SSR) and client-side hydration.

---

## Prerequisites Summary

To compile and run components in this workspace, you need:

| Prerequisite | Recommended Version |
|---|---|
| Rust Edition | `2024` |
| Rust Stable Channel | ≥ 1.93.0 |
| WASI Target | `wasm32-wasip2` |

```bash
# Add the WASI target
rustup target add wasm32-wasip2
```

For more details on CLI tool setups (e.g., `Wasmtime`, `wac-cli`, `wasm-tools`, `just`), see the [Getting Started](docs/getting_started.md) guide.

---

## Documentation Directory

Explore the sub-guides to integrate and configure the auth framework:

* 📖 **[Getting Started](docs/getting_started.md)**: Step-by-step setup, compilation instructions, Wasmtime execution, and comprehensive use-case tutorials (standalone proxy composition, Leptos Library and Gateway modes, custom storage adapters, and TOTP/Magic Link integration).
* 🏗️ **[Architecture](docs/architecture.md)**: High-level system topology, request lifecycle flow, Mermaid sequence diagrams, workspace crate breakdown, security boundaries, and MFA/WebAuthn flow designs.
* ⚙️ **[Configuration Reference](docs/configuration.md)**: Complete guide to environment variables, TOML config file formats (`wasi-auth.toml`), cookie precedence priorities, rate-limiter defaults, and OAuth2 client presets.

---

## Testing & Contribution

We welcome contributions! Please verify your changes before opening a pull request:

```bash
# Run all checks, tests, cargo clippy, and formatting validations:
just check
```

Make sure all code changes compile cleanly, meet standard formatting conventions, and contain corresponding tests.

---

## Issues & Vulnerabilities

- **Bug Reports**: If you find a bug, please search existing issues or open a new one on GitHub with reproduction steps.
- **Security Vulnerabilities**: For security concerns or vulnerability reports, please do not file a public issue. Instead, report them securely following our security disclosure policy (e.g., emailing the maintainers directly or using GitHub private vulnerability reporting if enabled).

---

## License

This project is dual-licensed under:
- **MIT License**
- **Apache License, Version 2.0**
