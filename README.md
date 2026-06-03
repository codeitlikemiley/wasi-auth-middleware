# WASI Auth Middleware

A modular, WebAssembly-compatible (WASI Preview 2) authentication framework for Rust.  
JWT session management, OAuth2/OIDC flows, email OTP, TOTP MFA, WebAuthn passkeys, and a composable HTTP proxy middleware — all targeting `wasm32-wasip2`.

---

## Features

- **WebAssembly-Native Crypto** — RSA JWT signing/verifying on `wasm32-wasip2` without external JS runtimes.
- **Composable Proxy Middleware** — `wasi-auth-interceptor` plugs in front of any WASI HTTP handler via `wac plug`.
- **Multi-Protocol Auth** — Passwordless OTP, Magic Links, OAuth2/OIDC presets, TOTP MFA, and WebAuthn Passkeys.
- **Leptos Integration** — Session middleware, routing guards, and premium glassmorphism UI components for SSR/hydration.
- **Pluggable Storage** — Swap in Redis, DynamoDB, SQLite, or Spin KV by implementing the `AuthStorage` trait.

---

## Quick Install

```bash
rustup target add wasm32-wasip2
cargo build --workspace
```

> Requires Rust ≥ 1.93.0, edition `2024`. See [Getting Started](docs/getting_started.md) for full prerequisites.

---

## Documentation

| Guide | What's Inside |
|---|---|
| 📖 [Getting Started](docs/getting_started.md) | Prerequisites, build & serve commands, use-case tutorials (proxy composition, Library/Gateway mode, custom traits, TOTP, Magic Links) |
| 🧩 [UI Components](docs/ui_components.md) | How-to guide for `LoginForm`, `TotpSetup`, `SessionList`, `MfaStatus`, `PasskeyList` — props API + full working examples |
| 🏗️ [Architecture](docs/architecture.md) | System topology, request flow, crate breakdown, security boundaries, MFA/WebAuthn flow designs |
| ⚙️ [Configuration](docs/configuration.md) | Environment variables, `wasi-auth.toml` schema, cookie precedence, rate-limiter defaults, OAuth2 provider presets |

### Crate Documentation

Each crate has its own README with API details:

| Crate | Purpose |
|---|---|
| [`wasi-auth-traits`](wasi-auth-traits/) | Core trait abstractions (`AuthStorage`, `EmailSender`, `RateLimiter`) and storage backends |
| [`wasi-auth-core`](wasi-auth-core/) | JWT engine, OAuth2 client, OTP, TOTP, Magic Links, Passkey WebAuthn |
| [`leptos-wasi-auth`](leptos-wasi-auth/) | Leptos framework integration (session context, guards, cookie helpers) |
| [`leptos-wasi-ui`](leptos-wasi-ui/) | Styled Leptos UI components for auth workflows |
| [`wasi-auth-providers`](wasi-auth-providers/) | OAuth2/OIDC client presets (Google, GitHub, Apple, Discord, etc.) |
| [`wasi-auth-interceptor`](wasi-auth-interceptor/) | Standalone WASI HTTP proxy middleware |

### Example App

The [`examples/leptos-auth-demo`](examples/leptos-auth-demo/) is a full SSR Leptos app demonstrating every auth flow and UI component. Run it with:

```bash
just example
```

---

## Contributing

```bash
# Run formatting, clippy, and tests:
just check
```

All changes must compile cleanly, pass tests, and follow standard formatting.

---

## Issues & Security

- **Bugs** — Search existing issues or open a new one with reproduction steps.
- **Security** — Do not file public issues. Use GitHub private vulnerability reporting or email maintainers directly.

---

## License

Dual-licensed under **MIT** and **Apache 2.0**.
