# Project: WASI Authentication & Middleware Framework

## Architecture
The framework is designed as a modular, WebAssembly-compatible (WASI Preview 2/3) authentication suite for Rust. It consists of the following components:
1. `wasi-auth-traits`: Defines abstractions for storage (`AuthStorage`) and email delivery (`EmailSender`). Includes in-memory, Spin KV, and SQLite storage backends, and stdout/HTTP email senders.
2. `wasi-auth-core`: The central engine containing cryptographic utils, Session JWT validation, Email OTP generation/validation, and OAuth2 handshake logic.
3. `leptos-wasi-auth`: Integrates core traits and validation into the `leptos_wasi` routing and server functions model.
4. `wasi-auth-interceptor`: A standalone WASI HTTP proxy component exporting `wasi:http/incoming-handler@0.2.9` and importing `wasi:http/incoming-handler@0.2.9` (as `next-handler`). Intercepts requests, validates sessions, injects headers (`X-User-Id`, `X-User-Roles`, `X-User-Email`, `X-User-Name`), and forwards to the next handler, or redirects/denies.
5. `examples/leptos-auth-demo`: An example counter-like Leptos app that consumes the auth SDK and serves as an integration target.
6. `tests/mock-auth-server`: A mock OAuth2 server to respond to code exchange and JWKS requests.

Data flows from client requests through either the standalone interceptor or the Leptos framework, checking session state against an `AuthStorage` backend, or redirecting to mock/real providers.

```
Request ---> [wasi-auth-interceptor] (inspects cookie/JWT)
                      |
                      v (if valid)
             [leptos-auth-demo] (extracts X-User-Id context)
```

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|--------------|--------|
| 1 | Workspace Init & Mock Server | Create workspace Cargo.toml, mock server stub, verify compilation targets | None | DONE |
| 2 | WASI Auth Traits | Define `AuthStorage` and `EmailSender` traits, implement memory, Spin, SQLite, and stdout/HTTP backends | M1 | DONE |
| 3 | WASI Auth Core Engine | Implement JWT sessions, OAuth2 client handlers, and Email OTP engine | M2 | DONE |
| 4 | Leptos Integration | Implement session extractors, protected routing contexts, and server function guards | M3 | DONE |
| 5 | Standalone Interceptor | Build WASI HTTP proxy component exporting and importing incoming-handler | M3 | DONE |
| 6 | Example App | Build Leptos auth demo utilizing components, login pages, and dashboard | M4, M5 | DONE |
| 7 | Final E2E Integration | Run entire test suite (Tiers 1-4) and perform Phase 2 adversarial coverage hardening | M6, E2E | DONE |

## Interface Contracts
### AuthStorage Trait
```rust
pub trait AuthStorage {
    fn store_session(&self, session_id: &str, user_id: &str, roles: &[String], expires_at: u64) -> Result<(), AuthError>;
    fn get_session(&self, session_id: &str) -> Result<Option<Session>, AuthError>;
    fn delete_session(&self, session_id: &str) -> Result<(), AuthError>;
    fn store_otp(&self, email: &str, otp: &str, expires_at: u64) -> Result<(), AuthError>;
    fn verify_otp(&self, email: &str, otp: &str) -> Result<bool, AuthError>;
}
```

### EmailSender Trait
```rust
pub trait EmailSender {
    fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), AuthError>;
}
```

## Code Layout
- `Cargo.toml` — Workspace configuration
- `wasi-auth-traits/`
  - `Cargo.toml`
  - `src/lib.rs` — Trait definitions (`AuthStorage`, `EmailSender`)
  - `src/in_memory.rs` — In-memory storage backend
  - `src/spin_kv.rs` — Spin KV storage backend
  - `src/sqlite.rs` — SQLite storage backend
  - `src/stdout_email.rs` — Stdout email sender
  - `src/http_email.rs` — HTTP email sender
- `wasi-auth-core/`
  - `Cargo.toml`
  - `src/lib.rs` — Re-exports
  - `src/jwt.rs` — RS256 JWT generation and verification
  - `src/oauth.rs` — OAuth2/OIDC client
  - `src/otp.rs` — Email OTP engine
- `leptos-wasi-auth/`
  - `Cargo.toml`
  - `src/lib.rs` — Session extraction, context, and guards
- `wasi-auth-interceptor/`
  - `Cargo.toml`
  - `src/lib.rs` — WASI HTTP proxy middleware
  - `wit/world.wit` — WIT world definition
  - `wit/deps/` — WASI interface dependencies
- `examples/leptos-auth-demo/`
  - `Cargo.toml`
  - `src/lib.rs` — Leptos SSR app with OTP/OAuth login
  - `src/main.rs` — Entry point
- `tests/mock-auth-server/`
  - `Cargo.toml`
  - `src/main.rs` — Entry point
  - `src/app.rs` — Mock OAuth2 & email HTTP server
- `tests/e2e-runner/`
  - `Cargo.toml`
  - `src/main.rs` — Entry point
  - `src/app.rs` — E2E test orchestrator
