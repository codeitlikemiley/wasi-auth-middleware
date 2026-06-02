# Leptos Auth Demo

A reference portal and web application built with the [Leptos](https://github.com/leptos-rs/leptos) framework, compiled for the WASI (`wasm32-wasip2`) target. It showcases the integration of the WASI Authentication Middleware, including both direct integration (Library Mode) and composed integration (Gateway/Proxy Mode).

## Purpose

The demo application serves as a comprehensive reference implementation showing how to:
1. **Manage Sessions**: Securely read and write JWT tokens from browser cookies.
2. **Handle Multi-Factor Authentication (MFA)**: Enroll and verify Time-based One-Time Passwords (TOTP).
3. **Passwordless Authentication**: Request and consume signed magic links and One-Time Passwords (OTP).
4. **OAuth2 / OIDC Integration**: Integrate mock OAuth/OIDC providers (e.g., Google, Github) with PKCE.
5. **Rate Limiting**: Enforce thread-safe rate limits using the `RateLimiter` trait and `InMemoryRateLimiter` on server functions.

## Layout

- `src/lib.rs`: Contains the application definition:
  - **AppState**: Configures in-memory storage, rate limiting, and email sending traits.
  - **Server Functions**: Implement endpoints for requesting and verifying OTP, exchange of OAuth code, logout, request/verify magic links, and TOTP enrollment/login verification.
  - **Leptos Components**: Define routing and views, including `App`, `Home`, `Login`, `Dashboard`, `OAuthCallback`, `MagicCallback`, and `TotpSetup`.
- `src/main.rs`: Simple entrypoint binary that prints a message (the actual logic executes through the server functions called inside the compiled component).
- `Cargo.toml`: Crate configuration, declaring dependencies on `leptos-wasi-auth`, `leptos-wasi-ui`, `wasi-auth-core`, and `wasi-auth-traits`.

## Configuration

The demo utilizes environment variables and in-context structures for configuration:
- `JWT_PUBLIC_KEY`: The PEM-encoded public key used to verify session signatures.
- `JWT_AUDIENCE`: The expected target audience.
- `JWT_ISSUER`: The expected issuer of the JWT.
- Crate Features:
  - `passkey`: Enables Passkey / WebAuthn elements within the Leptos interface.

## How to Run & Use

1. **Build the Demo**:
   Ensure you have the `wasm32-wasip2` target installed:
   ```bash
   rustup target add wasm32-wasip2
   ```
   Build the demo using cargo:
   ```bash
   cargo build --target wasm32-wasip2 -p leptos-auth-demo
   ```

2. **Compose with Interceptor**:
   Use `wac` or `wac-cli` to compose the built component with `wasi-auth-interceptor`:
   ```bash
   wac plug \
     target/wasm32-wasip2/debug/wasi_auth_interceptor.wasm \
     --plug target/wasm32-wasip2/debug/leptos_auth_demo.wasm \
     -o composed_app.wasm
   ```

3. **Serve with Wasmtime**:
   Serve the composed WebAssembly component using Wasmtime:
   ```bash
   wasmtime serve composed_app.wasm \
     --addr 127.0.0.1:8080 \
     -S inherit-network=y \
     -S cli=y \
     -S inherit-env=y \
     --env JWT_PUBLIC_KEY="$(cat public_key.pem)" \
     --env JWT_AUDIENCE="client-id-123" \
     --env JWT_ISSUER="leptos-auth-demo"
   ```
