# E2E Runner

An integration test orchestrator that automates compilation, composition, deployment, and testing of the WASI Authentication Middleware stack.

## Purpose

The E2E Runner acts as a test harness that verifies the interaction of all middleware components under realistic deployment scenarios. It programmatically manages:
1. **Compilation**: Compiles WASI components (`leptos-auth-demo` and `wasi-auth-interceptor`) to `wasm32-wasip2`, as well as the host-native `mock-auth-server`.
2. **Composition**: Plugs the interceptor gateway onto the Leptos application using the WebAssembly Composition CLI (`wac`).
3. **Port Allocation**: Dynamically requests unused TCP ports to avoid address conflicts.
4. **Lifecycle Coordination**: Spawns and manages background processes (e.g., Wasmtime server, mock OAuth server, SMTP/email sink) and cleans them up using RAII guards (`ChildGuard`, `TempFileGuard`).
5. **Flow Verification**: Executes a suite of 11 integration tests covering:
   - Web application sanity (200 OK checks).
   - Mock email OTP extraction and verification.
   - Dynamic key rotation and JWKS endpoint synchronization.
   - Gateway security error propagation (401 JSON payloads for API routes, 302 redirects for page routes).
   - Validation edge cases (expired tokens, signature mismatches, missing keys, storage/database failures).

## Layout

- `src/main.rs`: Launches the main asynchronous tokio engine.
- `src/app.rs`: Orchestrator source containing:
  - Process management guards (`ChildGuard`, `TempFileGuard`).
  - Compilation helpers (`compile_targets`, `compose_components`).
  - The E2E test client (`run_e2e_tests`) that issues HTTP requests via `reqwest` to verify the active routes.
  - Crate tests containing composition variation evaluations.
- `Cargo.toml`: Defines dependencies such as `reqwest`, `tokio`, `anyhow`, and workspace paths.

## How to Run & Use

Prerequisites:
- `wasmtime` CLI installed on your path.
- `wac` and `wasm-tools` binaries installed.

Execute the test suite from the repository root:
```bash
cargo run -p e2e-runner
```

To run the internal crate test harness:
```bash
cargo test -p e2e-runner
```
