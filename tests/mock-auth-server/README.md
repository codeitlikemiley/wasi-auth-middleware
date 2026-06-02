# Mock Auth Server

A mock authentication and utility server written in Rust, designed to support local development and end-to-end (E2E) integration testing.

## Purpose

The Mock Auth Server simulates:
1. **OAuth2 / OIDC Flow**: Mock implementations of `/authorize`, `/token`, and `/userinfo` endpoints, including PKCE simulation and ID token signing.
2. **JWKS Key Hosting**: Exposes JSON Web Key Sets (JWKS) via standard endpoints (`/jwks` and `/.well-known/jwks.json`) to verify JWT tokens cryptographically.
3. **Mock Email Sink / SMTP Simulator**: Intercepts email transmissions and registers them in an in-memory inbox, facilitating programmatic verification of verification codes (OTPs) and magic link URLs.
4. **Behavioral Injections**: Exposes control endpoints to simulate failure conditions like network latency, dropouts, signature key invalidation, and OIDC error scenarios.

## Layout

- `src/main.rs`: Main binary entrypoint that reads port settings and routes flows.
- `src/app.rs`: Main server logic containing:
  - TCP connection handling and basic HTTP request parser.
  - State management for sent emails, active mock keys, and behavior configurations.
  - RSA key generation routines and JSON Web Key construction.
  - Endpoints logic.
  - Comprehensive unit tests covering every mock route.
- `Cargo.toml`: Declares required dependencies (e.g., `jsonwebtoken`, `serde`, `chrono`, `base64`).

## Configuration

The server can be configured dynamically:
- **Port Selection**: Reads the first command-line argument, the `PORT` environment variable, or the `MOCK_AUTH_PORT` environment variable. Defaults to `8080`.
- **Runtime Behavior**: Send a `POST /mock/configure-behavior` request with a JSON body representing the `MockBehavior` struct:
  ```json
  {
    "jwks_key_rotation": false,
    "signature_key_invalid": false,
    "oidc_error": null,
    "latency_ms": 50,
    "network_dropout": false
  }
  ```

## How to Run & Use

Compile and run the server on the host:
```bash
# Build the binary
cargo build -p mock-auth-server

# Run on port 8080 (default)
./target/debug/mock-auth-server 8080
```

### Key Endpoints

- `GET /jwks` or `GET /.well-known/jwks.json`: Retrieves active JWK set.
- `GET /authorize`: Simulates OIDC auth redirect.
- `POST /token`: Exchanges authorization codes for a signed mock JWT.
- `GET /userinfo`: Returns mock claims matching the OIDC specification.
- `POST /email/send`: Intercepts outgoing email payload and extracts OTPs.
- `GET /email/inbox?to=<email>`: Queries intercepted emails for verification.
- `DELETE /email/inbox`: Clears the mock inbox.
