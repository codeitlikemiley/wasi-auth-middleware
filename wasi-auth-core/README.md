# wasi-auth-core

Core cryptographic routines, JWT token issuance/verification, OAuth2/OIDC handlers, and WebAuthn (Passkey) workflows.

This crate provides the core business logic of the authentication system, designed to work seamlessly in both native rust and WASI environments.

## Purpose

To handle:
- **JWT Operations**: Securely mint and verify RS256 tokens, support clock-skew leeway, and manage JWKS public key rotation.
- **OAuth 2.0 / OIDC**: Provide stateless handlers for generating redirect URLs, performing code exchanges, fetching user profiles, and parsing well-known OpenID discovery documents.
- **Passkeys (WebAuthn)**: Handle authentication and registration challenge generation, response verification, and error handling.

## Setup & Dependency Features

Add this to your `Cargo.toml`:

```toml
[dependencies]
wasi-auth-core = { version = "0.1.0", path = "../wasi-auth-core" }
```

### Feature Flags

- **`passkey`** — Enables WebAuthn/Passkey registration and authentication. Integrates the `passkey-server` crate and enables passkey traits in `wasi-auth-traits`.

## Key APIs

### JWT Token Management

- **`generate_jwt`**: Issues a new compact RS256 signed JSON Web Token using a private key (PKCS#8 PEM).
- **`verify_jwt` / `verify_jwt_with_options`**: Validates a token signature, verifies audience/issuer, checks expiration/not-before claims with configurable clock-skew leeway, and deserializes payload claims.
- **`Claims`**: The standard JWT claim structure (`sub`, `iss`, `aud`, `exp`, `iat`, `nbf`, `jti`, `roles`, `name`, `email`).
- **`JwksKeyCache`**: A thread-safe, rate-limiting (cooldown-controlled) cache for caching public keys fetched from an OIDC provider's JWKS (`.well-known/jwks.json`) endpoint.

### OAuth 2.0 / OIDC Client

- **`Oauth2Client`**: A stateless client engine. All I/O is decoupled via the `HttpClient` trait.
  - `generate_auth_url`: Builds the login redirection URL.
  - `exchange_code`: Exchanges the authorization code for a standard `TokenResponse`.
  - `get_user_info`: Fetches user profile attributes from the provider's UserInfo endpoint.
  - `fetch_oidc_config` / `parse_oidc_discovery`: Automatically configures endpoints from OIDC metadata discovery.
- **`PkceChallenge`**: Automatically generates secure code verifiers and SHA-256 code challenges for PKCE (Proof Key for Code Exchange) authorization.

### Passkey (WebAuthn) Module

*Note: Requires the `passkey` feature flag.*

- **`start_passkey_registration`**: Generates challenge options for registering a new credential.
- **`finish_passkey_registration`**: Verifies and records the credential creation response.
- **`start_passkey_login`**: Generates request options for login.
- **`finish_passkey_login`**: Verifies the assertion response and returns the authenticated user's ID.
