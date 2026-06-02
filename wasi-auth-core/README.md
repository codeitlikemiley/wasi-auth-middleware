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

## Usage Examples

### 1. Generating and Verifying JWTs (RS256)

`wasi-auth-core` provides a pure-Rust RS256 token signer and verifier using `rsa` and `sha2`:

```rust,ignore
use wasi_auth_core::jwt::{generate_jwt, verify_jwt, Claims};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let private_key_pem = "... your private key PEM ...";
    let public_key_pem = "... your public key PEM ...";

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let claims = Claims {
        sub: "user_12345".to_string(),
        iss: "my-app".to_string(),
        aud: "my-audience".to_string(),
        exp: now + 3600, // 1 hour expiry
        iat: now,
        nbf: now,
        jti: "unique-token-id".to_string(),
        roles: vec!["user".to_string()],
        name: Some("Alice Smith".to_string()),
        email: Some("alice@example.com".to_string()),
    };

    // 1. Generate a signed JWT
    let token = generate_jwt(&claims, private_key_pem)?;
    println!("Issued Token: {}", token);

    // 2. Verify the signed JWT
    let verified_claims = verify_jwt(
        &token,
        public_key_pem,
        "my-audience",
        "my-app"
    )?;
    println!("Token Verified! User ID: {}", verified_claims.sub);
    Ok(())
}
```

### 2. Setting Up TOTP MFA

You can generate and verify Time-based One-Time Passwords (TOTP):

```rust,ignore
use wasi_auth_core::totp::{generate_totp_secret, verify_totp_code, get_totp_qr_uri};

fn main() {
    // 1. Generate a new base32 secret
    let secret = generate_totp_secret();
    println!("User TOTP Secret (Base32): {}", secret);

    // 2. Generate a provisioning URI (for QR codes)
    let qr_uri = get_totp_qr_uri("Alice", "MyCompany", &secret);
    println!("QR Code Provisioning URI: {}", qr_uri);

    // 3. Verify a 6-digit code supplied by the user (with ±1 step leeway)
    let code = "123456"; // code entered by user
    let is_valid = verify_totp_code(&secret, code);
    println!("Is code valid? {}", is_valid);
}
```

### 3. WebAuthn/Passkey Login Ceremony

Using the passkey wrappers to generate challenge options and verify assertion responses:

```rust,ignore
use wasi_auth_core::passkey::{start_passkey_login, finish_passkey_login};
use wasi_auth_traits::PasskeyStore;

fn handle_login_ceremony(
    user_id: &str,
    client_response_json: &str,
    store: &dyn PasskeyStore
) -> Result<String, Box<dyn std::error::Error>> {
    // 1. Start the login ceremony, generating WebAuthn options and challenge
    let login_options = start_passkey_login(
        user_id,
        "my-app.com", // Relying Party ID
        store
    )?;
    
    // Send `login_options` JSON payload to the client/browser...
    
    // 2. Once the client returns the authenticator assertion, verify it
    let verified_user_id = finish_passkey_login(
        "my-app.com",
        "https://my-app.com", // Origin
        client_response_json,
        store
    )?;
    
    Ok(verified_user_id)
}
```
