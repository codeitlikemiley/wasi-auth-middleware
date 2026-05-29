# WASI Authentication Middleware — Comprehensive Usage Guides

This document provides step-by-step instructions and production-grade code examples for integrating, customizing, and deploying the `wasi-auth` framework across different scenarios.

---

## Table of Contents
1. [Use Case 1: Standalone Proxy Composition (`wasi-auth-interceptor`)](#use-case-1-standalone-proxy-composition)
2. [Use Case 2: Leptos Direct Integration (Library Mode)](#use-case-2-leptos-direct-integration-library-mode)
3. [Use Case 3: Leptos Proxy Integration (Gateway Mode)](#use-case-3-leptos-proxy-integration-gateway-mode)
4. [Use Case 4: Implementing Custom Traits (Storage & Email)](#use-case-4-implementing-custom-traits)
5. [Use Case 5: Multi-Factor Authentication (TOTP) & Magic Links](#use-case-5-multi-factor-authentication-totp--magic-links)

---

## Use Case 1: Standalone Proxy Composition

The standalone `wasi-auth-interceptor` acts as an authentication gateway proxy, exporting and importing `wasi:http/incoming-handler@0.2.9`. It sits in front of your application component, strips client-injected headers, cryptographically validates the JWT session, injects verified identity headers, and forwards requests.

```text
Request (Browser) ---> [wasi-auth-interceptor] (inspects cookie/JWT)
                                |
                   (if valid)   v (injects X-User-Id)
                       [Your Web App (e.g. Leptos)]
```

### 1. Configure the Interceptor
You can configure path bypasses and redirection rules using a `wasi-auth.toml` file in the working directory:

```toml
[auth]
# Paths bypassing authentication checks (supports suffix wildcards)
public_paths = [
    "/",
    "/login",
    "/signup",
    "/static/*",
    "/pkg/*"
]
# Path to redirect unauthenticated GET requests to
login_redirect = "/login"

[jwt]
# Expected claims
audience = "my-application"
issuer = "https://auth.example.com"
```

### 2. Build the Interceptor and Your App
Ensure the WASI compilation target is installed:
```bash
rustup target add wasm32-wasip2
```

Build both components:
```bash
# Build interceptor
cargo build -p wasi-auth-interceptor --target wasm32-wasip2 --release

# Build your downstream component (e.g., leptos-auth-demo)
cargo build -p leptos-auth-demo --target wasm32-wasip2 --release
```

### 3. Link and Compose Components
Use `wac-cli` to compose the interceptor with your web app:
```bash
wac plug \
  target/wasm32-wasip2/release/wasi_auth_interceptor.wasm \
  --plug target/wasm32-wasip2/release/leptos_auth_demo.wasm \
  -o composed_app.wasm
```

### 4. Serve the Composed Component
Run the composed application under Wasmtime, passing key config values as environment variables:
```bash
wasmtime serve composed_app.wasm \
  --addr 127.0.0.1:8080 \
  --wasi inherit-network \
  --env JWT_PUBLIC_KEY="$(cat public_key.pem)" \
  --env JWT_AUDIENCE="my-application" \
  --env JWT_ISSUER="https://auth.example.com"
```

---

## Use Case 2: Leptos Direct Integration (Library Mode)

In Library Mode, your Leptos application is directly responsible for extracting the JWT session from incoming cookies or headers and verifying the signature in-process using public keys or a dynamic JWKS cache.

### Server-Side Session Extraction
Inside a Leptos server function or SSR route handler, call `extract_session_from_parts_with_options` to parse and validate the request:

```rust
use leptos::prelude::*;
use leptos_wasi_auth::{
    extract_session_from_parts_with_options,
    CookieOptions, SameSite, build_set_cookie_header
};
use wasi_auth_core::jwt::ValidationOptions;

#[server(LoginUser, "/api")]
pub async fn login_user(email: String, secret_otp: String) -> Result<bool, ServerFnError> {
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("State missing"))?;
    
    // 1. Verify OTP against DB
    let is_valid = state.storage.verify_otp(&email, &secret_otp)
        .map_err(|e| ServerFnError::new(format!("Storage error: {:?}", e)))?;
        
    if !is_valid {
        return Err(ServerFnError::new("Invalid OTP code"));
    }

    // 2. Issue a JWT Session
    let claims = wasi_auth_core::jwt::Claims {
        sub: email.clone(),
        iss: "my-app-issuer".to_string(),
        aud: "my-app-audience".to_string(),
        exp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600, // 1 hour expiry
        iat: 0,
        nbf: None,
        jti: None,
        roles: vec!["user".to_string()],
        name: Some(email.split('@').next().unwrap_or("User").to_string()),
        email: Some(email),
    };

    let token = wasi_auth_core::jwt::generate_jwt(&claims, &state.private_key_pem, Some("key-v1"))
        .map_err(|e| ServerFnError::new(format!("Crypto error: {:?}", e)))?;

    // 3. Register session in database
    state.storage.store_session(&token, &claims.sub, &claims.roles, claims.exp)
        .map_err(|e| ServerFnError::new(format!("Storage error: {:?}", e)))?;

    // 4. Inject Set-Cookie Header into the Response
    if let Some(resp_opts) = use_context::<leptos_wasi::response::ResponseOptions>() {
        let cookie_opts = CookieOptions {
            name: "__Host-jwt".to_string(),
            http_only: true,
            secure: true,
            same_site: SameSite::Lax,
            path: "/".to_string(),
            max_age_secs: Some(3600),
        };
        let cookie_value = build_set_cookie_header(&token, &cookie_opts);
        resp_opts.insert_header(
            http::header::SET_COOKIE,
            http::HeaderValue::from_str(&cookie_value).unwrap(),
        );
    }

    Ok(true)
}
```

### Accessing Session in Route Handlers
Extract user session context in routing logic:

```rust
#[component]
pub fn Dashboard() -> impl IntoView {
    // Session context is provided globally in SSR / Hydration flow
    let session = use_context::<leptos_wasi_auth::UserSession>();
    
    view! {
        <div>
            {match session {
                Some(s) => view! {
                    <h1>"Welcome back, " {s.name.clone().unwrap_or_default()}</h1>
                    <p>"Roles: " {s.roles.join(", ")}</p>
                }.into_any(),
                None => view! {
                    <p>"Please log in."</p>
                }.into_any()
            }}
        </div>
    }
}
```

---

## Use Case 3: Leptos Proxy Integration (Gateway Mode)

In Gateway Mode, the standalone interceptor acts as the TLS and JWT validation gateway. It strips spoof headers and injects trusted identity headers. Your Leptos application simply trusts these upstream headers.

### 1. Enable Gateway Mode
Set the environment variable:
```bash
TRUST_PROXY_HEADERS=true
```
Or enable programmatically inside your initialization code (e.g., in `main.rs`):
```rust
leptos_wasi_auth::set_trust_proxy_headers(true);
```

### 2. Extract Session in Your Server Action
```rust
#[server(GetUserInfo, "/api")]
pub async fn get_user_info() -> Result<String, ServerFnError> {
    // Retrieve parts from the Leptos context
    let parts = use_context::<http::request::Parts>()
        .ok_or_else(|| ServerFnError::new("Request parts missing"))?;

    // Direct mode parameters (keys/aud/iss) can be None as proxy headers are trusted
    let session = leptos_wasi_auth::extract_session_from_parts::<wasi_auth_traits::InMemoryStorage>(
        &parts,
        None, // no storage checks needed when trusting upstream proxy
        None,
        None,
        None
    ).map_err(|e| ServerFnError::new(format!("Auth error: {:?}", e)))?;

    if let Some(s) = session {
        Ok(format!("Logged in as: {} with roles: {:?}", s.user_id, s.roles))
    } else {
        Err(ServerFnError::new("Unauthorized"))
    }
}
```

---

## Use Case 4: Implementing Custom Traits

You can swap out the default in-memory or Spin SDK key-value storage for custom backends (such as Redis, DynamoDB, or PostgreSQL) and delivery channels (SendGrid, AWS SES) by implementing the core traits.

### 1. Custom `AuthStorage` Implementation
Below is an example implementing `AuthStorage` mapped to an external key-value database connection:

```rust
use wasi_auth_traits::{AuthStorage, AuthError, Session};

pub struct MyRedisStorage {
    redis_client: RedisClient,
}

impl AuthStorage for MyRedisStorage {
    fn store_session(&self, session_id: &str, user_id: &str, roles: &[String], expires_at: u64) -> Result<(), AuthError> {
        let key = format!("session:{}", session_id);
        let roles_csv = roles.join(",");
        self.redis_client.set_with_expiry(&key, &format!("{}:{}", user_id, roles_csv), expires_at)
            .map_err(|e| AuthError::Storage(e.to_string()))
    }

    fn get_session(&self, session_id: &str) -> Result<Option<Session>, AuthError> {
        let key = format!("session:{}", session_id);
        match self.redis_client.get(&key) {
            Ok(Some(val)) => {
                let parts: Vec<&str> = val.splitn(2, ':').collect();
                if parts.len() == 2 {
                    Ok(Some(Session {
                        session_id: session_id.to_string(),
                        user_id: parts[0].to_string(),
                        roles: parts[1].split(',').map(|s| s.to_string()).collect(),
                        expires_at: 0, // Set correctly if required
                    }))
                } else {
                    Err(AuthError::Storage("Malformed session string".to_string()))
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AuthError::Storage(e.to_string())),
        }
    }

    fn delete_session(&self, session_id: &str) -> Result<(), AuthError> {
        let key = format!("session:{}", session_id);
        self.redis_client.del(&key).map_err(|e| AuthError::Storage(e.to_string()))
    }

    fn store_otp(&self, email: &str, otp: &str, expires_at: u64) -> Result<(), AuthError> {
        let key = format!("otp:{}", email);
        self.redis_client.set_with_expiry(&key, otp, expires_at)
            .map_err(|e| AuthError::Storage(e.to_string()))
    }

    fn verify_otp(&self, email: &str, otp: &str) -> Result<bool, AuthError> {
        let key = format!("otp:{}", email);
        match self.redis_client.get(&key) {
            Ok(Some(stored_val)) => {
                let _ = self.redis_client.del(&key); // Single use consumption
                Ok(stored_val == otp)
            }
            _ => Ok(false),
        }
    }

    fn store_totp_secret(&self, email: &str, secret: &str) -> Result<(), AuthError> {
        let key = format!("totp:{}", email);
        self.redis_client.set(&key, secret).map_err(|e| AuthError::Storage(e.to_string()))
    }

    fn get_totp_secret(&self, email: &str) -> Result<Option<String>, AuthError> {
        let key = format!("totp:{}", email);
        self.redis_client.get(&key).map_err(|e| AuthError::Storage(e.to_string()))
    }

    fn delete_totp_secret(&self, email: &str) -> Result<(), AuthError> {
        let key = format!("totp:{}", email);
        self.redis_client.del(&key).map_err(|e| AuthError::Storage(e.to_string()))
    }

    fn blacklist_jti(&self, jti: &str, expires_at: u64) -> Result<(), AuthError> {
        let key = format!("blacklist:{}", jti);
        self.redis_client.set_with_expiry(&key, "1", expires_at)
            .map_err(|e| AuthError::Storage(e.to_string()))
    }

    fn is_jti_blacklisted(&self, jti: &str) -> Result<bool, AuthError> {
        let key = format!("blacklist:{}", jti);
        match self.redis_client.get(&key) {
            Ok(Some(_)) => Ok(true),
            _ => Ok(false),
        }
    }

    fn cleanup_expired(&self) -> Result<(), AuthError> {
        // Handled automatically by Redis TTL expiry settings
        Ok(())
    }
}
```

### 2. Custom `EmailSender` Implementation
Here is an example sending transaction verification emails via SendGrid's API over standard outbound HTTP:

```rust
use wasi_auth_traits::{EmailSender, AuthError};

pub struct SendGridEmailSender {
    api_key: String,
}

impl EmailSender for SendGridEmailSender {
    fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), AuthError> {
        let payload = serde_json::json!({
            "personalizations": [{ "to": [{ "email": to }] }],
            "from": { "email": "noreply@example.com" },
            "subject": subject,
            "content": [{ "type": "text/plain", "value": body }]
        });

        // Use standard outgoing HTTP requests supported on WASI (wasi:http/outgoing-handler)
        let response = spin_sdk::http::send(
            http::Request::builder()
                .method("POST")
                .uri("https://api.sendgrid.com/v3/mail/send")
                .header("Authorization", format!("Bearer {}", self.api_key))
                .header("Content-Type", "application/json")
                .body(Some(serde_json::to_vec(&payload).unwrap().into()))
                .unwrap()
        ).map_err(|e| AuthError::Email(format!("HTTP transport error: {:?}", e)))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(AuthError::Email(format!("SendGrid rejected request: {}", response.status())))
        }
    }
}
```

---

## Use Case 5: Multi-Factor Authentication (TOTP) & Magic Links

### 1. Enrollment & Verification for TOTP

#### Enrollment (Server Function)
```rust
#[server(EnrollTotp, "/api")]
pub async fn enroll_totp(email: String) -> Result<String, ServerFnError> {
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("State missing"))?;
    
    // Generates secret, stores it in database, and returns standard provisioning URI
    let (_secret, uri) = leptos_wasi_auth::register_totp(&email, "MyCoolService", &*state.storage)
        .map_err(|e| ServerFnError::new(format!("TOTP enrollment failed: {:?}", e)))?;
        
    // Return provisioning URI (suitable for displaying as a QR code to the user)
    Ok(uri)
}
```

#### Verification & Login (Server Function with Anti-Replay)
```rust
#[server(VerifyTotp, "/api")]
pub async fn verify_totp(email: String, code: String) -> Result<bool, ServerFnError> {
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("State missing"))?;
    
    // Verifies code with ±1 time-step drift window and enforces single-use replay protection
    let is_valid = leptos_wasi_auth::verify_totp_login(&email, &code, &*state.storage)
        .map_err(|e| ServerFnError::new(format!("Verification failed: {:?}", e)))?;
        
    if !is_valid {
        return Err(ServerFnError::new("Invalid or replayed TOTP code"));
    }
    
    // Proceed to create a JWT cookie and store the authenticated session ...
    Ok(true)
}
```

### 2. Passwordless Signed Magic Links

#### Generate Magic Link Request (Server Function)
```rust
#[server(RequestMagicLink, "/api")]
pub async fn request_magic_link(email: String) -> Result<String, ServerFnError> {
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("State missing"))?;

    let callback_base_url = "https://my-app.example.com/magic-callback";
    let expiry_seconds = 300; // link valid for 5 minutes
    
    let magic_link_url = leptos_wasi_auth::generate_magic_link(
        &email,
        callback_base_url,
        &state.private_key_pem,
        Some("key-v1"), // Optional Key ID (kid)
        expiry_seconds,
        "my-app-audience",
        "my-app-issuer",
    ).map_err(|e| ServerFnError::new(format!("Magic link generation failed: {:?}", e)))?;

    // Send the link via the configured EmailSender trait
    state.email_sender.send_email(
        &email,
        "Your Secure Login Link",
        &format!("Click the link to complete login: {}", magic_link_url)
    ).map_err(|e| ServerFnError::new(format!("Failed to send email: {:?}", e)))?;

    Ok("Magic login link has been sent to your email inbox.".to_string())
}
```

#### Consume & Verify Magic Link Token (Route Callback Handler)
When a user clicks the magic link, they are directed to the callback route (e.g. `/magic-callback?token=...`). Extract the query token and verify it:

```rust
#[server(ConsumeMagicLinkToken, "/api")]
pub async fn consume_magic_link_token(token: String) -> Result<bool, ServerFnError> {
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("State missing"))?;

    // Validates signature, verifies expiration, checks JTI blacklist, and consumes the link (inserts JTI into blacklist)
    let email = leptos_wasi_auth::verify_magic_link(
        &token,
        &state.public_key_pem,
        "my-app-audience",
        "my-app-issuer",
        &*state.storage,
    ).map_err(|e| ServerFnError::new(format!("Link expired or already consumed: {:?}", e)))?;

    // Setup JWT Session Cookie ...
    Ok(true)
}
```
