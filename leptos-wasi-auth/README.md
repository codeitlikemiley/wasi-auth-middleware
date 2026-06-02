# leptos-wasi-auth

Leptos web framework integration and authentication utilities for the WASI Authentication Middleware. It provides session extraction, identity validation, and role-based access control guards.

## Core Features

- **Double Authentication Model**:
  - **Gateway / Proxy Mode**: Trust identity headers injected by a trusted upstream authentication proxy (e.g. `wasi-auth-interceptor`).
  - **Library / Direct Mode**: Decodes and verifies JWT tokens directly inside the Leptos application component.
- **Leptos Context System**: Seamless integration with Leptos reactive contexts to share user session information across components and server functions.
- **Multifactor Authentication (MFA)**: Support for TOTP registration and anti-replay verification.
- **Magic Link Authentication**: Helpers for generating and verifying cryptographically-signed magic links.

## Configuration & Environment Variables

### Trust Proxy Headers

When in proxy mode, the application relies on an upstream proxy to authenticate requests and inject user identity via `X-User-*` headers.

You must enable trust proxy headers using either of the following environment variables or programmatically:

| Variable | Value | Description |
|---|---|---|
| `TRUST_PROXY_HEADERS` | `"true"` or `"1"` | Enables trusting proxy headers (`X-User-*`) for session extraction. |
| `WASI_AUTH_TRUST_PROXY_HEADERS` | `"true"` or `"1"` | Alias for `TRUST_PROXY_HEADERS`. |

To programmatically configure this, use:
```rust
leptos_wasi_auth::set_trust_proxy_headers(true);
```

> **Security Warning**: Only enable trust proxy headers in production if a trusted gateway (such as `wasi-auth-interceptor`) is positioned in front of your application and is configured to strip these headers from all incoming external client requests.

## Key APIs

### Session Context Management

- **`UserSession`**: Represents the authenticated user, containing `user_id` (JWT `sub`), `roles`, and optional `email` and `name`.
- **`provide_session_context`**: Server-side helper that extracts the session from request `Parts` and sets up Leptos reactive contexts.
- **`expect_session`**: Guard that retrieves the current `UserSession` context inside server functions or components, returning a `ServerFnError` on failure.
- **`expect_role(role)`**: Guard that checks if the active session has the requested role, returning a `ServerFnError` if unauthorized.

### Helpers

- **Cookie Management**:
  - `CookieOptions` & `SameSite` configurations.
  - `build_set_cookie_header(token, options)` and `build_clear_cookie_header(options)`.
- **TOTP (MFA)**:
  - `register_totp(email, issuer, storage)`
  - `verify_totp_login(email, code, storage)`
- **Magic Link**:
  - `generate_magic_link(...)`
  - `verify_magic_link(...)`

## Setup & Features

### Cargo Features

| Feature | Description |
|---|---|
| `ssr` (default) | Server-side rendering support. Enables Leptos context functions on the server. |
| `hydrate` | Client-side hydration support. |
| `csr` | Client-side rendering support. |
| `unsafe-dev-fallback` | Skips cryptographic signature verification. **Do not use in production.** |
| `leptos` | Explicit integration with the Leptos framework. |

## Usage Guide

To use `leptos-wasi-auth` in your Leptos application:

### 1. Extracting and Providing Session Context in Leptos SSR

In your downstream WASI application component, you must extract the user session from the incoming HTTP request headers (injected by the proxy middleware) and feed it into the Leptos context:

```rust,ignore
use leptos::*;
use leptos_wasi::prelude::*;
use leptos_wasi_auth::{provide_session_context, expect_session};
use wasi_auth_traits::AuthStorage;

pub fn handle_request(
    request: wasi::http::types::IncomingRequest,
    response_outparam: wasi::http::types::ResponseOutparam,
    storage: &'static dyn AuthStorage,
) {
    let executor = WasiExecutor::new(leptos_wasi::executor::Mode::Stalled);
    
    executor.run_until(async {
        Handler::build(request, response_outparam)
            .unwrap()
            .handle_with_context(
                // Shell template render
                move || view! { <App /> },
                // Request context setup
                move || {
                    let parts = use_context::<http::request::Parts>();
                    
                    // Extracts JWT from cookies/headers or X-User-* headers 
                    // and provides the reactive context
                    provide_session_context(
                        Some(storage),
                        None,                 // Public key for local verification (if not relying on proxy)
                        Some("client-id-123"), // Audience
                        Some("my-app-issuer"), // Issuer
                    );
                }
            )
    });
}
```

### 2. Protecting Server Functions

You can enforce session and role verification inside Leptos `#[server]` functions using `expect_session()` or `expect_role()` guards:

```rust,ignore
use leptos::*;
use leptos_wasi_auth::{expect_session, expect_role};

#[server]
pub async fn get_admin_reports() -> Result<Vec<String>, ServerFnError> {
    // 1. Assert the user is fully logged in
    let session = expect_session()?;
    
    // 2. Assert the user holds the 'admin' role
    expect_role("admin")?;
    
    // Proceed with privileged database logic
    Ok(vec!["Q2 Earnings Report.pdf".to_string()])
}
```

### 3. Reading Session Context in Frontend Components

Access the current user context reactively within components using `use_context`:

```rust,ignore
use leptos::*;
use leptos_wasi_auth::UserSession;

#[component]
pub fn WelcomeWidget() -> impl IntoView {
    // Read user session context
    let session = use_context::<UserSession>();
    
    view! {
        <div>
            {move || match &session {
                Some(user) => view! {
                    <p>"Welcome back, " {user.name.clone().unwrap_or(user.user_id.clone())} "!"</p>
                    <p class="role-badge">"Roles: " {user.roles.join(", ")}</p>
                }.into_any(),
                None => view! {
                    <p>"Please log in to continue."</p>
                }.into_any()
            }}
        </div>
    }
}
```
