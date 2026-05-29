//! # wasi-auth-interceptor
//!
//! A standalone WASI HTTP middleware component that acts as an **authentication
//! proxy** in a [WebAssembly Component Model](https://component-model.bytecodealliance.org/)
//! composition pipeline.
//!
//! ## How It Works
//!
//! The interceptor **imports** `wasi:http/incoming-handler@0.2.9` (the
//! downstream application) and **exports** the same interface, allowing it to
//! sit transparently between the HTTP runtime and your application component.
//!
//! ```text
//! ┌──────────┐      ┌──────────────────────┐      ┌─────────────┐
//! │  Client  │─────▶│  wasi-auth-interceptor│─────▶│  Your App   │
//! └──────────┘      └──────────────────────┘      └─────────────┘
//! ```
//!
//! ## Security Behaviour
//!
//! 1. **Header stripping** — All `X-User-*` headers (`X-User-Id`,
//!    `X-User-Roles`, `X-User-Email`, `X-User-Name`) are **deleted** from
//!    every incoming request before any other processing. This prevents
//!    upstream clients from spoofing identity headers.
//!
//! 2. **Public path bypass** — Requests to the following paths are forwarded
//!    directly to the downstream component **without** authentication:
//!    - `/`
//!    - `/login`
//!    - `/pkg/*` (static WASM/JS bundles)
//!    - `/static/*` (static assets)
//!
//! 3. **JWT verification** — For all other paths, a JWT token is extracted
//!    from cookies (`jwt` or `session`) or the `Authorization: Bearer <token>`
//!    header. Verification behaviour depends on environment variables:
//!
//!    | Variable         | Description |
//!    |------------------|-------------|
//!    | `JWT_PUBLIC_KEY`  | PEM-encoded public key for RS256 signature verification. |
//!    | `JWT_AUDIENCE`    | Expected `aud` claim value. |
//!    | `JWT_ISSUER`      | Expected `iss` claim value. |
//!
//!    - When **all three** are set, the JWT is cryptographically verified via
//!      [`wasi_auth_core::jwt::verify_jwt`].
//!    - When any are **missing**, the interceptor falls back to *unsafe*
//!      parsing: claims are decoded without signature verification but
//!      expiration (`exp`) is still checked (with a 60-second grace window).
//!
//! 4. **Authenticated requests** — On successful verification the interceptor
//!    injects the following headers before forwarding to the downstream app:
//!    - `X-User-Id` — the `sub` claim
//!    - `X-User-Roles` — comma-separated role list
//!    - `X-User-Email` — *(if present in claims)*
//!    - `X-User-Name` — *(if present in claims)*
//!
//! 5. **Unauthenticated requests** — When authentication fails:
//!    - `POST`, `PUT`, `DELETE`, `PATCH`, or any path starting with `/api/`
//!      → **401 Unauthorized** response.
//!    - All other methods → **302 Redirect** to `/login`.

#![allow(clippy::missing_safety_doc)]
#![allow(unsafe_op_in_unsafe_fn)]

pub mod config;

wit_bindgen::generate!({
    path: "wit",
    world: "interceptor",
    generate_all,
});

/// The component struct that implements the `wasi:http/incoming-handler` export.
///
/// This is the entry point for all inbound HTTP requests. The WASI runtime
/// dispatches requests to [`Guest::handle`] which performs header stripping,
/// authentication, and conditional forwarding.
struct Interceptor;

fn match_path(path: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        path.starts_with(prefix)
    } else {
        path == pattern
    }
}

impl exports::wasi::http::incoming_handler::Guest for Interceptor {
    /// Handles an incoming HTTP request through the authentication pipeline.
    ///
    /// # Processing Steps
    ///
    /// 1. **Strip `X-User-*` headers** from the incoming request (both
    ///    lowercase and title-case variants) to prevent header spoofing.
    /// 2. **Check for public paths** (`/`, `/login`, `/pkg/*`, `/static/*`).
    ///    If the path is public, forward the request immediately.
    /// 3. **Extract a JWT** from cookies (`jwt`, `session`) or the
    ///    `Authorization: Bearer` header.
    /// 4. **Verify the JWT** using env-configured keys, or fall back to
    ///    unsafe expiration-only parsing.
    /// 5. On success, **inject identity headers** (`X-User-Id`, etc.) and
    ///    forward. On failure, return **401** for API/mutation requests or
    ///    **302 redirect** to `/login` for others.
    fn handle(
        request: exports::wasi::http::incoming_handler::IncomingRequest,
        response_outparam: exports::wasi::http::incoming_handler::ResponseOutparam,
    ) {
        use crate::wasi::http::types::{Fields, OutgoingBody, OutgoingResponse};

        let config = config::InterceptorConfig::load();

        let headers = request.headers();
        let _ = headers.delete(&"x-user-id".to_string());
        let _ = headers.delete(&"X-User-Id".to_string());
        let _ = headers.delete(&"x-user-roles".to_string());
        let _ = headers.delete(&"X-User-Roles".to_string());
        let _ = headers.delete(&"x-user-email".to_string());
        let _ = headers.delete(&"X-User-Email".to_string());
        let _ = headers.delete(&"x-user-name".to_string());
        let _ = headers.delete(&"X-User-Name".to_string());

        let path_with_query = request.path_with_query().unwrap_or_else(|| "/".to_string());
        let path = path_with_query.split('?').next().unwrap_or("/");

        // 1. Check if it's a public path using config patterns
        let is_public = config
            .auth
            .public_paths
            .iter()
            .any(|pattern| match_path(path, pattern));

        if is_public {
            // Forward request directly
            wasi::http::incoming_handler::handle(request, response_outparam);
            return;
        }

        // 2. Perform authentication check
        let mut token = None;

        // Try to get token from Cookie (6 precedence levels)
        // Try to get token from Cookie (6 precedence levels)
        if let Some(cookies) =
            get_header_value(&headers, "cookie").or_else(|| get_header_value(&headers, "Cookie"))
            && let Some(t) = extract_cookie(&cookies, "__Host-jwt")
                .or_else(|| extract_cookie(&cookies, "__Host-session"))
                .or_else(|| extract_cookie(&cookies, "__Secure-jwt"))
                .or_else(|| extract_cookie(&cookies, "__Secure-session"))
                .or_else(|| extract_cookie(&cookies, "jwt"))
                .or_else(|| extract_cookie(&cookies, "session"))
        {
            token = Some(t);
        }

        // Try to get token from Authorization: Bearer <token>
        if token.is_none()
            && let Some(auth_val) = get_header_value(&headers, "authorization")
                .or_else(|| get_header_value(&headers, "Authorization"))
            && let Some(t) = auth_val.strip_prefix("Bearer ")
        {
            token = Some(t.to_string());
        }

        let mut authenticated_session = None;

        if let Some(jwt_token) = token {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::ZERO)
                .as_secs();

            let pub_key = std::env::var("JWT_PUBLIC_KEY").ok();
            let aud = std::env::var("JWT_AUDIENCE").ok();
            let iss = std::env::var("JWT_ISSUER").ok();

            if let (Some(pub_key), Some(aud), Some(iss)) = (pub_key, aud, iss) {
                // Securely verify JWT
                if let Ok(claims) =
                    wasi_auth_core::jwt::verify_jwt(&jwt_token, &pub_key, &aud, &iss, now)
                {
                    authenticated_session = Some(claims);
                }
            } else {
                // Fallback to unsafe parsing but STILL validate token expiration manually
                if let Ok(claims) = parse_claims_unsafe(&jwt_token) {
                    let is_expired = if let Some(exp_limit) = claims.exp.checked_add(60) {
                        exp_limit <= now
                    } else {
                        claims.exp <= now
                    };
                    if !is_expired {
                        authenticated_session = Some(claims);
                    }
                }
            }
        }

        if let Some(session) = authenticated_session {
            // Inject identity headers into request
            let _ = headers.set(&"x-user-id".to_string(), &[session.sub.as_bytes().to_vec()]);

            let roles_str = session.roles.join(",");
            let _ = headers.set(
                &"x-user-roles".to_string(),
                &[roles_str.as_bytes().to_vec()],
            );

            if let Some(email) = session.email {
                let _ = headers.set(&"x-user-email".to_string(), &[email.as_bytes().to_vec()]);
            }
            if let Some(name) = session.name {
                let _ = headers.set(&"x-user-name".to_string(), &[name.as_bytes().to_vec()]);
            }

            // Forward authenticated request to downstream application
            wasi::http::incoming_handler::handle(request, response_outparam);
        } else {
            // Unauthenticated! Block request.
            // If it's a POST/PUT/DELETE/PATCH/API request, return 401. Otherwise redirect to /login.
            let method = request.method();
            let is_api_or_action = matches!(
                method,
                crate::wasi::http::types::Method::Post
                    | crate::wasi::http::types::Method::Put
                    | crate::wasi::http::types::Method::Delete
                    | crate::wasi::http::types::Method::Patch
            ) || path.starts_with("/api/");

            if is_api_or_action {
                // Return 401 Unauthorized
                let resp_headers = Fields::new();
                let response = OutgoingResponse::new(resp_headers);
                let _ = response.set_status_code(401);

                let body = response.body().unwrap();
                let stream = body.write().unwrap();
                let _ = stream.blocking_write_and_flush(b"Unauthorized");
                drop(stream);
                let _ = OutgoingBody::finish(body, None);

                exports::wasi::http::incoming_handler::ResponseOutparam::set(
                    response_outparam,
                    Ok(response),
                );
            } else {
                // Return 302 Redirect to login_redirect config
                let resp_headers = Fields::new();
                let _ = resp_headers.set(
                    &"location".to_string(),
                    &[config.auth.login_redirect.as_bytes().to_vec()],
                );
                let response = OutgoingResponse::new(resp_headers);
                let _ = response.set_status_code(302);

                let body = response.body().unwrap();
                let stream = body.write().unwrap();
                let redirect_msg = format!("Redirecting to {}...", config.auth.login_redirect);
                let _ = stream.blocking_write_and_flush(&redirect_msg.into_bytes());
                drop(stream);
                let _ = OutgoingBody::finish(body, None);

                exports::wasi::http::incoming_handler::ResponseOutparam::set(
                    response_outparam,
                    Ok(response),
                );
            }
        }
    }
}

/// Retrieves the first value of the header with the given `name` from a
/// WASI HTTP [`Fields`](crate::wasi::http::types::Fields) resource.
///
/// Returns `None` if the header is absent or contains non-UTF-8 bytes.
fn get_header_value(fields: &crate::wasi::http::types::Fields, name: &str) -> Option<String> {
    fields
        .get(&name.to_string())
        .first()
        .and_then(|bytes| std::str::from_utf8(bytes).ok().map(|s| s.to_string()))
}

/// Extracts the value of a cookie with the given `name` from a raw
/// `Cookie` header string.
///
/// Performs a simple linear scan over semicolon-delimited `name=value` pairs
/// and returns the first match.
fn extract_cookie(cookie_header: &str, name: &str) -> Option<String> {
    for cookie in cookie_header.split(';') {
        let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
        if parts.len() == 2 && parts[0] == name {
            return Some(parts[1].to_string());
        }
    }
    None
}

/// Decodes the claims payload of a JWT **without** verifying its signature.
///
/// # Security
///
/// This function is intentionally **unsafe** from an authentication
/// perspective — it only decodes the Base64url-encoded payload segment and
/// deserialises it into [`Claims`](wasi_auth_core::jwt::Claims). The caller
/// is responsible for performing at least an expiration check on the returned
/// claims. This is used as a fallback when `JWT_PUBLIC_KEY`, `JWT_AUDIENCE`,
/// or `JWT_ISSUER` environment variables are not configured.
///
/// # Errors
///
/// Returns an error string if the token does not have at least two
/// dot-separated segments, if Base64url decoding fails, or if JSON
/// deserialisation into `Claims` fails.
fn parse_claims_unsafe(token: &str) -> Result<wasi_auth_core::jwt::Claims, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return Err("Invalid JWT format".to_string());
    }
    // Decode header or claims
    let claims_json =
        wasi_auth_core::jwt::base64_url_decode(parts[1]).map_err(|e| e.to_string())?;

    let claims: wasi_auth_core::jwt::Claims =
        serde_json::from_slice(&claims_json).map_err(|e| e.to_string())?;
    Ok(claims)
}

export!(Interceptor);
