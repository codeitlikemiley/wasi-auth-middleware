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

use tracing::{debug, info, warn};
use wasi_auth_core::extract_cookie;

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
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .init();
        });

        use crate::wasi::http::types::{Fields, OutgoingBody, OutgoingResponse};

        static CONFIG: std::sync::OnceLock<config::InterceptorConfig> = std::sync::OnceLock::new();
        let config = CONFIG.get_or_init(config::InterceptorConfig::load);

        let headers = request.headers();
        let _ = headers.delete(&"x-user-id".to_string());
        let _ = headers.delete(&"X-User-Id".to_string());
        let _ = headers.delete(&"x-user-roles".to_string());
        let _ = headers.delete(&"X-User-Roles".to_string());
        let _ = headers.delete(&"x-user-email".to_string());
        let _ = headers.delete(&"X-User-Email".to_string());
        let _ = headers.delete(&"x-user-name".to_string());
        let _ = headers.delete(&"X-User-Name".to_string());

        let method = request.method();
        let path_with_query = request.path_with_query().unwrap_or_else(|| "/".to_string());
        let path = path_with_query.split('?').next().unwrap_or("/");

        debug!("Interceptor handling request: {:?} {}", method, path);

        // 1. Check if it's a public path using config patterns
        let is_public = config
            .auth
            .public_paths
            .iter()
            .any(|pattern| match_path(path, pattern));

        if is_public {
            debug!("Bypassing authentication for public path: {}", path);
            // Forward request directly
            wasi::http::incoming_handler::handle(request, response_outparam);
            return;
        }

        // 2. Perform authentication check
        let mut token = None;

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

        if token.is_some() {
            debug!("Extracted credentials token from request context");
        } else {
            debug!("No credentials token found in request context");
        }

        let auth_result: Result<wasi_auth_core::jwt::Claims, wasi_auth_core::AuthError> =
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
                    wasi_auth_core::jwt::verify_jwt(&jwt_token, &pub_key, &aud, &iss, now)
                } else {
                    // Fallback to unsafe parsing but STILL validate token expiration manually
                    match parse_claims_unsafe(&jwt_token) {
                        Ok(claims) => {
                            let is_expired = if let Some(exp_limit) = claims.exp.checked_add(60) {
                                exp_limit <= now
                            } else {
                                claims.exp <= now
                            };
                            if !is_expired {
                                Ok(claims)
                            } else {
                                Err(wasi_auth_core::AuthError::TokenExpired(
                                    "Token has expired".to_string(),
                                ))
                            }
                        }
                        Err(e) => Err(e),
                    }
                }
            } else {
                Err(wasi_auth_core::AuthError::Other(
                    "Missing authentication token".to_string(),
                ))
            };

        match auth_result {
            Ok(session) => {
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

                info!(
                    "Request authenticated. Subject: {}. Injected X-User-* headers.",
                    session.sub
                );

                // Forward authenticated request to downstream application
                wasi::http::incoming_handler::handle(request, response_outparam);
            }
            Err(err) => {
                let err_code = err.code();
                let err_message = err.message();

                // Unauthenticated! Block request.
                // If it's a POST/PUT/DELETE/PATCH/API request, return 401. Otherwise redirect to /login.
                let is_api_or_action = matches!(
                    method,
                    crate::wasi::http::types::Method::Post
                        | crate::wasi::http::types::Method::Put
                        | crate::wasi::http::types::Method::Delete
                        | crate::wasi::http::types::Method::Patch
                ) || path.starts_with("/api/");

                warn!(
                    "Request unauthenticated. Method: {:?}, Path: {}. Error: {}. Blocking or redirecting.",
                    method, path, err_message
                );

                if is_api_or_action {
                    // Return 401 Unauthorized with custom headers and JSON body
                    let resp_headers = Fields::new();
                    let _ = resp_headers
                        .set(&"content-type".to_string(), &[b"application/json".to_vec()]);
                    let _ = resp_headers
                        .set(&"x-auth-error".to_string(), &[err_code.as_bytes().to_vec()]);
                    // RFC 6750 WWW-Authenticate header
                    let _ = resp_headers.set(
                        &"www-authenticate".to_string(),
                        &[format!(
                            r#"Bearer error="invalid_token", error_description="{}""#,
                            err_message
                        )
                        .as_bytes()
                        .to_vec()],
                    );

                    let response = OutgoingResponse::new(resp_headers);
                    let _ = response.set_status_code(401);

                    let body = response.body().unwrap();
                    let stream = body.write().unwrap();
                    let response_payload = serde_json::json!({
                        "error": err_code,
                        "message": err_message
                    })
                    .to_string();
                    let _ = stream.blocking_write_and_flush(response_payload.as_bytes());
                    drop(stream);
                    let _ = OutgoingBody::finish(body, None);

                    exports::wasi::http::incoming_handler::ResponseOutparam::set(
                        response_outparam,
                        Ok(response),
                    );
                } else {
                    // Return 302 Redirect with URL query parameters
                    let resp_headers = Fields::new();
                    let redirect_url = if config.auth.login_redirect.contains('?') {
                        format!(
                            "{}&auth_error={}&message={}",
                            config.auth.login_redirect,
                            urlencoding::encode(err_code),
                            urlencoding::encode(err_message)
                        )
                    } else {
                        format!(
                            "{}?auth_error={}&message={}",
                            config.auth.login_redirect,
                            urlencoding::encode(err_code),
                            urlencoding::encode(err_message)
                        )
                    };

                    let _ = resp_headers
                        .set(&"location".to_string(), &[redirect_url.as_bytes().to_vec()]);
                    let response = OutgoingResponse::new(resp_headers);
                    let _ = response.set_status_code(302);

                    let body = response.body().unwrap();
                    let stream = body.write().unwrap();
                    let redirect_msg = format!("Redirecting to {}...", redirect_url);
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
fn parse_claims_unsafe(
    token: &str,
) -> Result<wasi_auth_core::jwt::Claims, wasi_auth_core::AuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return Err(wasi_auth_core::AuthError::InvalidSignature(
            "Invalid JWT format".to_string(),
        ));
    }
    // Decode header or claims
    let claims_json = wasi_auth_core::jwt::base64_url_decode(parts[1])?;

    let claims: wasi_auth_core::jwt::Claims =
        serde_json::from_slice(&claims_json).map_err(|e| {
            wasi_auth_core::AuthError::InvalidSignature(format!(
                "Failed to parse JWT claims: {}",
                e
            ))
        })?;
    Ok(claims)
}

export!(Interceptor);
