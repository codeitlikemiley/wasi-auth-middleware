//! # leptos-wasi-auth
//!
//! Integrates the WASI authentication framework with the [Leptos](https://leptos.dev/) web
//! framework, providing session extraction and role-based access guards for server-side
//! rendered (SSR), hydrated, and client-side rendered (CSR) Leptos applications.
//!
//! ## Authentication Modes
//!
//! This crate supports two authentication modes that can be used independently or together:
//!
//! 1. **Gateway / Proxy mode** — When a reverse proxy or the
//!    [`wasi-auth-interceptor`](../wasi-auth-interceptor) component sits in front of your
//!    application, it strips and re-injects trusted `X-User-*` headers after verifying the
//!    JWT. Enable this mode by setting the `TRUST_PROXY_HEADERS` or
//!    `WASI_AUTH_TRUST_PROXY_HEADERS` environment variable to `"true"` or `"1"`, or by
//!    calling [`set_trust_proxy_headers`]`(true)`.
//!
//! 2. **Library / Direct mode** — The crate extracts a JWT token directly from the
//!    request's cookies or `Authorization: Bearer <token>` header and verifies it
//!    in-process using a public key, audience, and issuer you provide.
//!
//! ## Cookie Precedence (highest → lowest)
//!
//! When extracting a JWT from cookies, the following precedence order is used:
//!
//! | Priority | Cookie Name        |
//! |----------|--------------------|
//! | 1        | `__Host-jwt`       |
//! | 2        | `__Host-session`   |
//! | 3        | `__Secure-jwt`     |
//! | 4        | `__Secure-session` |
//! | 5        | `jwt`              |
//! | 6        | `session`          |
//!
//! Prefixed cookies (`__Host-*`, `__Secure-*`) are preferred because browsers enforce
//! stricter security guarantees on them.
//!
//! ## Feature Flags
//!
//! | Feature               | Description |
//! |-----------------------|-------------|
//! | `ssr` *(default)*     | Server-side rendering support; enables Leptos context functions. |
//! | `hydrate`             | Hydration support; enables Leptos context functions. |
//! | `csr`                 | Client-side rendering support; enables Leptos context functions. |
//! | `unsafe-dev-fallback` | **Development only.** Skips JWT signature verification and parses claims directly. |
//! | `leptos`              | Re-export / integration with the Leptos reactive context system. |
//!
//! ## Environment Variables
//!
//! | Variable                        | Description |
//! |---------------------------------|-------------|
//! | `TRUST_PROXY_HEADERS`           | Set to `"true"` or `"1"` to trust `X-User-*` proxy headers. |
//! | `WASI_AUTH_TRUST_PROXY_HEADERS`  | Alias for `TRUST_PROXY_HEADERS`. |

use http::request::Parts;
#[cfg(any(feature = "ssr", feature = "hydrate", feature = "csr"))]
use leptos::prelude::*;
#[cfg(any(feature = "unsafe-dev-fallback", test))]
use wasi_auth_core::jwt::Claims;
use wasi_auth_core::jwt::verify_jwt_with_options;
use wasi_auth_core::{AuthError, AuthStorage};

use std::sync::atomic::{AtomicBool, Ordering};

/// Global flag controlling whether the `X-User-*` headers injected by a trusted
/// proxy (e.g. [`wasi-auth-interceptor`]) should be used to construct the session.
///
/// Defaults to `false`. Can be toggled at runtime via [`set_trust_proxy_headers`]
/// or via the `TRUST_PROXY_HEADERS` / `WASI_AUTH_TRUST_PROXY_HEADERS` environment
/// variables (checked by [`is_trust_proxy_headers`]).
static TRUST_PROXY_HEADERS: AtomicBool = AtomicBool::new(false);

/// Programmatically enable or disable trusting proxy headers.
///
/// When enabled, [`extract_session_from_parts`] will first look for
/// `X-User-Id`, `X-User-Roles`, `X-User-Email`, and `X-User-Name` headers
/// before falling back to JWT extraction.
///
/// # Security
///
/// Only enable this when a **trusted** reverse proxy (such as
/// `wasi-auth-interceptor`) sits in front of your application and is
/// responsible for stripping and re-injecting these headers after verification.
pub fn set_trust_proxy_headers(trust: bool) {
    TRUST_PROXY_HEADERS.store(trust, Ordering::Relaxed);
}

/// Returns `true` if proxy headers should be trusted for session extraction.
///
/// The check is satisfied when **any** of the following is true:
///
/// 1. [`set_trust_proxy_headers`]`(true)` was called at runtime.
/// 2. The `TRUST_PROXY_HEADERS` environment variable is `"true"` or `"1"`.
/// 3. The `WASI_AUTH_TRUST_PROXY_HEADERS` environment variable is `"true"` or `"1"`.
pub fn is_trust_proxy_headers() -> bool {
    TRUST_PROXY_HEADERS.load(Ordering::Relaxed)
        || std::env::var("TRUST_PROXY_HEADERS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false)
        || std::env::var("WASI_AUTH_TRUST_PROXY_HEADERS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false)
}

/// Represents an authenticated user session extracted from a verified JWT or
/// trusted proxy headers.
///
/// This struct is the primary output of [`extract_session_from_parts`] and is
/// made available to Leptos components via [`provide_session_context`]. It can
/// be serialized/deserialized for transfer between server and client in SSR.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserSession {
    /// Unique identifier of the authenticated user (the JWT `sub` claim).
    pub user_id: String,
    /// List of roles assigned to the user (from the JWT `roles` claim or
    /// the `X-User-Roles` header). Empty strings and whitespace-only entries
    /// are stripped during construction.
    pub roles: Vec<String>,
    /// Optional email address from the JWT `email` claim or `X-User-Email` header.
    pub email: Option<String>,
    /// Optional display name from the JWT `name` claim or `X-User-Name` header.
    pub name: Option<String>,
}

impl UserSession {
    /// Returns `true` if this session's [`roles`](Self::roles) list contains
    /// the given `role` (exact, case-sensitive match).
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// Cleans up a list of role strings by trimming leading/trailing whitespace
/// from each entry and removing any entries that become empty after trimming.
///
/// This is applied automatically when building a [`UserSession`] from either
/// proxy headers or JWT claims, so callers rarely need to invoke it directly.
pub fn sanitize_roles(roles: Vec<String>) -> Vec<String> {
    roles
        .into_iter()
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect()
}

/// Extracts the value of a cookie with the given `name` from a raw
/// `Cookie` header string.
///
/// Performs a simple linear scan over semicolon-delimited `name=value` pairs.
/// Returns `Some(value)` for the first match, or `None` if no cookie with
/// that name is present.
pub fn extract_cookie(cookie_header: &str, name: &str) -> Option<String> {
    for cookie in cookie_header.split(';') {
        let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
        if parts.len() == 2 && parts[0] == name {
            return Some(parts[1].to_string());
        }
    }
    None
}

/// Core session extraction function that examines HTTP request [`Parts`] and
/// returns a [`UserSession`] if authentication succeeds.
///
/// # Authentication Flow
///
/// 1. **Gateway / Proxy mode** — If [`is_trust_proxy_headers()`] returns `true`
///    and the request contains an `X-User-Id` header, the session is built
///    directly from the `X-User-*` headers without any JWT processing.
///
/// 2. **Library / Direct mode** — Otherwise the function extracts a JWT token
///    from cookies (see [cookie precedence](crate#cookie-precedence-highest--lowest))
///    or from the `Authorization: Bearer <token>` header.
///
///    - If `public_key_pem`, `expected_aud`, and `expected_iss` are all
///      provided, the JWT is **cryptographically verified** using
///      [`wasi_auth_core::jwt::verify_jwt`].
///    - If verification keys are **not** provided and the `unsafe-dev-fallback`
///      feature is enabled, the JWT claims are decoded **without signature
///      verification** (a warning is printed to stderr).
///    - If verification keys are missing and `unsafe-dev-fallback` is disabled,
///      an [`AuthError::Crypto`] error is returned.
///
/// # Storage Backend
///
/// When a `storage` backend is provided, the function additionally checks that
/// the token exists in the session store. If the session has been revoked or
/// was never stored, an [`AuthError::Crypto`] error is returned.
///
/// # Errors
///
/// - [`AuthError::Crypto`] — JWT verification failed, keys are missing (without
///   `unsafe-dev-fallback`), or the session was revoked.
/// - [`AuthError::Storage`] — The storage backend encountered an error.
pub fn extract_session_from_parts<S: AuthStorage>(
    parts: &Parts,
    storage: Option<&S>,
    public_key_pem: Option<&str>,
    expected_aud: Option<&str>,
    expected_iss: Option<&str>,
) -> Result<Option<UserSession>, AuthError> {
    extract_session_from_parts_with_options(
        parts,
        storage,
        public_key_pem,
        expected_aud,
        expected_iss,
        &wasi_auth_core::jwt::ValidationOptions::default(),
    )
}

/// Extracts a [`UserSession`] from an incoming HTTP request [`Parts`], validating the session and
/// JWT against custom [`wasi_auth_core::ValidationOptions`].
///
/// Under Gateway Mode, trusts `X-User-*` headers directly. Under Library Mode, extracts the JWT
/// from request cookies or Authorization headers, verifies its signature using the key and leeway options,
/// and validates the active session in storage.
pub fn extract_session_from_parts_with_options<S: AuthStorage>(
    parts: &Parts,
    storage: Option<&S>,
    public_key_pem: Option<&str>,
    expected_aud: Option<&str>,
    expected_iss: Option<&str>,
    options: &wasi_auth_core::jwt::ValidationOptions,
) -> Result<Option<UserSession>, AuthError> {
    // 1. Interceptor/Gateway Mode: Check X-User-Id and X-User-Roles headers first
    if is_trust_proxy_headers()
        && let Some(user_id_val) = parts.headers.get("x-user-id")
        && let Ok(user_id) = user_id_val.to_str()
    {
        let roles = parts
            .headers
            .get("x-user-roles")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').map(|r| r.to_string()).collect())
            .unwrap_or_default();
        let roles = sanitize_roles(roles);

        let email = parts
            .headers
            .get("x-user-email")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let name = parts
            .headers
            .get("x-user-name")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        return Ok(Some(UserSession {
            user_id: user_id.to_string(),
            roles,
            email,
            name,
        }));
    }

    // 2. Library/Direct Mode: Extract JWT from Cookie or Authorization header
    let token = if let Some(cookie_val) = parts.headers.get(http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_val.to_str() {
            extract_cookie(cookie_str, "__Host-jwt")
                .or_else(|| extract_cookie(cookie_str, "__Host-session"))
                .or_else(|| extract_cookie(cookie_str, "__Secure-jwt"))
                .or_else(|| extract_cookie(cookie_str, "__Secure-session"))
                .or_else(|| extract_cookie(cookie_str, "jwt"))
                .or_else(|| extract_cookie(cookie_str, "session"))
        } else {
            None
        }
    } else {
        None
    };

    let token = token.or_else(|| {
        parts
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.to_string())
    });

    let token = match token {
        Some(t) => t,
        None => return Ok(None),
    };

    // If we have a verification key, decode and verify the JWT
    if let (Some(pub_key), Some(aud), Some(iss)) = (public_key_pem, expected_aud, expected_iss) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let claims = verify_jwt_with_options(&token, pub_key, aud, iss, now, options)?;

        // If a storage backend is provided, verify session is active
        if let Some(store) = storage
            && store.get_session(&token)?.is_none()
        {
            return Err(AuthError::Crypto(
                "Session revoked or not found in storage".to_string(),
            ));
        }

        let roles = sanitize_roles(claims.roles);

        Ok(Some(UserSession {
            user_id: claims.sub,
            roles,
            email: claims.email,
            name: claims.name,
        }))
    } else {
        #[cfg(feature = "unsafe-dev-fallback")]
        {
            eprintln!(
                "WARNING: Running in unsafe-dev-fallback mode! Token signatures are not verified."
            );
            // Ensure the token storage lookup is always executed if storage is provided, even in dev mode unverified fallback.
            if let Some(store) = storage
                && store.get_session(&token)?.is_none()
            {
                return Err(AuthError::Crypto(
                    "Session revoked or not found in storage".to_string(),
                ));
            }

            // No verification key configured, just parse claims without verification (Unsafe - Dev/Testing only!)
            let parts: Vec<&str> = token.split('.').collect();
            if parts.len() >= 2 {
                let claims_json = wasi_auth_core::jwt::base64_url_decode(parts[1])?;
                if let Ok(claims) = serde_json::from_slice::<Claims>(&claims_json) {
                    let roles = sanitize_roles(claims.roles);

                    return Ok(Some(UserSession {
                        user_id: claims.sub,
                        roles,
                        email: claims.email,
                        name: claims.name,
                    }));
                }
            }
            Err(AuthError::Crypto(
                "Unverified fallback failed: claims are malformed".to_string(),
            ))
        }
        #[cfg(not(feature = "unsafe-dev-fallback"))]
        {
            Err(AuthError::Crypto(
                "Missing cryptographic verification keys".to_string(),
            ))
        }
    }
}

/// Extracts the user session from the current Leptos request context and
/// provides the result as a Leptos reactive context value of type
/// `Result<Option<UserSession>, AuthError>`.
///
/// This should be called once during server-side request handling (e.g. in
/// your Leptos `App` component or a layout component). Downstream components
/// and server functions can then retrieve the session via [`expect_session`]
/// or [`expect_role`].
///
/// Internally this reads [`http::request::Parts`] from the Leptos context,
/// passes them to [`extract_session_from_parts`], and stores the outcome
/// with [`provide_context`].
///
/// If no `Parts` are available in the context (e.g. during client-side
/// rendering), the provided value will be `Ok(None)`.
#[cfg(any(feature = "ssr", feature = "hydrate", feature = "csr"))]
pub fn provide_session_context<S: AuthStorage>(
    storage: Option<&S>,
    public_key_pem: Option<&str>,
    expected_aud: Option<&str>,
    expected_iss: Option<&str>,
) {
    let result = match use_context::<Parts>() {
        Some(parts) => {
            match extract_session_from_parts(
                &parts,
                storage,
                public_key_pem,
                expected_aud,
                expected_iss,
            ) {
                Ok(session) => Ok(session),
                Err(err) => {
                    eprintln!("Auth error: {:?}", err);
                    Err(err)
                }
            }
        }
        None => Ok(None),
    };

    provide_context(result);
}

/// Guard that retrieves the current [`UserSession`] from the Leptos context,
/// returning a [`ServerFnError`] if the user is not authenticated.
///
/// This is the primary way to protect Leptos server functions. Call it at the
/// top of any `#[server]` function to ensure the caller is logged in:
///
/// ```rust,ignore
/// #[server]
/// async fn protected_action() -> Result<String, ServerFnError> {
///     let session = expect_session()?;
///     Ok(format!("Hello, {}", session.user_id))
/// }
/// ```
///
/// # Errors
///
/// Returns descriptive [`ServerFnError`] messages depending on the failure:
///
/// - `"Unauthorized: No valid session found"` — no JWT / proxy headers present.
/// - `"Unauthorized: <detail>"` — JWT cryptographic verification failed.
/// - `"Internal Server Error: Database failure"` — storage backend error.
/// - `"Internal Server Error: Email failure: <detail>"` — email subsystem error.
/// - `"Unauthorized: No authentication context found"` — [`provide_session_context`]
///   was not called before this function.
#[cfg(any(feature = "ssr", feature = "hydrate", feature = "csr"))]
pub fn expect_session() -> Result<UserSession, ServerFnError> {
    let context_val = use_context::<Result<Option<UserSession>, AuthError>>();
    match context_val {
        Some(Ok(Some(session))) => Ok(session),
        Some(Ok(None)) => Err(ServerFnError::new("Unauthorized: No valid session found")),
        Some(Err(AuthError::Storage(_msg))) => {
            eprintln!("Auth database storage error: {}", _msg);
            Err(ServerFnError::new("Internal Server Error"))
        }
        Some(Err(AuthError::Crypto(_msg))) => {
            eprintln!("Auth cryptographic / verification error: {}", _msg);
            Err(ServerFnError::new("Unauthorized"))
        }
        Some(Err(AuthError::Email(_msg))) => {
            eprintln!("Auth email delivery error: {}", _msg);
            Err(ServerFnError::new("Internal Server Error"))
        }
        Some(Err(AuthError::Other(_msg))) => {
            eprintln!("Auth general error: {}", _msg);
            Err(ServerFnError::new("Internal Server Error"))
        }
        None => Err(ServerFnError::new(
            "Unauthorized: No authentication context found",
        )),
    }
}

/// Guard that retrieves the current [`UserSession`] **and** verifies it
/// contains the specified `role`.
///
/// This is a convenience wrapper around [`expect_session`] that additionally
/// checks [`UserSession::has_role`]. Use it to protect server functions that
/// require a specific privilege:
///
/// ```rust,ignore
/// #[server]
/// async fn admin_action() -> Result<(), ServerFnError> {
///     let _session = expect_role("admin")?;
///     // … admin-only logic …
///     Ok(())
/// }
/// ```
///
/// # Errors
///
/// - All errors from [`expect_session`] (no session, crypto failure, etc.).
/// - `"Forbidden: Requires role '<role>'"`  — the session exists but does not
///   include the requested role.
#[cfg(any(feature = "ssr", feature = "hydrate", feature = "csr"))]
pub fn expect_role(role: &str) -> Result<UserSession, ServerFnError> {
    let session = expect_session()?;
    if session.has_role(role) {
        Ok(session)
    } else {
        Err(ServerFnError::new(format!(
            "Forbidden: Requires role '{}'",
            role
        )))
    }
}

/// Returns a static status string confirming the crate is linked and operational.
///
/// Useful as a simple health-check endpoint or smoke test.
pub fn check_leptos_auth_status() -> &'static str {
    "Leptos WASI Auth is running"
}

/// The SameSite attribute of the Set-Cookie header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SameSite {
    /// Strict same-site cookie policy.
    Strict,
    /// Lax same-site cookie policy.
    Lax,
    /// None same-site cookie policy (requires Secure attribute).
    None,
}

impl SameSite {
    /// Returns the string representation of the SameSite value.
    pub fn as_str(&self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

/// Options configuring how a Set-Cookie header is built.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CookieOptions {
    /// Name of the cookie. Defaults to `__Host-jwt`.
    pub name: String,
    /// Whether the cookie is HTTP-only. Defaults to `true`.
    pub http_only: bool,
    /// Whether the cookie requires a secure context (HTTPS/WASI sandbox redirect rules). Defaults to `true`.
    pub secure: bool,
    /// The SameSite attribute value. Defaults to `SameSite::Lax`.
    pub same_site: SameSite,
    /// The path for the cookie. Defaults to `/`.
    pub path: String,
    /// Optional max age of the cookie in seconds.
    pub max_age_secs: Option<u64>,
}

impl Default for CookieOptions {
    fn default() -> Self {
        Self {
            name: "__Host-jwt".to_string(),
            http_only: true,
            secure: true,
            same_site: SameSite::Lax,
            path: "/".to_string(),
            max_age_secs: None,
        }
    }
}

/// Helper to build a Set-Cookie header string with the given token and options.
pub fn build_set_cookie_header(token: &str, options: &CookieOptions) -> String {
    let mut parts = vec![format!("{}={}", options.name, token)];

    if options.http_only {
        parts.push("HttpOnly".to_string());
    }
    if options.secure {
        parts.push("Secure".to_string());
    }
    parts.push(format!("SameSite={}", options.same_site.as_str()));
    parts.push(format!("Path={}", options.path));

    if let Some(max_age) = options.max_age_secs {
        parts.push(format!("Max-Age={}", max_age));
    }

    parts.join("; ")
}

/// Helper to build a Set-Cookie header string that clears/invalidates the cookie.
pub fn build_clear_cookie_header(options: &CookieOptions) -> String {
    let mut parts = vec![format!(
        "{}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0",
        options.name
    )];

    if options.http_only {
        parts.push("HttpOnly".to_string());
    }
    if options.secure {
        parts.push("Secure".to_string());
    }
    parts.push(format!("SameSite={}", options.same_site.as_str()));
    parts.push(format!("Path={}", options.path));

    parts.join("; ")
}

/// Helper to generate a new TOTP secret, store it in the storage backend,
/// and return the secret and the provisioning URI.
pub fn register_totp(
    email: &str,
    issuer: &str,
    storage: &impl AuthStorage,
) -> Result<(String, String), AuthError> {
    let secret = wasi_auth_core::totp::generate_totp_secret();
    storage.store_totp_secret(email, &secret)?;
    let uri = wasi_auth_core::totp::generate_totp_uri(email, &secret, issuer);
    Ok((secret, uri))
}

/// Helper to verify a TOTP code against the stored secret for the given email.
///
/// Implements RFC 6238 anti-replay code verification by blacklisting successfully
/// verified step numbers in the storage backend for the duration of the validity window.
pub fn verify_totp_login(
    email: &str,
    code: &str,
    storage: &impl AuthStorage,
) -> Result<bool, AuthError> {
    let secret = match storage.get_totp_secret(email)? {
        Some(s) => s,
        None => return Ok(false),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if let Some(step) = wasi_auth_core::totp::verify_totp(&secret, code, now)? {
        let replay_key = format!("totp:{}:{}", email, step);
        if storage.is_jti_blacklisted(&replay_key)? {
            return Ok(false); // Replay attack detected!
        }
        // Blacklist step for 90 seconds to cover drift window
        storage.blacklist_jti(&replay_key, now.saturating_add(90))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Helper to generate a signed Magic Link URL.
pub fn generate_magic_link(
    email: &str,
    base_url: &str,
    private_key_pem: &str,
    kid: Option<&str>,
    expiry_secs: u64,
    audience: &str,
    issuer: &str,
) -> Result<String, AuthError> {
    wasi_auth_core::magic_link::generate_magic_link(
        email,
        base_url,
        private_key_pem,
        kid,
        expiry_secs,
        audience,
        issuer,
    )
}

/// Helper to verify and consume a Magic Link token, returning the authenticated user's email.
pub fn verify_magic_link(
    token: &str,
    public_key_pem: &str,
    audience: &str,
    issuer: &str,
    storage: &impl AuthStorage,
) -> Result<String, AuthError> {
    wasi_auth_core::magic_link::verify_magic_link(token, public_key_pem, audience, issuer, storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;
    use wasi_auth_core::InMemoryStorage;

    static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct FailingStorage;

    impl AuthStorage for FailingStorage {
        fn store_session(
            &self,
            _id: &str,
            _uid: &str,
            _roles: &[String],
            _exp: u64,
        ) -> Result<(), AuthError> {
            Ok(())
        }
        fn get_session(&self, _id: &str) -> Result<Option<wasi_auth_core::Session>, AuthError> {
            Err(AuthError::Storage("Connection timed out".to_string()))
        }
        fn delete_session(&self, _id: &str) -> Result<(), AuthError> {
            Ok(())
        }
        fn store_otp(&self, _email: &str, _otp: &str, _exp: u64) -> Result<(), AuthError> {
            Ok(())
        }
        fn verify_otp(&self, _email: &str, _otp: &str) -> Result<bool, AuthError> {
            Ok(true)
        }
    }

    // Test proxy headers parsing when enabled
    #[test]
    fn test_proxy_headers_enabled() {
        let _lock = TEST_MUTEX.lock().unwrap();
        set_trust_proxy_headers(true);
        let (parts, _) = Request::builder()
            .header("x-user-id", "alice123")
            .header("x-user-roles", "admin, user,  ")
            .header("x-user-email", "alice@example.com")
            .header("x-user-name", "Alice")
            .body(())
            .unwrap()
            .into_parts();

        let storage: Option<&InMemoryStorage> = None;
        let session = extract_session_from_parts(&parts, storage, None, None, None)
            .unwrap()
            .unwrap();

        assert_eq!(session.user_id, "alice123");
        assert!(session.has_role("admin"));
        assert!(session.has_role("user"));
        // Check that empty role was filtered out
        assert_eq!(session.roles.len(), 2);
        assert_eq!(session.email, Some("alice@example.com".to_string()));
        assert_eq!(session.name, Some("Alice".to_string()));
    }

    // Test proxy headers parsing when disabled
    #[test]
    fn test_proxy_headers_disabled() {
        let _lock = TEST_MUTEX.lock().unwrap();
        set_trust_proxy_headers(false);
        // Clear environment variable just in case it is set
        unsafe { std::env::remove_var("TRUST_PROXY_HEADERS") };

        let (parts, _) = Request::builder()
            .header("x-user-id", "alice123")
            .header("x-user-roles", "admin, user")
            .body(())
            .unwrap()
            .into_parts();

        let storage: Option<&InMemoryStorage> = None;
        let session = extract_session_from_parts(&parts, storage, None, None, None).unwrap();

        // Should return None because proxy headers are disabled and no JWT token is provided
        assert!(session.is_none());
    }

    // Test proxy headers when enabled via environment variable
    #[test]
    fn test_proxy_headers_env_enabled() {
        let _lock = TEST_MUTEX.lock().unwrap();

        // Test with TRUST_PROXY_HEADERS
        set_trust_proxy_headers(false);
        unsafe { std::env::set_var("TRUST_PROXY_HEADERS", "1") };

        let (parts, _) = Request::builder()
            .header("x-user-id", "alice123")
            .header("x-user-roles", "admin")
            .body(())
            .unwrap()
            .into_parts();

        let storage: Option<&InMemoryStorage> = None;
        let session = extract_session_from_parts(&parts, storage, None, None, None).unwrap();
        assert!(session.is_some());
        unsafe { std::env::remove_var("TRUST_PROXY_HEADERS") };

        // Test with WASI_AUTH_TRUST_PROXY_HEADERS
        set_trust_proxy_headers(false);
        unsafe { std::env::set_var("WASI_AUTH_TRUST_PROXY_HEADERS", "true") };

        let (parts2, _) = Request::builder()
            .header("x-user-id", "bob123")
            .header("x-user-roles", "user")
            .body(())
            .unwrap()
            .into_parts();

        let session2 = extract_session_from_parts(&parts2, storage, None, None, None).unwrap();
        assert!(session2.is_some());
        unsafe { std::env::remove_var("WASI_AUTH_TRUST_PROXY_HEADERS") };
    }

    // Test role matching and sanitization
    #[test]
    fn test_role_matching_and_sanitization() {
        let roles = vec![
            "  admin  ".to_string(),
            "".to_string(),
            "user".to_string(),
            "   ".to_string(),
        ];
        let sanitized = sanitize_roles(roles);
        assert_eq!(sanitized, vec!["admin".to_string(), "user".to_string()]);

        let session = UserSession {
            user_id: "test-user".to_string(),
            roles: sanitized,
            email: None,
            name: None,
        };
        assert!(session.has_role("admin"));
        assert!(session.has_role("user"));
        assert!(!session.has_role("guest"));
    }

    fn get_test_keys_and_token(sub: &str) -> (String, String, String, String) {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
        use rsa::{RsaPrivateKey, RsaPublicKey};

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let priv_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string();
        let pub_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();

        let claims = Claims {
            sub: sub.to_string(),
            roles: vec!["user".to_string()],
            email: Some(format!("{}@example.com", sub)),
            name: Some(sub.to_string()),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600),
            iss: "my-issuer".to_string(),
            aud: "my-audience".to_string(),
            iat: 0,
            nbf: None,
            jti: None,
        };

        let token = wasi_auth_core::jwt::generate_jwt(&claims, &priv_pem, None).unwrap();
        (
            pub_pem,
            "my-audience".to_string(),
            "my-issuer".to_string(),
            token,
        )
    }

    // Test cookie & auth headers extraction
    #[test]
    fn test_cookie_and_auth_headers() {
        let (pub_pem, aud, iss, token) = get_test_keys_and_token("bob456");

        // 1. From Cookie "jwt"
        let (parts, _) = Request::builder()
            .header(http::header::COOKIE, format!("jwt={}", token))
            .body(())
            .unwrap()
            .into_parts();

        let storage: Option<&InMemoryStorage> = None;
        let session =
            extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(&aud), Some(&iss))
                .unwrap()
                .unwrap();
        assert_eq!(session.user_id, "bob456");

        // 2. From Cookie "session"
        let (parts, _) = Request::builder()
            .header(http::header::COOKIE, format!("session={}", token))
            .body(())
            .unwrap()
            .into_parts();

        let session =
            extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(&aud), Some(&iss))
                .unwrap()
                .unwrap();
        assert_eq!(session.user_id, "bob456");

        // 2a. From Cookie "__Host-jwt"
        let (parts, _) = Request::builder()
            .header(http::header::COOKIE, format!("__Host-jwt={}", token))
            .body(())
            .unwrap()
            .into_parts();

        let session =
            extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(&aud), Some(&iss))
                .unwrap()
                .unwrap();
        assert_eq!(session.user_id, "bob456");

        // 2b. From Cookie "__Host-session"
        let (parts, _) = Request::builder()
            .header(http::header::COOKIE, format!("__Host-session={}", token))
            .body(())
            .unwrap()
            .into_parts();

        let session =
            extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(&aud), Some(&iss))
                .unwrap()
                .unwrap();
        assert_eq!(session.user_id, "bob456");

        // 2c. From Cookie "__Secure-jwt"
        let (parts, _) = Request::builder()
            .header(http::header::COOKIE, format!("__Secure-jwt={}", token))
            .body(())
            .unwrap()
            .into_parts();

        let session =
            extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(&aud), Some(&iss))
                .unwrap()
                .unwrap();
        assert_eq!(session.user_id, "bob456");

        // 2d. From Cookie "__Secure-session"
        let (parts, _) = Request::builder()
            .header(http::header::COOKIE, format!("__Secure-session={}", token))
            .body(())
            .unwrap()
            .into_parts();

        let session =
            extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(&aud), Some(&iss))
                .unwrap()
                .unwrap();
        assert_eq!(session.user_id, "bob456");

        // 3. From Authorization header
        let (parts, _) = Request::builder()
            .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
            .body(())
            .unwrap()
            .into_parts();

        let session =
            extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(&aud), Some(&iss))
                .unwrap()
                .unwrap();
        assert_eq!(session.user_id, "bob456");
    }

    // Test token validation with and without keys
    #[test]
    fn test_token_validation_with_keys() {
        // Generate a real key pair and sign/verify a token using wasi-auth-core jwt module
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
        use rsa::{RsaPrivateKey, RsaPublicKey};

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let priv_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string();
        let pub_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();

        let claims = Claims {
            sub: "charlie".to_string(),
            roles: vec!["manager".to_string()],
            email: None,
            name: None,
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600),
            iss: "issuer".to_string(),
            aud: "audience".to_string(),
            iat: 0,
            nbf: None,
            jti: None,
        };

        let token = wasi_auth_core::jwt::generate_jwt(&claims, &priv_pem, None).unwrap();

        let (parts, _) = Request::builder()
            .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
            .body(())
            .unwrap()
            .into_parts();

        let storage: Option<&InMemoryStorage> = None;
        let session = extract_session_from_parts(
            &parts,
            storage,
            Some(&pub_pem),
            Some("audience"),
            Some("issuer"),
        )
        .unwrap()
        .unwrap();

        assert_eq!(session.user_id, "charlie");
        assert!(session.has_role("manager"));

        // If keys are missing (None), and unsafe-dev-fallback is active, it should succeed
        #[cfg(feature = "unsafe-dev-fallback")]
        {
            let session_fallback = extract_session_from_parts(&parts, storage, None, None, None)
                .unwrap()
                .unwrap();
            assert_eq!(session_fallback.user_id, "charlie");
        }

        // If keys are invalid (e.g. signature verification fails), it returns Err
        let bad_pub_key = pub_pem.replace("A", "B"); // Corrupt public key
        let session_bad = extract_session_from_parts(
            &parts,
            storage,
            Some(&bad_pub_key),
            Some("audience"),
            Some("issuer"),
        );
        assert!(session_bad.is_err());
    }

    // Test token validation without keys when unsafe-dev-fallback is disabled
    #[test]
    fn test_keys_missing_error() {
        let dummy_jwt = "dummy_header.dummy_claims.dummy_signature";
        let (parts, _) = Request::builder()
            .header(http::header::AUTHORIZATION, format!("Bearer {}", dummy_jwt))
            .body(())
            .unwrap()
            .into_parts();
        let storage: Option<&InMemoryStorage> = None;
        let res = extract_session_from_parts(&parts, storage, None, None, None);

        #[cfg(feature = "unsafe-dev-fallback")]
        {
            // Under unsafe-dev-fallback, this will try to parse dummy claims which will fail decoding, or return Ok(None) / Err
            // But let's check it doesn't panic.
            let _ = res;
        }

        #[cfg(not(feature = "unsafe-dev-fallback"))]
        {
            // Under not(unsafe-dev-fallback), it must return Crypto error
            assert!(res.is_err());
            match res {
                Err(AuthError::Crypto(msg)) => {
                    assert!(msg.contains("verification keys"));
                }
                _ => panic!("Expected Crypto error"),
            }
        }
    }

    // Test session lookup in storage and revocation handling
    #[test]
    fn test_storage_lookup_and_revocation() {
        let (pub_pem, aud, iss, token) = get_test_keys_and_token("dave");

        let storage = InMemoryStorage::new();
        // Initially, the session is NOT stored (or is revoked/expired)
        let (parts, _) = Request::builder()
            .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
            .body(())
            .unwrap()
            .into_parts();

        // 1. Storage provided, but session not stored -> should fail (revoked/not found)
        let res = extract_session_from_parts::<InMemoryStorage>(
            &parts,
            Some(&storage),
            Some(&pub_pem),
            Some(&aud),
            Some(&iss),
        );
        assert!(res.is_err());
        match res {
            Err(AuthError::Crypto(msg)) => {
                assert!(msg.contains("Session revoked or not found"));
            }
            _ => panic!("Expected revoked session error"),
        }

        // 2. Store the session
        storage
            .store_session(&token, "dave", &["user".to_string()], 9999999999)
            .unwrap();

        // 3. Storage provided, session stored -> should succeed
        let session = extract_session_from_parts::<InMemoryStorage>(
            &parts,
            Some(&storage),
            Some(&pub_pem),
            Some(&aud),
            Some(&iss),
        )
        .unwrap()
        .unwrap();
        assert_eq!(session.user_id, "dave");

        // 4. Revoke (delete) the session
        storage.delete_session(&token).unwrap();

        // 5. Query again -> should fail
        let res_revoked = extract_session_from_parts::<InMemoryStorage>(
            &parts,
            Some(&storage),
            Some(&pub_pem),
            Some(&aud),
            Some(&iss),
        );
        assert!(res_revoked.is_err());
    }

    // Test storage backend database failures propagation
    #[test]
    fn test_storage_database_failures_propagation() {
        let (pub_pem, aud, iss, token) = get_test_keys_and_token("dave");

        let (parts, _) = Request::builder()
            .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
            .body(())
            .unwrap()
            .into_parts();

        let storage = FailingStorage;
        let res = extract_session_from_parts(
            &parts,
            Some(&storage),
            Some(&pub_pem),
            Some(&aud),
            Some(&iss),
        );

        assert!(res.is_err());
        match res {
            Err(AuthError::Storage(msg)) => {
                assert_eq!(msg, "Connection timed out");
            }
            _ => panic!("Expected Storage error, got {:?}", res),
        }
    }

    // Test context providing and guards (expect_session, expect_role) under Leptos Owner scope
    #[cfg(any(feature = "ssr", feature = "hydrate", feature = "csr"))]
    #[test]
    fn test_leptos_context_and_guards() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let (parts, _) = Request::builder()
            .header("x-user-id", "context-user")
            .header("x-user-roles", "admin, user")
            .body(())
            .unwrap()
            .into_parts();

        set_trust_proxy_headers(true);

        let owner = Owner::new();
        owner.with(|| {
            // Provide request parts to the context
            provide_context(parts);

            // Call provide_session_context
            let storage: Option<&InMemoryStorage> = None;
            provide_session_context(storage, None, None, None);

            // Verify expect_session succeeds and contains correct data
            let session = expect_session().unwrap();
            assert_eq!(session.user_id, "context-user");

            // Verify expect_role is correct
            assert!(expect_role("admin").is_ok());
            assert!(expect_role("user").is_ok());
            assert!(expect_role("guest").is_err());
        });
    }

    // Test context providing and error propagation under Leptos Owner scope
    #[cfg(any(feature = "ssr", feature = "hydrate", feature = "csr"))]
    #[test]
    fn test_leptos_context_error_propagation() {
        let (pub_pem, aud, iss, token) = get_test_keys_and_token("fail-user");

        let (parts, _) = Request::builder()
            .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
            .body(())
            .unwrap()
            .into_parts();

        let storage = FailingStorage;

        let owner = Owner::new();
        owner.with(|| {
            provide_context(parts);

            // Provide session context using the failing storage backend
            provide_session_context(Some(&storage), Some(&pub_pem), Some(&aud), Some(&iss));

            // expect_session should return ServerFnError corresponding to the Database failure
            let res = expect_session();
            assert!(res.is_err());
            let err_msg = res.err().unwrap().to_string();
            assert!(err_msg.contains("Internal Server Error"));
            assert!(!err_msg.contains("Connection timed out"));
        });
    }

    #[test]
    fn test_cookie_precedence_order() {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
        use rsa::{RsaPrivateKey, RsaPublicKey};

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let priv_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string();
        let pub_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();

        let make_token = |sub: &str| -> String {
            let claims = Claims {
                sub: sub.to_string(),
                roles: vec!["user".to_string()],
                email: Some(format!("{}@example.com", sub)),
                name: Some(sub.to_string()),
                exp: (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 3600),
                iss: "my-issuer".to_string(),
                aud: "my-audience".to_string(),
                iat: 0,
                nbf: None,
                jti: None,
            };
            wasi_auth_core::jwt::generate_jwt(&claims, &priv_pem, None).unwrap()
        };

        let t_host_jwt = make_token("host-jwt");
        let t_host_sess = make_token("host-session");
        let t_sec_jwt = make_token("secure-jwt");
        let t_sec_sess = make_token("secure-session");
        let t_jwt = make_token("jwt");
        let t_sess = make_token("session");

        let aud = "my-audience";
        let iss = "my-issuer";
        let storage: Option<&InMemoryStorage> = None;

        // Test 1: __Host-jwt takes precedence over everything
        let (parts, _) = Request::builder()
            .header(http::header::COOKIE, format!(
                "session={}; jwt={}; __Secure-session={}; __Secure-jwt={}; __Host-session={}; __Host-jwt={}",
                t_sess, t_jwt, t_sec_sess, t_sec_jwt, t_host_sess, t_host_jwt
            ))
            .body(())
            .unwrap()
            .into_parts();
        let session =
            extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(aud), Some(iss))
                .unwrap()
                .unwrap();
        assert_eq!(session.user_id, "host-jwt");

        // Test 2: __Host-session takes precedence when __Host-jwt is absent
        let (parts, _) = Request::builder()
            .header(
                http::header::COOKIE,
                format!(
                    "session={}; jwt={}; __Secure-session={}; __Secure-jwt={}; __Host-session={}",
                    t_sess, t_jwt, t_sec_sess, t_sec_jwt, t_host_sess
                ),
            )
            .body(())
            .unwrap()
            .into_parts();
        let session =
            extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(aud), Some(iss))
                .unwrap()
                .unwrap();
        assert_eq!(session.user_id, "host-session");

        // Test 3: __Secure-jwt takes precedence when Host-* cookies are absent
        let (parts, _) = Request::builder()
            .header(
                http::header::COOKIE,
                format!(
                    "session={}; jwt={}; __Secure-session={}; __Secure-jwt={}",
                    t_sess, t_jwt, t_sec_sess, t_sec_jwt
                ),
            )
            .body(())
            .unwrap()
            .into_parts();
        let session =
            extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(aud), Some(iss))
                .unwrap()
                .unwrap();
        assert_eq!(session.user_id, "secure-jwt");

        // Test 4: __Secure-session takes precedence when Secure-jwt and Host-* are absent
        let (parts, _) = Request::builder()
            .header(
                http::header::COOKIE,
                format!(
                    "session={}; jwt={}; __Secure-session={}",
                    t_sess, t_jwt, t_sec_sess
                ),
            )
            .body(())
            .unwrap()
            .into_parts();
        let session =
            extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(aud), Some(iss))
                .unwrap()
                .unwrap();
        assert_eq!(session.user_id, "secure-session");

        // Test 5: jwt takes precedence when all prefixes are absent
        let (parts, _) = Request::builder()
            .header(
                http::header::COOKIE,
                format!("session={}; jwt={}", t_sess, t_jwt),
            )
            .body(())
            .unwrap()
            .into_parts();
        let session =
            extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(aud), Some(iss))
                .unwrap()
                .unwrap();
        assert_eq!(session.user_id, "jwt");
    }

    #[test]
    fn test_cookie_helpers() {
        let options = CookieOptions::default();
        let set_cookie = build_set_cookie_header("mytoken", &options);
        assert_eq!(
            set_cookie,
            "__Host-jwt=mytoken; HttpOnly; Secure; SameSite=Lax; Path=/"
        );

        let clear_cookie = build_clear_cookie_header(&options);
        assert_eq!(
            clear_cookie,
            "__Host-jwt=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly; Secure; SameSite=Lax; Path=/"
        );

        let custom_options = CookieOptions {
            name: "session_id".to_string(),
            http_only: false,
            secure: false,
            same_site: SameSite::Strict,
            path: "/api".to_string(),
            max_age_secs: Some(3600),
        };
        let set_custom = build_set_cookie_header("mytoken2", &custom_options);
        assert_eq!(
            set_custom,
            "session_id=mytoken2; SameSite=Strict; Path=/api; Max-Age=3600"
        );
    }

    #[test]
    fn test_leptos_totp_and_magic_link_helpers() {
        let storage = InMemoryStorage::new();
        let email = "leptos-user@example.com";
        let issuer = "LeptosTest";

        // Test TOTP helpers
        let (_secret, uri) = register_totp(email, issuer, &storage).unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("issuer=LeptosTest"));

        // Get stored secret and generate code
        let stored_secret = storage.get_totp_secret(email).unwrap().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Generate manual code using verify test logic to verify verification works
        let step = now / 30;
        let step_bytes = step.to_be_bytes();
        let decoded_secret = wasi_auth_core::totp::base32_decode(&stored_secret).unwrap();
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        let mut mac = Hmac::<Sha1>::new_from_slice(&decoded_secret).unwrap();
        mac.update(&step_bytes);
        let code_bytes = mac.finalize().into_bytes();
        let offset = (code_bytes[19] & 0x0f) as usize;
        let binary: u32 = (((code_bytes[offset] & 0x7f) as u32) << 24)
            | ((code_bytes[offset + 1] as u32) << 16)
            | ((code_bytes[offset + 2] as u32) << 8)
            | (code_bytes[offset + 3] as u32);
        let totp = binary % 1_000_000;
        let code_str = format!("{:06}", totp);

        assert!(verify_totp_login(email, &code_str, &storage).unwrap());
        // Re-verification of the same code within the validity window should fail (replay-protection)
        assert!(!verify_totp_login(email, &code_str, &storage).unwrap());

        // Test Magic Link helpers
        let mut rng = rand::thread_rng();
        use rsa::RsaPrivateKey;
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
        let private_key = RsaPrivateKey::new(&mut rng, 512).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);
        let private_key_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string();
        let public_key_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();

        let link = generate_magic_link(
            email,
            "https://example.com/magic",
            &private_key_pem,
            None,
            60,
            "my-aud",
            "my-iss",
        )
        .unwrap();

        assert!(link.starts_with("https://example.com/magic?token="));
        let token = link.split("token=").nth(1).unwrap();

        let verified =
            verify_magic_link(token, &public_key_pem, "my-aud", "my-iss", &storage).unwrap();
        assert_eq!(verified, email);
    }
}
