use http::request::Parts;
#[cfg(any(feature = "ssr", feature = "hydrate", feature = "csr"))]
use leptos::prelude::*;
use wasi_auth_core::jwt::verify_jwt;
#[cfg(any(feature = "unsafe-dev-fallback", test))]
use wasi_auth_core::jwt::Claims;
use wasi_auth_core::{AuthError, AuthStorage};

use std::sync::atomic::{AtomicBool, Ordering};

static TRUST_PROXY_HEADERS: AtomicBool = AtomicBool::new(false);

/// Programmatically enable or disable trusting proxy headers (like `X-User-Id`, `X-User-Roles`).
pub fn set_trust_proxy_headers(trust: bool) {
    TRUST_PROXY_HEADERS.store(trust, Ordering::Relaxed);
}

/// Check if proxy headers should be trusted, looking at the static atomic flag and the `TRUST_PROXY_HEADERS` environment variable.
pub fn is_trust_proxy_headers() -> bool {
    TRUST_PROXY_HEADERS.load(Ordering::Relaxed)
        || std::env::var("TRUST_PROXY_HEADERS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false)
        || std::env::var("WASI_AUTH_TRUST_PROXY_HEADERS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserSession {
    pub user_id: String,
    pub roles: Vec<String>,
    pub email: Option<String>,
    pub name: Option<String>,
}

impl UserSession {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// Clean up role strings by trimming whitespace and filtering out empty strings.
pub fn sanitize_roles(roles: Vec<String>) -> Vec<String> {
    roles
        .into_iter()
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect()
}

pub fn extract_cookie(cookie_header: &str, name: &str) -> Option<String> {
    for cookie in cookie_header.split(';') {
        let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
        if parts.len() == 2 && parts[0] == name {
            return Some(parts[1].to_string());
        }
    }
    None
}

pub fn extract_session_from_parts<S: AuthStorage>(
    parts: &Parts,
    storage: Option<&S>,
    public_key_pem: Option<&str>,
    expected_aud: Option<&str>,
    expected_iss: Option<&str>,
) -> Result<Option<UserSession>, AuthError> {
    // 1. Interceptor/Gateway Mode: Check X-User-Id and X-User-Roles headers first
    if is_trust_proxy_headers() {
        if let Some(user_id_val) = parts.headers.get("x-user-id") {
            if let Ok(user_id) = user_id_val.to_str() {
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
        }
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

        let claims = verify_jwt(&token, pub_key, aud, iss, now)?;

        // If a storage backend is provided, verify session is active
        if let Some(store) = storage {
            if store.get_session(&token)?.is_none() {
                return Err(AuthError::Crypto(
                    "Session revoked or not found in storage".to_string(),
                ));
            }
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
            eprintln!("WARNING: Running in unsafe-dev-fallback mode! Token signatures are not verified.");
            // Ensure the token storage lookup is always executed if storage is provided, even in dev mode unverified fallback.
            if let Some(store) = storage {
                if store.get_session(&token)?.is_none() {
                    return Err(AuthError::Crypto(
                        "Session revoked or not found in storage".to_string(),
                    ));
                }
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
            Ok(None)
        }
        #[cfg(not(feature = "unsafe-dev-fallback"))]
        {
            Err(AuthError::Crypto(
                "Missing cryptographic verification keys".to_string(),
            ))
        }
    }
}

#[cfg(any(feature = "ssr", feature = "hydrate", feature = "csr"))]
pub fn provide_session_context<S: AuthStorage>(
    storage: Option<&S>,
    public_key_pem: Option<&str>,
    expected_aud: Option<&str>,
    expected_iss: Option<&str>,
) {
    let result = match use_context::<Parts>() {
        Some(parts) => {
            match extract_session_from_parts(&parts, storage, public_key_pem, expected_aud, expected_iss) {
                Ok(session) => Ok(session),
                Err(err) => {
                    eprintln!("Auth error: {:?}", err);
                    Err(err)
                }
            }
        }
        None => {
            Ok(None)
        }
    };

    provide_context(result);
}

#[cfg(any(feature = "ssr", feature = "hydrate", feature = "csr"))]
pub fn expect_session() -> Result<UserSession, ServerFnError> {
    let context_val = use_context::<Result<Option<UserSession>, AuthError>>();
    match context_val {
        Some(Ok(Some(session))) => Ok(session),
        Some(Ok(None)) => Err(ServerFnError::new("Unauthorized: No valid session found")),
        Some(Err(AuthError::Storage(_msg))) => {
            Err(ServerFnError::new("Internal Server Error: Database failure"))
        }
        Some(Err(AuthError::Crypto(msg))) => {
            Err(ServerFnError::new(format!("Unauthorized: {}", msg)))
        }
        Some(Err(AuthError::Email(msg))) => {
            Err(ServerFnError::new(format!(
                "Internal Server Error: Email failure: {}",
                msg
            )))
        }
        Some(Err(AuthError::Other(msg))) => {
            Err(ServerFnError::new(format!(
                "Internal Server Error: {}",
                msg
            )))
        }
        None => Err(ServerFnError::new(
            "Unauthorized: No authentication context found",
        )),
    }
}

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

pub fn check_leptos_auth_status() -> &'static str {
    "Leptos WASI Auth is running"
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;
    use wasi_auth_core::InMemoryStorage;

    static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct FailingStorage;

    impl AuthStorage for FailingStorage {
        fn store_session(&self, _id: &str, _uid: &str, _roles: &[String], _exp: u64) -> Result<(), AuthError> {
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
        std::env::remove_var("TRUST_PROXY_HEADERS");

        let (parts, _) = Request::builder()
            .header("x-user-id", "alice123")
            .header("x-user-roles", "admin, user")
            .body(())
            .unwrap()
            .into_parts();

        let storage: Option<&InMemoryStorage> = None;
        let session = extract_session_from_parts(&parts, storage, None, None, None)
            .unwrap();

        // Should return None because proxy headers are disabled and no JWT token is provided
        assert!(session.is_none());
    }

    // Test proxy headers when enabled via environment variable
    #[test]
    fn test_proxy_headers_env_enabled() {
        let _lock = TEST_MUTEX.lock().unwrap();
        
        // Test with TRUST_PROXY_HEADERS
        set_trust_proxy_headers(false);
        std::env::set_var("TRUST_PROXY_HEADERS", "1");

        let (parts, _) = Request::builder()
            .header("x-user-id", "alice123")
            .header("x-user-roles", "admin")
            .body(())
            .unwrap()
            .into_parts();

        let storage: Option<&InMemoryStorage> = None;
        let session = extract_session_from_parts(&parts, storage, None, None, None)
            .unwrap();
        assert!(session.is_some());
        std::env::remove_var("TRUST_PROXY_HEADERS");

        // Test with WASI_AUTH_TRUST_PROXY_HEADERS
        set_trust_proxy_headers(false);
        std::env::set_var("WASI_AUTH_TRUST_PROXY_HEADERS", "true");

        let (parts2, _) = Request::builder()
            .header("x-user-id", "bob123")
            .header("x-user-roles", "user")
            .body(())
            .unwrap()
            .into_parts();

        let session2 = extract_session_from_parts(&parts2, storage, None, None, None)
            .unwrap();
        assert!(session2.is_some());
        std::env::remove_var("WASI_AUTH_TRUST_PROXY_HEADERS");
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
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let priv_pem = private_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let pub_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();

        let claims = Claims {
            sub: sub.to_string(),
            roles: vec!["user".to_string()],
            email: Some(format!("{}@example.com", sub)),
            name: Some(sub.to_string()),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() + 3600),
            iss: "my-issuer".to_string(),
            aud: "my-audience".to_string(),
        };

        let token = wasi_auth_core::jwt::generate_jwt(&claims, &priv_pem, None).unwrap();
        (pub_pem, "my-audience".to_string(), "my-issuer".to_string(), token)
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
        let session = extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(&aud), Some(&iss))
            .unwrap()
            .unwrap();
        assert_eq!(session.user_id, "bob456");

        // 2. From Cookie "session"
        let (parts, _) = Request::builder()
            .header(http::header::COOKIE, format!("session={}", token))
            .body(())
            .unwrap()
            .into_parts();

        let session = extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(&aud), Some(&iss))
            .unwrap()
            .unwrap();
        assert_eq!(session.user_id, "bob456");

        // 2a. From Cookie "__Host-jwt"
        let (parts, _) = Request::builder()
            .header(http::header::COOKIE, format!("__Host-jwt={}", token))
            .body(())
            .unwrap()
            .into_parts();

        let session = extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(&aud), Some(&iss))
            .unwrap()
            .unwrap();
        assert_eq!(session.user_id, "bob456");

        // 2b. From Cookie "__Host-session"
        let (parts, _) = Request::builder()
            .header(http::header::COOKIE, format!("__Host-session={}", token))
            .body(())
            .unwrap()
            .into_parts();

        let session = extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(&aud), Some(&iss))
            .unwrap()
            .unwrap();
        assert_eq!(session.user_id, "bob456");

        // 2c. From Cookie "__Secure-jwt"
        let (parts, _) = Request::builder()
            .header(http::header::COOKIE, format!("__Secure-jwt={}", token))
            .body(())
            .unwrap()
            .into_parts();

        let session = extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(&aud), Some(&iss))
            .unwrap()
            .unwrap();
        assert_eq!(session.user_id, "bob456");

        // 2d. From Cookie "__Secure-session"
        let (parts, _) = Request::builder()
            .header(http::header::COOKIE, format!("__Secure-session={}", token))
            .body(())
            .unwrap()
            .into_parts();

        let session = extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(&aud), Some(&iss))
            .unwrap()
            .unwrap();
        assert_eq!(session.user_id, "bob456");

        // 3. From Authorization header
        let (parts, _) = Request::builder()
            .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
            .body(())
            .unwrap()
            .into_parts();

        let session = extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(&aud), Some(&iss))
            .unwrap()
            .unwrap();
        assert_eq!(session.user_id, "bob456");
    }

    // Test token validation with and without keys
    #[test]
    fn test_token_validation_with_keys() {
        // Generate a real key pair and sign/verify a token using wasi-auth-core jwt module
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let priv_pem = private_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let pub_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();

        let claims = Claims {
            sub: "charlie".to_string(),
            roles: vec!["manager".to_string()],
            email: None,
            name: None,
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() + 3600),
            iss: "issuer".to_string(),
            aud: "audience".to_string(),
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
            let session_fallback = extract_session_from_parts(
                &parts,
                storage,
                None,
                None,
                None,
            )
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
        let res = extract_session_from_parts::<InMemoryStorage>(&parts, Some(&storage), Some(&pub_pem), Some(&aud), Some(&iss));
        assert!(res.is_err());
        match res {
            Err(AuthError::Crypto(msg)) => {
                assert!(msg.contains("Session revoked or not found"));
            }
            _ => panic!("Expected revoked session error"),
        }

        // 2. Store the session
        storage.store_session(&token, "dave", &["user".to_string()], 9999999999).unwrap();

        // 3. Storage provided, session stored -> should succeed
        let session = extract_session_from_parts::<InMemoryStorage>(&parts, Some(&storage), Some(&pub_pem), Some(&aud), Some(&iss))
            .unwrap()
            .unwrap();
        assert_eq!(session.user_id, "dave");

        // 4. Revoke (delete) the session
        storage.delete_session(&token).unwrap();

        // 5. Query again -> should fail
        let res_revoked = extract_session_from_parts::<InMemoryStorage>(&parts, Some(&storage), Some(&pub_pem), Some(&aud), Some(&iss));
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
        let res = extract_session_from_parts(&parts, Some(&storage), Some(&pub_pem), Some(&aud), Some(&iss));

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
            assert!(err_msg.contains("Internal Server Error: Database failure"));
            assert!(!err_msg.contains("Connection timed out"));
        });
    }

    #[test]
    fn test_cookie_precedence_order() {
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let priv_pem = private_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
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
                    .as_secs() + 3600),
                iss: "my-issuer".to_string(),
                aud: "my-audience".to_string(),
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
        let session = extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(aud), Some(iss))
            .unwrap()
            .unwrap();
        assert_eq!(session.user_id, "host-jwt");

        // Test 2: __Host-session takes precedence when __Host-jwt is absent
        let (parts, _) = Request::builder()
            .header(http::header::COOKIE, format!(
                "session={}; jwt={}; __Secure-session={}; __Secure-jwt={}; __Host-session={}",
                t_sess, t_jwt, t_sec_sess, t_sec_jwt, t_host_sess
            ))
            .body(())
            .unwrap()
            .into_parts();
        let session = extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(aud), Some(iss))
            .unwrap()
            .unwrap();
        assert_eq!(session.user_id, "host-session");

        // Test 3: __Secure-jwt takes precedence when Host-* cookies are absent
        let (parts, _) = Request::builder()
            .header(http::header::COOKIE, format!(
                "session={}; jwt={}; __Secure-session={}; __Secure-jwt={}",
                t_sess, t_jwt, t_sec_sess, t_sec_jwt
            ))
            .body(())
            .unwrap()
            .into_parts();
        let session = extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(aud), Some(iss))
            .unwrap()
            .unwrap();
        assert_eq!(session.user_id, "secure-jwt");

        // Test 4: __Secure-session takes precedence when Secure-jwt and Host-* are absent
        let (parts, _) = Request::builder()
            .header(http::header::COOKIE, format!(
                "session={}; jwt={}; __Secure-session={}",
                t_sess, t_jwt, t_sec_sess
            ))
            .body(())
            .unwrap()
            .into_parts();
        let session = extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(aud), Some(iss))
            .unwrap()
            .unwrap();
        assert_eq!(session.user_id, "secure-session");

        // Test 5: jwt takes precedence when all prefixes are absent
        let (parts, _) = Request::builder()
            .header(http::header::COOKIE, format!(
                "session={}; jwt={}",
                t_sess, t_jwt
            ))
            .body(())
            .unwrap()
            .into_parts();
        let session = extract_session_from_parts(&parts, storage, Some(&pub_pem), Some(aud), Some(iss))
            .unwrap()
            .unwrap();
        assert_eq!(session.user_id, "jwt");
    }
}

