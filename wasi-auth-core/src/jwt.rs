use crate::AuthError;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;

/// The JWT claims payload embedded in every token issued by this crate.
///
/// Fields follow the [registered claims](https://www.rfc-editor.org/rfc/rfc7519#section-4.1)
/// specification where applicable, extended with application-specific fields
/// (`roles`, `name`, `email`).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject — typically the unique user identifier (e.g. a UUID).
    pub sub: String,
    /// Issuer — the authority that minted the token (e.g. `"my-auth-server"`).
    pub iss: String,
    /// Audience — the intended recipient service or application.
    pub aud: String,
    /// Expiration time as a Unix timestamp (seconds since epoch).
    ///
    /// During verification a **60-second leeway** is applied, so tokens are
    /// accepted until `exp + 60`.
    pub exp: u64,
    /// Issued-at time as a Unix timestamp (seconds since epoch).
    #[serde(default)]
    pub iat: u64,
    /// Not-before time as a Unix timestamp (seconds since epoch).
    #[serde(default)]
    pub nbf: Option<u64>,
    /// JWT ID — unique identifier for this token.
    #[serde(default)]
    pub jti: Option<String>,
    /// A list of role names granted to the subject (may be empty).
    pub roles: Vec<String>,
    /// Optional display name of the authenticated user.
    pub name: Option<String>,
    /// Optional email address of the authenticated user.
    pub email: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
    kid: Option<String>,
}

/// Encodes raw bytes into a **URL-safe Base64** string *without* padding.
///
/// This is the encoding specified by [RFC 7515 §2](https://www.rfc-editor.org/rfc/rfc7515#section-2)
/// for JWS/JWT segments.
pub fn base64_url_encode(data: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(data)
}

/// Decodes a **URL-safe, unpadded Base64** string back into raw bytes.
///
/// # Errors
///
/// Returns [`AuthError::Crypto`] if the input contains characters outside the
/// Base64url alphabet or is otherwise malformed.
pub fn base64_url_decode(data: &str) -> Result<Vec<u8>, AuthError> {
    BASE64_URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| AuthError::Crypto(format!("Base64url decode error: {:?}", e)))
}

/// Creates a signed **RS256** JSON Web Token.
///
/// The function builds a three-part compact JWT (`header.payload.signature`):
///
/// 1. **Header** — `{"alg":"RS256","typ":"JWT"}`, optionally including a `kid`
///    (Key ID) so verifiers can look up the correct public key via JWKS.
/// 2. **Payload** — the serialised [`Claims`].
/// 3. **Signature** — RSASSA-PKCS1-v1_5 with SHA-256 over the signing input
///    (`base64url(header).base64url(payload)`).
///
/// # Arguments
///
/// * `claims` — the token payload.
/// * `private_key_pem` — an RSA private key in **PKCS#8 PEM** format.
/// * `kid` — an optional Key ID written into the JWT header.
///
/// # Errors
///
/// Returns [`AuthError::Crypto`] if serialisation, PEM parsing, or signing
/// fails.
pub fn generate_jwt(
    claims: &Claims,
    private_key_pem: &str,
    kid: Option<&str>,
) -> Result<String, AuthError> {
    let mut claims = claims.clone();
    if claims.iat == 0 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        claims.iat = now;
    }

    let header = Header {
        alg: "RS256".to_string(),
        typ: "JWT".to_string(),
        kid: kid.map(|s| s.to_string()),
    };

    let header_json = serde_json::to_vec(&header)
        .map_err(|e| AuthError::Crypto(format!("Header serialization failed: {}", e)))?;
    let claims_json = serde_json::to_vec(&claims)
        .map_err(|e| AuthError::Crypto(format!("Claims serialization failed: {}", e)))?;

    let header_b64 = base64_url_encode(&header_json);
    let claims_b64 = base64_url_encode(&claims_json);

    let signing_input = format!("{}.{}", header_b64, claims_b64);

    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| AuthError::Crypto(format!("Invalid private key PEM: {}", e)))?;

    let mut hasher = Sha256::new();
    hasher.update(signing_input.as_bytes());
    let hashed = hasher.finalize();

    let signature = private_key
        .sign(Pkcs1v15Sign::new::<Sha256>(), &hashed)
        .map_err(|e| AuthError::Crypto(format!("JWT signing failed: {}", e)))?;

    let signature_b64 = base64_url_encode(&signature);

    Ok(format!("{}.{}", signing_input, signature_b64))
}

/// Verifies and decodes a compact RS256 JWT, returning the embedded [`Claims`].
///
/// The verification pipeline performs the following checks **in order**:
///
/// 1. **Structure** — the token must consist of exactly three Base64url-encoded
///    segments separated by `.`.
/// 2. **Algorithm** — the header `alg` field must be `"RS256"`; any other value
///    is rejected immediately (algorithm confusion protection).
/// 3. **Signature** — the RSASSA-PKCS1-v1_5/SHA-256 signature is verified
///    against the supplied `public_key_pem`.
/// 4. **Expiration** — the `exp` claim is compared to `now` with a **60-second
///    leeway** (`exp + 60 > now`). Overflow of the addition is handled safely.
/// 5. **Not Before** — if present, `claims.nbf` is verified to ensure it is
///    not in the future, with a **60-second leeway** (`nbf - 60 <= now`).
/// 6. **Audience** — `claims.aud` must exactly match `expected_aud`.
/// 7. **Issuer** — `claims.iss` must exactly match `expected_iss`.
///
/// # Arguments
///
/// * `token` — the compact JWT string (`header.payload.signature`).
/// * `public_key_pem` — the RSA public key in **SPKI PEM** format.
/// * `expected_aud` — the audience value this service expects.
/// * `expected_iss` — the issuer value this service expects.
/// * `now` — the current Unix timestamp (seconds) used for expiry comparison.
///
/// # Errors
///
/// Returns [`AuthError::Crypto`] for any validation failure (bad format,
/// unsupported algorithm, invalid signature, expired token, not-yet-valid token,
/// or audience/issuer mismatch).
/// Configuration options for JWT validation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidationOptions {
    /// The clock skew leeway (in seconds) permitted during validation.
    ///
    /// Applied when validating `exp` (expiration time) and `nbf` (not before) claims.
    pub leeway_secs: u64,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self { leeway_secs: 60 }
    }
}

/// Verifies and decodes a compact RS256 JWT, returning the embedded [`Claims`].
///
/// Wraps [`verify_jwt_with_options`] using [`ValidationOptions::default`].
pub fn verify_jwt(
    token: &str,
    public_key_pem: &str,
    expected_aud: &str,
    expected_iss: &str,
    now: u64,
) -> Result<Claims, AuthError> {
    verify_jwt_with_options(
        token,
        public_key_pem,
        expected_aud,
        expected_iss,
        now,
        &ValidationOptions::default(),
    )
}

/// Verifies and decodes a compact RS256 JWT with configurable [`ValidationOptions`].
///
/// Performs signature verification, checks the audience and issuer, and validates
/// expiration and not-before claims using the leeway specified in `options`.
pub fn verify_jwt_with_options(
    token: &str,
    public_key_pem: &str,
    expected_aud: &str,
    expected_iss: &str,
    now: u64,
    options: &ValidationOptions,
) -> Result<Claims, AuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::Crypto(
            "Invalid token format: expected 3 parts".to_string(),
        ));
    }

    let header_b64 = parts[0];
    let claims_b64 = parts[1];
    let signature_b64 = parts[2];

    let header_json = base64_url_decode(header_b64)?;
    let header: Header = serde_json::from_slice(&header_json)
        .map_err(|e| AuthError::Crypto(format!("Failed to parse header JSON: {}", e)))?;
    if header.alg != "RS256" {
        return Err(AuthError::Crypto(format!(
            "Unsupported algorithm: {}, expected RS256",
            header.alg
        )));
    }

    let signing_input = format!("{}.{}", header_b64, claims_b64);
    let signature = base64_url_decode(signature_b64)?;

    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .map_err(|e| AuthError::Crypto(format!("Invalid public key PEM: {}", e)))?;

    let mut hasher = Sha256::new();
    hasher.update(signing_input.as_bytes());
    let hashed = hasher.finalize();

    public_key
        .verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, &signature)
        .map_err(|e| AuthError::Crypto(format!("JWT signature verification failed: {}", e)))?;

    let claims_json = base64_url_decode(claims_b64)?;
    let claims: Claims = serde_json::from_slice(&claims_json)
        .map_err(|e| AuthError::Crypto(format!("Failed to deserialize Claims: {}", e)))?;

    let is_expired = if let Some(exp_limit) = claims.exp.checked_add(options.leeway_secs) {
        exp_limit <= now
    } else {
        claims.exp <= now
    };
    if is_expired {
        return Err(AuthError::Crypto("Token has expired".to_string()));
    }

    if let Some(nbf) = claims.nbf {
        let is_before = if let Some(nbf_limit) = nbf.checked_sub(options.leeway_secs) {
            now < nbf_limit
        } else {
            now < nbf
        };
        if is_before {
            return Err(AuthError::Crypto("Token is not valid yet".to_string()));
        }
    }

    if claims.aud != expected_aud {
        return Err(AuthError::Crypto(format!(
            "Audience mismatch: expected {}, got {}",
            expected_aud, claims.aud
        )));
    }

    if claims.iss != expected_iss {
        return Err(AuthError::Crypto(format!(
            "Issuer mismatch: expected {}, got {}",
            expected_iss, claims.iss
        )));
    }

    Ok(claims)
}

/// Extracts the **Key ID** (`kid`) from a JWT header without performing any
/// cryptographic verification.
///
/// This is typically used as a first step in JWKS-based verification: parse the
/// `kid`, look up the matching public key from the JWKS endpoint, then pass that
/// key to [`verify_jwt`].
///
/// # Errors
///
/// Returns [`AuthError::Crypto`] if the token has fewer than three segments or
/// if the header cannot be decoded / parsed.
pub fn extract_kid(token: &str) -> Result<Option<String>, AuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 3 {
        return Err(AuthError::Crypto("Invalid token format".to_string()));
    }
    let header_json = base64_url_decode(parts[0])?;
    let header: Header = serde_json::from_slice(&header_json)
        .map_err(|e| AuthError::Crypto(format!("Failed to parse header JSON: {}", e)))?;
    Ok(header.kid)
}

/// A thread-safe cache for RSA public keys loaded dynamically from a JWKS endpoint.
///
/// Keeps verified public keys in memory and retrieves new keys by calling the JWKS URL
/// if an unknown `kid` is requested. Includes a fetch cooldown limit to prevent DoS attacks.
#[derive(Debug)]
pub struct JwksKeyCache {
    keys: RwLock<HashMap<String, RsaPublicKey>>,
    jwks_url: String,
    last_fetched: RwLock<u64>,
    cooldown_secs: u64,
}

impl JwksKeyCache {
    /// Creates a new `JwksKeyCache` for the given JWKS URL with a default 30-second cooldown.
    pub fn new(jwks_url: String) -> Self {
        Self::with_cooldown(jwks_url, 30)
    }

    /// Creates a new `JwksKeyCache` with a custom fetch cooldown in seconds.
    pub fn with_cooldown(jwks_url: String, cooldown_secs: u64) -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            jwks_url,
            last_fetched: RwLock::new(0),
            cooldown_secs,
        }
    }

    /// Retrieves an RSA public key matching `kid` from the cache, fetching and parsing
    /// the JWKS from the issuer if it is not cached and the fetch cooldown has expired.
    ///
    /// Returns `None` if the key is not present in the fetched key set, is not a valid RSA key,
    /// or if the fetch cooldown is active.
    pub fn get_key(
        &self,
        kid: &str,
        client: &impl crate::oauth::HttpClient,
    ) -> Result<Option<RsaPublicKey>, AuthError> {
        {
            let map = self
                .keys
                .read()
                .map_err(|e| AuthError::Crypto(format!("Failed to acquire read lock on keys: {}", e)))?;
            if let Some(key) = map.get(kid) {
                return Ok(Some(key.clone()));
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        {
            let mut last_fetch = self
                .last_fetched
                .write()
                .map_err(|e| AuthError::Crypto(format!("Failed to acquire write lock on last_fetched: {}", e)))?;
            if now.saturating_sub(*last_fetch) < self.cooldown_secs {
                // Fetch cooldown active, return None immediately to avoid outbound HTTP DoS
                return Ok(None);
            }
            *last_fetch = now;
        }

        // Fetch JWKS if key is not found in cache and cooldown has expired
        let headers = [("Accept", "application/json")];
        let jwks_json = client.get(&self.jwks_url, &headers)?;

        #[derive(Deserialize)]
        struct JwksJson {
            keys: Vec<JwkJson>,
        }

        #[derive(Deserialize)]
        struct JwkJson {
            kty: String,
            kid: String,
            n: String,
            e: String,
        }

        let jwks: JwksJson = serde_json::from_str(&jwks_json)
            .map_err(|e| AuthError::Crypto(format!("Failed to parse JWKS JSON: {}", e)))?;

        let mut map = self
            .keys
            .write()
            .map_err(|e| AuthError::Crypto(format!("Failed to acquire write lock on keys: {}", e)))?;
        for jwk in jwks.keys {
            if jwk.kty == "RSA" {
                if let (Ok(n_bytes), Ok(e_bytes)) = (
                    base64_url_decode(&jwk.n),
                    base64_url_decode(&jwk.e),
                ) {
                    let n = rsa::BigUint::from_bytes_be(&n_bytes);
                    let e = rsa::BigUint::from_bytes_be(&e_bytes);
                    if let Ok(pub_key) = RsaPublicKey::new(n, e) {
                        map.insert(jwk.kid.clone(), pub_key);
                    }
                }
            }
        }

        Ok(map.get(kid).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_generation_and_verification() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 512).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        use rsa::pkcs8::EncodePrivateKey;
        use rsa::pkcs8::EncodePublicKey;
        let priv_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();
        let pub_pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();

        let claims = Claims {
            sub: "user-123".to_string(),
            iss: "my-auth-server".to_string(),
            aud: "my-app".to_string(),
            exp: 2000000000,
            iat: 0,
            nbf: None,
            jti: None,
            roles: vec!["admin".to_string()],
            name: Some("Alice".to_string()),
            email: Some("alice@example.com".to_string()),
        };

        let token = generate_jwt(&claims, &priv_pem, Some("key-1")).unwrap();
        let kid = extract_kid(&token).unwrap();
        assert_eq!(kid, Some("key-1".to_string()));

        let verified =
            verify_jwt(&token, &pub_pem, "my-app", "my-auth-server", 1000000000).unwrap();
        assert_eq!(verified.sub, "user-123");
        assert_eq!(verified.roles, vec!["admin".to_string()]);
        assert_ne!(verified.iat, 0); // verify iat was populated
    }

    #[test]
    fn test_jwt_not_before() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 512).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        use rsa::pkcs8::EncodePrivateKey;
        use rsa::pkcs8::EncodePublicKey;
        let priv_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();
        let pub_pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();

        let claims = Claims {
            sub: "user-123".to_string(),
            iss: "my-auth-server".to_string(),
            aud: "my-app".to_string(),
            exp: 2000,
            iat: 1000,
            nbf: Some(1500),
            jti: Some("jwt-id-123".to_string()),
            roles: vec![],
            name: None,
            email: None,
        };

        let token = generate_jwt(&claims, &priv_pem, None).unwrap();

        // 1. Verification at now = 1439 (more than 60s skew before nbf = 1500) -> should fail
        let verified = verify_jwt(&token, &pub_pem, "my-app", "my-auth-server", 1439);
        assert!(verified.is_err());
        assert!(verified
            .unwrap_err()
            .to_string()
            .contains("Token is not valid yet"));

        // 2. Verification at now = 1440 (exactly within 60s skew leeway before nbf = 1500) -> should pass
        let verified = verify_jwt(&token, &pub_pem, "my-app", "my-auth-server", 1440);
        assert!(verified.is_ok());

        // 3. Verification at now = 1500 (exactly at nbf) -> should pass
        let verified = verify_jwt(&token, &pub_pem, "my-app", "my-auth-server", 1500);
        assert!(verified.is_ok());
    }

    #[test]
    fn test_jwt_expiration_with_clock_skew() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 512).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        use rsa::pkcs8::EncodePrivateKey;
        use rsa::pkcs8::EncodePublicKey;
        let priv_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();
        let pub_pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();

        let claims = Claims {
            sub: "user-123".to_string(),
            iss: "my-auth-server".to_string(),
            aud: "my-app".to_string(),
            exp: 1000,
            iat: 0,
            nbf: None,
            jti: None,
            roles: vec![],
            name: None,
            email: None,
        };

        let token = generate_jwt(&claims, &priv_pem, None).unwrap();

        // 1. Within leeway (now = 1059), should pass
        let verified = verify_jwt(&token, &pub_pem, "my-app", "my-auth-server", 1059);
        assert!(verified.is_ok());

        // 2. Exactly at or past leeway (now = 1060), should fail
        let verified = verify_jwt(&token, &pub_pem, "my-app", "my-auth-server", 1060);
        assert!(verified.is_err());
    }

    #[test]
    fn test_jwt_invalid_algorithm() {
        let header = Header {
            alg: "HS256".to_string(),
            typ: "JWT".to_string(),
            kid: None,
        };
        let claims = Claims {
            sub: "user-123".to_string(),
            iss: "my-auth-server".to_string(),
            aud: "my-app".to_string(),
            exp: 2000000000,
            iat: 0,
            nbf: None,
            jti: None,
            roles: vec![],
            name: None,
            email: None,
        };

        let header_json = serde_json::to_vec(&header).unwrap();
        let claims_json = serde_json::to_vec(&claims).unwrap();
        let token = format!(
            "{}.{}.dummysignature",
            base64_url_encode(&header_json),
            base64_url_encode(&claims_json)
        );

        let err =
            verify_jwt(&token, "dummy_key", "my-app", "my-auth-server", 1000000000).unwrap_err();
        assert!(err.to_string().contains("Unsupported algorithm"));
    }

    #[test]
    fn test_extract_kid_invalid_format() {
        let token = "part1.part2";
        let err = extract_kid(token).unwrap_err();
        assert!(err.to_string().contains("Invalid token format"));
    }

    #[test]
    fn test_jwt_expiration_overflow() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 512).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        use rsa::pkcs8::EncodePrivateKey;
        use rsa::pkcs8::EncodePublicKey;
        let priv_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();
        let pub_pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();

        let claims = Claims {
            sub: "user-123".to_string(),
            iss: "my-auth-server".to_string(),
            aud: "my-app".to_string(),
            exp: u64::MAX,
            iat: 0,
            nbf: None,
            jti: None,
            roles: vec![],
            name: None,
            email: None,
        };

        let token = generate_jwt(&claims, &priv_pem, None).unwrap();
        let verified = verify_jwt(&token, &pub_pem, "my-app", "my-auth-server", 1000000000);
        assert!(verified.is_ok());

        let verified_expired = verify_jwt(&token, &pub_pem, "my-app", "my-auth-server", u64::MAX);
        assert!(verified_expired.is_err());
        let err = verified_expired.unwrap_err();
        assert!(err.to_string().contains("Token has expired"));
    }

    #[test]
    fn test_jwks_key_cache() {
        use rsa::traits::PublicKeyParts;

        struct MockJwkHttpClient {
            response_body: String,
        }

        impl crate::oauth::HttpClient for MockJwkHttpClient {
            fn post(&self, _url: &str, _headers: &[(&str, &str)], _body: &str) -> Result<String, AuthError> {
                unimplemented!()
            }

            fn get(&self, _url: &str, _headers: &[(&str, &str)]) -> Result<String, AuthError> {
                Ok(self.response_body.clone())
            }
        }

        let mut rng = rand::thread_rng();
        let private_key = RsaPublicKey::from(&RsaPrivateKey::new(&mut rng, 512).unwrap());

        let n_b64 = base64_url_encode(&private_key.n().to_bytes_be());
        let e_b64 = base64_url_encode(&private_key.e().to_bytes_be());
        let jwks_json = format!(
            r#"{{"keys": [{{"kty": "RSA", "kid": "key-1", "n": "{}", "e": "{}"}}]}}"#,
            n_b64, e_b64
        );

        let client = MockJwkHttpClient {
            response_body: jwks_json,
        };

        let cache = JwksKeyCache::new("https://example.com/jwks".to_string());

        // 1. First fetch should trigger client lookup and fetch key successfully
        let fetched_key = cache.get_key("key-1", &client).unwrap().unwrap();
        assert_eq!(fetched_key.n(), private_key.n());
        assert_eq!(fetched_key.e(), private_key.e());

        // 2. Second fetch should hit the cache (which we can verify by using a client with empty response)
        let empty_client = MockJwkHttpClient {
            response_body: "".to_string(),
        };
        let cached_key = cache.get_key("key-1", &empty_client).unwrap().unwrap();
        assert_eq!(cached_key.n(), private_key.n());

        // 3. Fetching unknown kid should return None due to cooldown
        let unknown_key = cache.get_key("key-unknown", &empty_client).unwrap();
        assert!(unknown_key.is_none());
    }

    #[test]
    fn test_jwks_key_cache_cooldown() {
        struct CounterHttpClient {
            count: std::sync::atomic::AtomicUsize,
        }
        impl crate::oauth::HttpClient for CounterHttpClient {
            fn post(&self, _url: &str, _headers: &[(&str, &str)], _body: &str) -> Result<String, AuthError> {
                unimplemented!()
            }
            fn get(&self, _url: &str, _headers: &[(&str, &str)]) -> Result<String, AuthError> {
                self.count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(r#"{"keys": []}"#.to_string())
            }
        }

        let client = CounterHttpClient {
            count: std::sync::atomic::AtomicUsize::new(0),
        };

        // Cache with 30s cooldown
        let cache = JwksKeyCache::with_cooldown("https://example.com/jwks".to_string(), 30);

        // Fetch 1: should fetch (count becomes 1)
        let res1 = cache.get_key("missing", &client).unwrap();
        assert!(res1.is_none());
        assert_eq!(client.count.load(std::sync::atomic::Ordering::Relaxed), 1);

        // Fetch 2 (immediate): should hit cooldown and return None without fetching (count stays 1)
        let res2 = cache.get_key("missing2", &client).unwrap();
        assert!(res2.is_none());
        assert_eq!(client.count.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
}
