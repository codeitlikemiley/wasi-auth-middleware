use wasi_auth_core::jwt::{base64_url_encode, generate_jwt, verify_jwt, Claims};
use wasi_auth_core::oauth::{HttpClient, OAuthConfig, Oauth2Client};
use wasi_auth_core::otp::{send_and_store_otp, verify_otp};
use wasi_auth_core::{AuthError, AuthStorage, InMemoryStorage, StdoutEmail};

use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

// Helper to generate RSA key pair
fn generate_keys() -> (String, String) {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);

    let priv_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();
    let pub_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    (priv_pem, pub_pem)
}

// Helper to create claims
fn make_claims(exp: u64) -> Claims {
    Claims {
        sub: "user-123".to_string(),
        iss: "test-issuer".to_string(),
        aud: "test-audience".to_string(),
        exp,
        roles: vec!["user".to_string()],
        name: Some("Test User".to_string()),
        email: Some("test@example.com".to_string()),
    }
}

// ----------------- JWT Validation Stress Tests -----------------

#[test]
fn test_jwt_alg_none_confusion() {
    let (_, pub_pem) = generate_keys();
    let claims = make_claims(2000000000);

    let header_json = serde_json::json!({
        "alg": "none",
        "typ": "JWT"
    });
    let claims_json = serde_json::to_vec(&claims).unwrap();

    let token = format!(
        "{}.{}.",
        base64_url_encode(&serde_json::to_vec(&header_json).unwrap()),
        base64_url_encode(&claims_json)
    );

    let res = verify_jwt(&token, &pub_pem, "test-audience", "test-issuer", 1000000000);
    assert!(res.is_err(), "verify_jwt should reject alg='none'");
    let err = res.unwrap_err();
    assert!(err.to_string().contains("Unsupported algorithm"));
}

#[test]
fn test_jwt_alg_hs256_confusion() {
    let (_, pub_pem) = generate_keys();
    let claims = make_claims(2000000000);

    let header_json = serde_json::json!({
        "alg": "HS256",
        "typ": "JWT"
    });
    let claims_json = serde_json::to_vec(&claims).unwrap();

    let token = format!(
        "{}.{}.dummysignature",
        base64_url_encode(&serde_json::to_vec(&header_json).unwrap()),
        base64_url_encode(&claims_json)
    );

    let res = verify_jwt(&token, &pub_pem, "test-audience", "test-issuer", 1000000000);
    assert!(res.is_err(), "verify_jwt should reject alg='HS256'");
    let err = res.unwrap_err();
    assert!(err.to_string().contains("Unsupported algorithm"));
}

#[test]
fn test_jwt_invalid_signature() {
    let (priv_pem, pub_pem) = generate_keys();
    let claims = make_claims(2000000000);

    let valid_token = generate_jwt(&claims, &priv_pem, None).unwrap();
    let parts: Vec<&str> = valid_token.split('.').collect();

    // Corrupt the signature part
    let invalid_token = format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        base64_url_encode(b"invalid_signature_bytes")
    );

    let res = verify_jwt(
        &invalid_token,
        &pub_pem,
        "test-audience",
        "test-issuer",
        1000000000,
    );
    assert!(res.is_err(), "verify_jwt should reject invalid signature");
    let err = res.unwrap_err();
    assert!(
        err.to_string().contains("verification failed") || err.to_string().contains("decode error")
    );
}

#[test]
fn test_jwt_truncated_signature() {
    let (priv_pem, pub_pem) = generate_keys();
    let claims = make_claims(2000000000);

    let valid_token = generate_jwt(&claims, &priv_pem, None).unwrap();
    let parts: Vec<&str> = valid_token.split('.').collect();

    // Truncate signature to very short string
    let truncated_token = format!("{}.{}.abc", parts[0], parts[1]);

    let res = verify_jwt(
        &truncated_token,
        &pub_pem,
        "test-audience",
        "test-issuer",
        1000000000,
    );
    assert!(res.is_err(), "verify_jwt should reject truncated signature");
}

#[test]
fn test_jwt_exp_u64_max_overflow() {
    let (priv_pem, pub_pem) = generate_keys();

    // Case 1: exp = u64::MAX
    let claims_max = make_claims(u64::MAX);
    let token_max = generate_jwt(&claims_max, &priv_pem, None).unwrap();
    let res = verify_jwt(
        &token_max,
        &pub_pem,
        "test-audience",
        "test-issuer",
        1000000000,
    );
    assert!(res.is_ok());

    // Case 2: exp = u64::MAX - 59 (still overflows exp + 60)
    let claims_overflow = make_claims(u64::MAX - 59);
    let token_overflow = generate_jwt(&claims_overflow, &priv_pem, None).unwrap();
    let res = verify_jwt(
        &token_overflow,
        &pub_pem,
        "test-audience",
        "test-issuer",
        1000000000,
    );
    assert!(res.is_ok());

    // Case 3: exp = u64::MAX - 60 (exactly exp + 60 = u64::MAX, no overflow)
    let claims_boundary = make_claims(u64::MAX - 60);
    let token_boundary = generate_jwt(&claims_boundary, &priv_pem, None).unwrap();
    let res = verify_jwt(
        &token_boundary,
        &pub_pem,
        "test-audience",
        "test-issuer",
        1000000000,
    );
    // This should verify successfully because exp + 60 = u64::MAX, which is > 1000000000
    assert!(
        res.is_ok(),
        "exp = u64::MAX - 60 should verify successfully"
    );
}

#[test]
fn test_jwt_skew_now_u64_max() {
    let (priv_pem, pub_pem) = generate_keys();
    let claims = make_claims(2000000000);

    let token = generate_jwt(&claims, &priv_pem, None).unwrap();
    // Verification when now is u64::MAX should fail (expired) but not panic/crash
    let res = verify_jwt(&token, &pub_pem, "test-audience", "test-issuer", u64::MAX);
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("Token has expired"));
}

// ----------------- Email OTP Engine Stress Tests -----------------

#[test]
fn test_otp_expired() {
    let storage = InMemoryStorage::new();
    let email = "expired@example.com";

    // Store OTP that expires in the past (expiry = now - 10)
    storage.store_otp(email, "123456", 990).unwrap();

    // The verify_otp implementation uses SystemTime::now() which is dynamic,
    // but InMemoryStorage uses system clock. To ensure it expires, we check
    // verify_otp under normal conditions where now is much greater than 990.
    let is_valid = verify_otp(email, "123456", &storage).unwrap();
    assert!(!is_valid, "Expired OTP must not be validated");

    // Verify it was cleaned up
    let is_valid_again = verify_otp(email, "123456", &storage).unwrap();
    assert!(!is_valid_again);
}

#[test]
fn test_otp_empty_email() {
    let storage = InMemoryStorage::new();
    let email = "";

    // Store OTP under empty email
    storage.store_otp(email, "123456", 2000000000).unwrap();

    // Verify with empty email and correct OTP
    let is_valid = verify_otp(email, "123456", &storage).unwrap();
    assert!(is_valid, "OTP for empty email should be valid if stored");
}

#[test]
fn test_otp_incorrect_otp() {
    let storage = InMemoryStorage::new();
    let email = "user@example.com";

    storage.store_otp(email, "123456", 2000000000).unwrap();

    // Verify with incorrect OTP
    let is_valid = verify_otp(email, "111111", &storage).unwrap();
    assert!(!is_valid, "Incorrect OTP should return false");

    // Verify that subsequent check with correct OTP fails (it got consumed)
    let is_valid_correct = verify_otp(email, "123456", &storage).unwrap();
    assert!(
        !is_valid_correct,
        "OTP must be consumed after first attempt even if incorrect"
    );
}

// OTP Expiry Addition Overflow check.
// This verifies that calling send_and_store_otp with an expiry_duration_secs
// that causes overflow returns the expected error instead of panicking.
#[test]
fn test_otp_expiry_overflow_panic() {
    let storage = InMemoryStorage::new();
    let sender = StdoutEmail::new();
    let email = "overflow@example.com";

    // expiry_duration_secs = u64::MAX will cause now + expiry_duration_secs to overflow
    let res = send_and_store_otp(email, &storage, &sender, u64::MAX, 1000);
    assert!(res.is_err());
    assert!(res
        .unwrap_err()
        .to_string()
        .contains("OTP expiry time overflow"));
}

// ----------------- OAuth2 Engine Stress Tests -----------------

#[test]
fn test_oauth_auth_url_weird_redirect_uri() {
    let config = OAuthConfig {
        client_id: "client-abc".to_string(),
        client_secret: "secret-xyz".to_string(),
        auth_url: "https://provider.com/auth".to_string(),
        token_url: "https://provider.com/token".to_string(),
        userinfo_url: None,
        redirect_uri: "https://my-app.com/callback?param=1&param=2".to_string(),
    };

    let url = Oauth2Client::generate_auth_url(&config, "state with spaces", "scope1 scope2");

    // Check that redirect_uri is URL-encoded
    assert!(
        url.contains("redirect_uri=https%3A%2F%2Fmy-app.com%2Fcallback%3Fparam%3D1%26param%3D2")
    );
    // Check that state is URL-encoded
    assert!(url.contains("state=state%20with%20spaces"));
    // Check scope is URL-encoded
    assert!(url.contains("scope=scope1%20scope2"));
}

#[test]
fn test_oauth_auth_url_query_merging() {
    // auth_url already has query parameters
    let config = OAuthConfig {
        client_id: "client-abc".to_string(),
        client_secret: "secret-xyz".to_string(),
        auth_url: "https://provider.com/auth?partner=123".to_string(),
        token_url: "https://provider.com/token".to_string(),
        userinfo_url: None,
        redirect_uri: "https://my-app.com/callback".to_string(),
    };

    let url = Oauth2Client::generate_auth_url(&config, "state", "scope");

    // Check that the existing query parameter is preserved and new ones are appended with '&'
    assert!(url.starts_with("https://provider.com/auth?partner=123&"));
    assert!(url.contains("response_type=code"));
}

struct FaultyHttpClient {
    response_body: String,
    should_fail: bool,
}

impl HttpClient for FaultyHttpClient {
    fn post(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
        _body: &str,
    ) -> Result<String, AuthError> {
        if self.should_fail {
            Err(AuthError::Crypto("Network request failed".to_string()))
        } else {
            Ok(self.response_body.clone())
        }
    }

    fn get(&self, _url: &str, _headers: &[(&str, &str)]) -> Result<String, AuthError> {
        if self.should_fail {
            Err(AuthError::Crypto("Network request failed".to_string()))
        } else {
            Ok(self.response_body.clone())
        }
    }
}

#[test]
fn test_oauth_exchange_code_invalid_json() {
    let config = OAuthConfig {
        client_id: "client-abc".to_string(),
        client_secret: "secret-xyz".to_string(),
        auth_url: "https://provider.com/auth".to_string(),
        token_url: "https://provider.com/token".to_string(),
        userinfo_url: None,
        redirect_uri: "https://my-app.com/callback".to_string(),
    };

    // Body is empty or malformed JSON
    let client = FaultyHttpClient {
        response_body: "this-is-not-json".to_string(),
        should_fail: false,
    };

    let res = Oauth2Client::exchange_code(&config, "code123", &client);
    assert!(res.is_err(), "Should fail on invalid JSON response");
    let err = res.unwrap_err();
    assert!(err.to_string().contains("Failed to parse token response"));
}

#[test]
fn test_oauth_exchange_code_http_failure() {
    let config = OAuthConfig {
        client_id: "client-abc".to_string(),
        client_secret: "secret-xyz".to_string(),
        auth_url: "https://provider.com/auth".to_string(),
        token_url: "https://provider.com/token".to_string(),
        userinfo_url: None,
        redirect_uri: "https://my-app.com/callback".to_string(),
    };

    let client = FaultyHttpClient {
        response_body: "".to_string(),
        should_fail: true,
    };

    let res = Oauth2Client::exchange_code(&config, "code123", &client);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.to_string().contains("Network request failed"));
}

#[test]
fn test_oauth_get_user_info_invalid_json() {
    let config = OAuthConfig {
        client_id: "client-abc".to_string(),
        client_secret: "secret-xyz".to_string(),
        auth_url: "https://provider.com/auth".to_string(),
        token_url: "https://provider.com/token".to_string(),
        userinfo_url: Some("https://provider.com/userinfo".to_string()),
        redirect_uri: "https://my-app.com/callback".to_string(),
    };

    let client = FaultyHttpClient {
        response_body: "invalid-user-info-json".to_string(),
        should_fail: false,
    };

    let res = Oauth2Client::get_user_info(&config, "token123", &client);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err
        .to_string()
        .contains("Failed to parse userinfo response"));
}
