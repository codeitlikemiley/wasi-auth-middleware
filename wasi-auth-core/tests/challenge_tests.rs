use wasi_auth_core::AuthError;
use wasi_auth_core::jwt::{Claims, base64_url_encode, generate_jwt, verify_jwt};
use wasi_auth_core::oauth::{HttpClient, OAuthConfig, Oauth2Client};
use wasi_auth_core::otp::{send_and_store_otp, verify_otp};
use wasi_auth_traits::{AuthStorage, InMemoryStorage, StdoutEmail};

use rsa::pkcs8::EncodePrivateKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

// Setup helper for RSA keys
fn generate_keys() -> (String, String) {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 512).expect("failed to generate private key");
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

#[derive(Serialize, Deserialize)]
struct DummyHeader {
    alg: String,
    typ: String,
    kid: Option<String>,
}

// 1. JWT Signature Tests
#[test]
fn test_jwt_invalid_signature() {
    let (priv_pem, pub_pem) = generate_keys();
    let claims = Claims {
        sub: "user-123".to_string(),
        iss: "my-iss".to_string(),
        aud: "my-aud".to_string(),
        exp: 2000000000,
        iat: 0,
        nbf: None,
        jti: None,
        roles: vec![],
        name: None,
        email: None,
    };

    let token = generate_jwt(&claims, &priv_pem, None).unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);

    // Modify signature part slightly (change last character)
    let bad_sig = format!("{}a", &parts[2][..parts[2].len() - 1]);
    let corrupted_token = format!("{}.{}.{}", parts[0], parts[1], bad_sig);

    let res = verify_jwt(&corrupted_token, &pub_pem, "my-aud", "my-iss", 1000000000);
    assert!(
        res.is_err(),
        "Verification should fail for invalid signature"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("signature verification failed") || err_msg.contains("decode error"),
        "Unexpected error: {}",
        err_msg
    );
}

#[test]
fn test_jwt_truncated_signature() {
    let (priv_pem, pub_pem) = generate_keys();
    let claims = Claims {
        sub: "user-123".to_string(),
        iss: "my-iss".to_string(),
        aud: "my-aud".to_string(),
        exp: 2000000000,
        iat: 0,
        nbf: None,
        jti: None,
        roles: vec![],
        name: None,
        email: None,
    };

    let token = generate_jwt(&claims, &priv_pem, None).unwrap();
    let parts: Vec<&str> = token.split('.').collect();

    // Truncate signature to 10 characters
    let truncated_sig = &parts[2][..10];
    let corrupted_token = format!("{}.{}.{}", parts[0], parts[1], truncated_sig);

    let res = verify_jwt(&corrupted_token, &pub_pem, "my-aud", "my-iss", 1000000000);
    assert!(
        res.is_err(),
        "Verification should fail for truncated signature"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("signature verification failed") || err_msg.contains("decode error"),
        "Unexpected error: {}",
        err_msg
    );

    // Truncate signature to empty
    let empty_sig_token = format!("{}.{}.", parts[0], parts[1]);
    let res_empty = verify_jwt(&empty_sig_token, &pub_pem, "my-aud", "my-iss", 1000000000);
    assert!(
        res_empty.is_err(),
        "Verification should fail for empty signature"
    );
}

// 2. JWT Algorithm Confusion Attacks
#[test]
fn test_jwt_alg_none_attack() {
    let (_, pub_pem) = generate_keys();
    let header = DummyHeader {
        alg: "none".to_string(),
        typ: "JWT".to_string(),
        kid: None,
    };
    let claims = Claims {
        sub: "user-123".to_string(),
        iss: "my-iss".to_string(),
        aud: "my-aud".to_string(),
        exp: 2000000000,
        iat: 0,
        nbf: None,
        jti: None,
        roles: vec![],
        name: None,
        email: None,
    };

    let header_b64 = base64_url_encode(&serde_json::to_vec(&header).unwrap());
    let claims_b64 = base64_url_encode(&serde_json::to_vec(&claims).unwrap());
    let token = format!("{}.{}.", header_b64, claims_b64);

    let res = verify_jwt(&token, &pub_pem, "my-aud", "my-iss", 1000000000);
    assert!(res.is_err(), "Verification should fail when alg is 'none'");
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("Unsupported algorithm"),
        "Unexpected error message: {}",
        err_msg
    );
}

#[test]
fn test_jwt_alg_hs256_attack() {
    let (_, pub_pem) = generate_keys();
    let header = DummyHeader {
        alg: "HS256".to_string(),
        typ: "JWT".to_string(),
        kid: None,
    };
    let claims = Claims {
        sub: "user-123".to_string(),
        iss: "my-iss".to_string(),
        aud: "my-aud".to_string(),
        exp: 2000000000,
        iat: 0,
        nbf: None,
        jti: None,
        roles: vec![],
        name: None,
        email: None,
    };

    let header_b64 = base64_url_encode(&serde_json::to_vec(&header).unwrap());
    let claims_b64 = base64_url_encode(&serde_json::to_vec(&claims).unwrap());
    // We sign with a HMAC-SHA256, but verification code uses RSA.
    // However, the validation engine rejects any non-RS256 algorithm anyway.
    let token = format!("{}.{}.dummysignature", header_b64, claims_b64);

    let res = verify_jwt(&token, &pub_pem, "my-aud", "my-iss", 1000000000);
    assert!(res.is_err(), "Verification should fail when alg is 'HS256'");
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("Unsupported algorithm"),
        "Unexpected error message: {}",
        err_msg
    );
}

// 3. JWT Expiration/Overflow boundary cases (exp = u64::MAX, etc.)
#[test]
fn test_jwt_exp_overflow_boundary() {
    let (priv_pem, pub_pem) = generate_keys();

    // Case A: exp = u64::MAX
    let claims_max = Claims {
        sub: "user-123".to_string(),
        iss: "my-iss".to_string(),
        aud: "my-aud".to_string(),
        exp: u64::MAX,
        iat: 0,
        nbf: None,
        jti: None,
        roles: vec![],
        name: None,
        email: None,
    };
    let token_max = generate_jwt(&claims_max, &priv_pem, None).unwrap();
    let res_max = verify_jwt(&token_max, &pub_pem, "my-aud", "my-iss", 1000000000);
    assert!(
        res_max.is_ok(),
        "exp = u64::MAX should verify successfully when now is not expired"
    );

    // Case B: exp = u64::MAX - 59 (still overflows since leeway is 60)
    let claims_overflow_edge = Claims {
        sub: "user-123".to_string(),
        iss: "my-iss".to_string(),
        aud: "my-aud".to_string(),
        exp: u64::MAX - 59,
        iat: 0,
        nbf: None,
        jti: None,
        roles: vec![],
        name: None,
        email: None,
    };
    let token_edge = generate_jwt(&claims_overflow_edge, &priv_pem, None).unwrap();
    let res_edge = verify_jwt(&token_edge, &pub_pem, "my-aud", "my-iss", 1000000000);
    assert!(
        res_edge.is_ok(),
        "exp = u64::MAX - 59 should verify successfully when now is not expired"
    );

    // Case C: exp = u64::MAX - 60 (does NOT overflow since checked_add(60) == Some(u64::MAX))
    let claims_no_overflow = Claims {
        sub: "user-123".to_string(),
        iss: "my-iss".to_string(),
        aud: "my-aud".to_string(),
        exp: u64::MAX - 60,
        iat: 0,
        nbf: None,
        jti: None,
        roles: vec![],
        name: None,
        email: None,
    };
    let token_no_overflow = generate_jwt(&claims_no_overflow, &priv_pem, None).unwrap();
    let res_no_overflow = verify_jwt(&token_no_overflow, &pub_pem, "my-aud", "my-iss", 1000000000);
    assert!(
        res_no_overflow.is_ok(),
        "exp = u64::MAX - 60 should succeed because it doesn't overflow checked_add(60)"
    );
}

// 4. Email OTP Engine Stress-Testing
#[test]
fn test_otp_expired() {
    let storage = InMemoryStorage::new();
    let sender = StdoutEmail::new();
    let email = "user@example.com";
    let now = 100000;

    // Store with 0 seconds expiry duration, meaning expires_at = now
    let otp = send_and_store_otp(email, &storage, &sender, 0, now, None).unwrap();

    // Verify immediately at now (where expires_at = now) - it should pass
    // Wait, in_memory.rs uses std::time::SystemTime::now().as_secs() which will be > 100000.
    // So if std::time::SystemTime::now() is greater than expires_at (which is 100000), it will fail.
    // That means storing with an arbitrary timestamp "100000" in the past makes it expired instantly compared to SystemTime::now().
    let verify_now = verify_otp(email, &otp, &storage, None).unwrap();
    assert!(
        !verify_now,
        "Verification at a past time (100000) relative to SystemTime::now() should fail (be treated as expired)"
    );
}

#[test]
fn test_otp_expiry_past() {
    let storage = InMemoryStorage::new();
    let email = "user@example.com";
    let otp = "123456";

    // Directly store an expired OTP in storage (expires_at = now - 10)
    let now_real = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    storage.store_otp(email, otp, now_real - 10).unwrap();

    // Verify should return false
    let res = verify_otp(email, otp, &storage, None).unwrap();
    assert!(!res, "Expired OTP verification should fail");

    // Ensure it is consumed (deleted) even on failure
    storage.store_otp(email, otp, now_real + 100).unwrap();
    let res_wrong = verify_otp(email, "wrong_otp", &storage, None).unwrap();
    assert!(!res_wrong);
    // Verifying it again with correct OTP should now fail because it was consumed
    let res_retry = verify_otp(email, otp, &storage, None).unwrap();
    assert!(
        !res_retry,
        "OTP must be consumed/invalidated after one failed attempt"
    );
}

#[test]
fn test_otp_empty_email() {
    let storage = InMemoryStorage::new();
    let sender = StdoutEmail::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Call send_and_store_otp with empty email
    let otp_res = send_and_store_otp("", &storage, &sender, 300, now, None);
    assert!(
        otp_res.is_ok(),
        "OTP generation with empty email should be allowed"
    );
    let otp = otp_res.unwrap();

    // Verification with empty email and correct OTP
    // Wait, the expiry was stored at `now + 300`, so since now = now_real (almost), it should verify successfully
    let verify_res = verify_otp("", &otp, &storage, None).unwrap();
    assert!(
        verify_res,
        "Verification with empty email should succeed with correct OTP"
    );

    // Verification with empty email and incorrect OTP
    // Directly store a fresh valid one
    let now_real = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    storage.store_otp("", &otp, now_real + 300).unwrap();
    let verify_res_wrong = verify_otp("", "000000", &storage, None).unwrap();
    assert!(
        !verify_res_wrong,
        "Verification with empty email and incorrect OTP should fail"
    );
}

// 5. OAuth2 Mock client token exchange & URL generation tests
struct MockOAuthHttpClient {
    response_body: String,
    error_message: Option<String>,
    last_url: Mutex<Option<String>>,
}

impl HttpClient for MockOAuthHttpClient {
    fn post(&self, url: &str, _headers: &[(&str, &str)], _body: &str) -> Result<String, AuthError> {
        let mut last = self.last_url.lock().unwrap();
        *last = Some(url.to_string());
        if let Some(ref err_msg) = self.error_message {
            return Err(AuthError::Other(err_msg.clone()));
        }
        Ok(self.response_body.clone())
    }

    fn get(&self, url: &str, _headers: &[(&str, &str)]) -> Result<String, AuthError> {
        let mut last = self.last_url.lock().unwrap();
        *last = Some(url.to_string());
        if let Some(ref err_msg) = self.error_message {
            return Err(AuthError::Other(err_msg.clone()));
        }
        Ok(self.response_body.clone())
    }
}

#[test]
fn test_oauth_url_generation_boundaries() {
    let config_with_query = OAuthConfig {
        client_id: "id123".to_string(),
        client_secret: "secret".to_string(),
        auth_url: "https://auth.com/oauth?provider=google".to_string(),
        token_url: "https://auth.com/token".to_string(),
        userinfo_url: None,
        redirect_uri: "https://app.com/callback".to_string(),
    };

    let url = Oauth2Client::generate_auth_url(&config_with_query, "state", "scope", None);
    assert!(url.starts_with("https://auth.com/oauth?provider=google&response_type=code"));
    assert!(url.contains("client_id=id123"));

    let config_no_query = OAuthConfig {
        client_id: "id123".to_string(),
        client_secret: "secret".to_string(),
        auth_url: "https://auth.com/oauth".to_string(),
        token_url: "https://auth.com/token".to_string(),
        userinfo_url: None,
        redirect_uri: "https://app.com/callback".to_string(),
    };

    let url2 = Oauth2Client::generate_auth_url(&config_no_query, "state", "scope", None);
    assert!(url2.starts_with("https://auth.com/oauth?response_type=code"));
}

#[test]
fn test_oauth_exchange_malformed_json() {
    let config = OAuthConfig {
        client_id: "id123".to_string(),
        client_secret: "secret".to_string(),
        auth_url: "https://auth.com/oauth".to_string(),
        token_url: "https://auth.com/token".to_string(),
        userinfo_url: None,
        redirect_uri: "https://app.com/callback".to_string(),
    };

    let mock_client = MockOAuthHttpClient {
        response_body: "{invalid_json}".to_string(),
        error_message: None,
        last_url: Mutex::new(None),
    };

    let res = Oauth2Client::exchange_code(&config, "code", &mock_client, None);
    assert!(
        res.is_err(),
        "Exchange should fail if response is invalid JSON"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("Failed to parse token response"));
}

#[test]
fn test_oauth_exchange_http_error() {
    let config = OAuthConfig {
        client_id: "id123".to_string(),
        client_secret: "secret".to_string(),
        auth_url: "https://auth.com/oauth".to_string(),
        token_url: "https://auth.com/token".to_string(),
        userinfo_url: None,
        redirect_uri: "https://app.com/callback".to_string(),
    };

    let mock_client = MockOAuthHttpClient {
        response_body: "".to_string(),
        error_message: Some("Network failure".to_string()),
        last_url: Mutex::new(None),
    };

    let res = Oauth2Client::exchange_code(&config, "code", &mock_client, None);
    assert!(res.is_err(), "Exchange should fail if HTTP request fails");
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("Network failure"));
}
