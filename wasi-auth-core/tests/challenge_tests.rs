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

#[cfg(feature = "passkey")]
mod passkey_tests {
    use base64::prelude::*;
    use coset::{Algorithm, CborSerializable, CoseKey, KeyType, Label, iana};
    use p256::SecretKey;
    use p256::ecdsa::{SigningKey, VerifyingKey, signature::Signer};
    use p256::elliptic_curve::rand_core::OsRng;
    use sha2::{Digest, Sha256};
    use wasi_auth_core::passkey::*;
    use wasi_auth_traits::InMemoryStorage;

    fn make_client_data(challenge: &str, origin: &str, type_: &str) -> String {
        let json = serde_json::json!({
            "challenge": challenge,
            "origin": origin,
            "type": type_,
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        BASE64_URL_SAFE_NO_PAD.encode(bytes)
    }

    fn make_cose_key(public_key: &VerifyingKey) -> Vec<u8> {
        let encoded = public_key.to_encoded_point(false);
        let x = encoded.x().unwrap().as_slice();
        let y = encoded.y().unwrap().as_slice();

        let key = CoseKey {
            kty: KeyType::Assigned(iana::KeyType::EC2),
            key_id: vec![],
            alg: Some(Algorithm::Assigned(iana::Algorithm::ES256)),
            key_ops: Default::default(),
            base_iv: vec![],
            params: vec![
                (Label::Int(-1), coset::cbor::value::Value::Integer(1.into())), // P-256
                (Label::Int(-2), coset::cbor::value::Value::Bytes(x.to_vec())), // x
                (Label::Int(-3), coset::cbor::value::Value::Bytes(y.to_vec())), // y
            ],
        };
        key.to_vec().unwrap()
    }

    fn make_auth_data(
        rp_id: &str,
        flags: u8,
        counter: u32,
        cred_id: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        let hash = Sha256::digest(rp_id.as_bytes());
        buf.extend_from_slice(&hash);
        buf.push(flags);
        buf.extend_from_slice(&counter.to_be_bytes());

        if let (Some(cid), Some(pk)) = (cred_id, public_key) {
            buf.extend_from_slice(&[0u8; 16]); // AAGUID
            buf.extend_from_slice(&(cid.len() as u16).to_be_bytes());
            buf.extend_from_slice(cid);
            buf.extend_from_slice(pk);
        }
        buf
    }

    fn make_attestation_object(auth_data: &[u8]) -> String {
        let map = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("fmt".to_string()),
                ciborium::value::Value::Text("none".to_string()),
            ),
            (
                ciborium::value::Value::Text("attStmt".to_string()),
                ciborium::value::Value::Map(vec![]),
            ),
            (
                ciborium::value::Value::Text("authData".to_string()),
                ciborium::value::Value::Bytes(auth_data.to_vec()),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&map, &mut bytes).unwrap();
        BASE64_URL_SAFE_NO_PAD.encode(bytes)
    }

    #[tokio::test]
    async fn test_passkey_e2e_flow() {
        let store = InMemoryStorage::new();
        let user_id = "user123";
        let username = "testuser";
        let display_name = "Test User";
        let origin = "https://example.com";
        let rp_id = "example.com";

        let config = PasskeyConfig {
            rp_id: rp_id.to_string(),
            rp_name: "Test RP".to_string(),
            origin: origin.to_string(),
            state_ttl: 300,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        // 1. Start registration
        let options =
            start_passkey_registration(&store, user_id, username, display_name, &config, now)
                .await
                .expect("start_passkey_registration failed");

        // 2. Prepare Client Response
        let challenge = options.challenge;
        let client_data_json = make_client_data(&challenge, origin, "webauthn.create");

        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(secret_key);
        let public_key = VerifyingKey::from(&signing_key);
        let cose_key = make_cose_key(&public_key);

        let cred_id = b"cred123";

        let auth_data = make_auth_data(rp_id, 0x41, 0, Some(cred_id), Some(&cose_key));
        let attestation_object = make_attestation_object(&auth_data);

        let response = RegistrationResponse {
            id: BASE64_URL_SAFE_NO_PAD.encode(cred_id),
            raw_id: BASE64_URL_SAFE_NO_PAD.encode(cred_id),
            type_: "public-key".to_string(),
            response: AttestationResponse {
                client_data_json,
                attestation_object,
            },
            client_extension_results: None,
            name: Some("My Passkey".to_string()),
        };

        // 3. Finish registration
        finish_passkey_registration(&store, user_id, &config, response, now)
            .await
            .expect("finish_passkey_registration failed");

        // 4. Start login
        let login_options = start_passkey_login(&store, &config, now)
            .await
            .expect("start_passkey_login failed");

        // 5. Prepare Client Login Response
        let login_challenge = login_options.challenge;
        let login_client_data_json = make_client_data(&login_challenge, origin, "webauthn.get");
        let login_client_data_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(&login_client_data_json)
            .unwrap();

        let login_auth_data = make_auth_data(rp_id, 0x01, 1, None, None);

        let login_client_data_hash = Sha256::digest(&login_client_data_bytes);
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&login_auth_data);
        signed_data.extend_from_slice(&login_client_data_hash);

        let signature: p256::ecdsa::Signature = signing_key.sign(&signed_data);
        let signature_der = signature.to_der();
        let signature_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature_der.as_bytes());

        let login_response = LoginResponse {
            id: BASE64_URL_SAFE_NO_PAD.encode(cred_id),
            raw_id: BASE64_URL_SAFE_NO_PAD.encode(cred_id),
            type_: "public-key".to_string(),
            response: AssertionResponse {
                client_data_json: login_client_data_json,
                authenticator_data: BASE64_URL_SAFE_NO_PAD.encode(&login_auth_data),
                signature: signature_b64,
                user_handle: Some(BASE64_URL_SAFE_NO_PAD.encode(user_id.as_bytes())),
            },
            client_extension_results: None,
        };

        // 6. Finish login
        let auth_user_id = finish_passkey_login(&store, &config, login_response, now)
            .await
            .expect("finish_passkey_login failed");

        assert_eq!(auth_user_id, user_id);
    }
}
