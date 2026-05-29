use crate::AuthError;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // user_id
    pub iss: String,
    pub aud: String,
    pub exp: u64,
    pub roles: Vec<String>,
    pub name: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
    kid: Option<String>,
}

pub fn base64_url_encode(data: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(data)
}

pub fn base64_url_decode(data: &str) -> Result<Vec<u8>, AuthError> {
    BASE64_URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| AuthError::Crypto(format!("Base64url decode error: {:?}", e)))
}

pub fn generate_jwt(
    claims: &Claims,
    private_key_pem: &str,
    kid: Option<&str>,
) -> Result<String, AuthError> {
    let header = Header {
        alg: "RS256".to_string(),
        typ: "JWT".to_string(),
        kid: kid.map(|s| s.to_string()),
    };

    let header_json = serde_json::to_vec(&header)
        .map_err(|e| AuthError::Crypto(format!("Header serialization failed: {}", e)))?;
    let claims_json = serde_json::to_vec(claims)
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

pub fn verify_jwt(
    token: &str,
    public_key_pem: &str,
    expected_aud: &str,
    expected_iss: &str,
    now: u64,
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

    let is_expired = if let Some(exp_limit) = claims.exp.checked_add(60) {
        exp_limit <= now
    } else {
        claims.exp <= now
    };
    if is_expired {
        return Err(AuthError::Crypto("Token has expired".to_string()));
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
}
