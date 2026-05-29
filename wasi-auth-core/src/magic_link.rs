//! Magic Link passwordless authentication implementation.
//!
//! Reuses the RS256 JWT engine to sign a single-use, short-lived token.
//! Revocation and replay prevention are managed by blacklisting the token's JTI.

use crate::jwt::{Claims, generate_jwt, verify_jwt};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};
use wasi_auth_traits::{AuthError, AuthStorage};

/// Generates a signed Magic Link URL containing a JWT token.
pub fn generate_magic_link(
    email: &str,
    base_url: &str,
    private_key_pem: &str,
    kid: Option<&str>,
    expiry_secs: u64,
    audience: &str,
    issuer: &str,
) -> Result<String, AuthError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut jti_bytes = [0u8; 16];
    rand::thread_rng().fill(&mut jti_bytes);
    let jti = BASE64_URL_SAFE_NO_PAD.encode(jti_bytes);

    let claims = Claims {
        sub: email.to_string(),
        iss: issuer.to_string(),
        aud: audience.to_string(),
        exp: now + expiry_secs,
        iat: now,
        nbf: None,
        jti: Some(jti),
        roles: vec![],
        name: None,
        email: Some(email.to_string()),
    };

    let token = generate_jwt(&claims, private_key_pem, kid)?;

    let separator = if base_url.contains('?') { "&" } else { "?" };
    Ok(format!("{}{}token={}", base_url, separator, token))
}

/// Verifies a Magic Link token, ensuring it is cryptographically valid,
/// has not expired, and has not been used before (by checking and blacklisting the JTI).
///
/// Returns the email of the authenticated user.
pub fn verify_magic_link(
    token: &str,
    public_key_pem: &str,
    audience: &str,
    issuer: &str,
    storage: &impl AuthStorage,
) -> Result<String, AuthError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let claims = verify_jwt(token, public_key_pem, audience, issuer, now)?;

    let jti = claims
        .jti
        .as_ref()
        .ok_or_else(|| AuthError::Crypto("Missing JTI claim in token".to_string()))?;

    // Check if token has been consumed
    if storage.is_jti_blacklisted(jti)? {
        return Err(AuthError::Crypto(
            "Magic link has already been used or is invalid".to_string(),
        ));
    }

    // Blacklist JTI to prevent reuse. Set expiration to exp + 60 to align with verify_jwt leeway.
    let blacklist_exp = claims.exp.saturating_add(60);
    storage.blacklist_jti(jti, blacklist_exp)?;

    Ok(claims.sub)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use wasi_auth_traits::InMemoryStorage;

    #[test]
    fn test_magic_link_flow() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 512).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let private_key_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string();
        let public_key_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();

        let storage = InMemoryStorage::new();
        let email = "magic@example.com";
        let base_url = "https://example.com/callback";
        let audience = "my-audience";
        let issuer = "my-issuer";

        let link = generate_magic_link(
            email,
            base_url,
            &private_key_pem,
            None,
            30,
            audience,
            issuer,
        )
        .unwrap();

        assert!(link.starts_with("https://example.com/callback?token="));
        let token = link.split("token=").nth(1).unwrap();

        // 1. Verify token successfully
        let verified_email =
            verify_magic_link(token, &public_key_pem, audience, issuer, &storage).unwrap();
        assert_eq!(verified_email, email);

        // 2. Re-verifying should fail due to JTI blacklist
        let res = verify_magic_link(token, &public_key_pem, audience, issuer, &storage);
        assert!(res.is_err());
    }
}
