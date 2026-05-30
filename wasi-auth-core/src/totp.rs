//! Time-based One-Time Password (TOTP) implementation.
//!
//! Follows RFC 6238 and RFC 4226 for generating and verifying TOTP codes
//! using HMAC-SHA1.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use wasi_auth_traits::AuthError;

type HmacSha1 = Hmac<Sha1>;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encodes a byte slice into a Base32 string according to RFC 4648.
#[allow(clippy::manual_is_multiple_of)]
pub fn base32_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let mut bit_buffer: u32 = 0;
    let mut bit_count: u8 = 0;
    for &byte in data {
        bit_buffer = (bit_buffer << 8) | (byte as u32);
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let index = ((bit_buffer >> bit_count) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }
    if bit_count > 0 {
        let index = ((bit_buffer << (5 - bit_count)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }
    while result.len() % 8 != 0 {
        result.push('=');
    }
    result
}

/// Decodes a Base32 string according to RFC 4648.
pub fn base32_decode(data: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut bit_buffer: u32 = 0;
    let mut bit_count: u8 = 0;
    for c in data.chars() {
        if c == '=' {
            break;
        }
        if c.is_whitespace() {
            continue;
        }
        let val = match c.to_ascii_uppercase() {
            'A'..='Z' => c.to_ascii_uppercase() as u8 - b'A',
            '2'..='7' => c.to_ascii_uppercase() as u8 - b'2' + 26,
            _ => return None, // Invalid character
        };
        bit_buffer = (bit_buffer << 5) | (val as u32);
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            result.push((bit_buffer >> bit_count) as u8);
        }
    }
    Some(result)
}

/// Generates a cryptographically secure 160-bit (20-byte) secret key,
/// encoded in Base32 (returns 32 characters, no padding).
pub fn generate_totp_secret() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 20];
    rand::thread_rng().fill(&mut bytes);
    let encoded = base32_encode(&bytes);
    encoded.trim_end_matches('=').to_string()
}

/// Generates a standard provisioning URI (`otpauth://totp/...`) for authenticator apps.
pub fn generate_totp_uri(email: &str, secret: &str, issuer: &str) -> String {
    let label = format!("{}:{}", issuer, email);
    let encoded_label = urlencoding::encode(&label);
    let encoded_issuer = urlencoding::encode(issuer);
    let encoded_secret = urlencoding::encode(secret);
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        encoded_label, encoded_secret, encoded_issuer
    )
}

/// Verifies a 6-digit TOTP code against a Base32-encoded secret.
///
/// Implements clock drift tolerance with a window of ±1 step (30 seconds).
/// Returns the matching step number on success, or `None` on failure.
pub fn verify_totp(secret_b32: &str, code: &str, time_secs: u64) -> Result<Option<u64>, AuthError> {
    let secret_bytes = base32_decode(secret_b32)
        .ok_or_else(|| AuthError::Other("Invalid Base32 secret".to_string()))?;

    let clean_code = code.trim().replace(' ', "");
    if clean_code.len() != 6 || !clean_code.chars().all(|c| c.is_ascii_digit()) {
        return Ok(None);
    }

    let current_step = time_secs / 30;

    // Check steps in window: current_step - 1, current_step, current_step + 1
    for step_offset in &[-1i64, 0i64, 1i64] {
        let step = if *step_offset < 0 {
            current_step.saturating_sub(step_offset.unsigned_abs())
        } else {
            current_step.saturating_add(*step_offset as u64)
        };

        let step_bytes = step.to_be_bytes();
        let mut mac = HmacSha1::new_from_slice(&secret_bytes)
            .map_err(|e| AuthError::Other(format!("HMAC key initialization failed: {}", e)))?;
        mac.update(&step_bytes);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        let offset = (code_bytes[19] & 0x0f) as usize;
        let binary: u32 = (((code_bytes[offset] & 0x7f) as u32) << 24)
            | ((code_bytes[offset + 1] as u32) << 16)
            | ((code_bytes[offset + 2] as u32) << 8)
            | (code_bytes[offset + 3] as u32);

        let totp = binary % 1_000_000;
        let totp_str = format!("{:06}", totp);

        if totp_str == clean_code {
            return Ok(Some(step));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_encode_decode() {
        let cases = vec![
            (b"".as_slice(), ""),
            (b"f".as_slice(), "MY======"),
            (b"fo".as_slice(), "MZXQ===="),
            (b"foo".as_slice(), "MZXW6==="),
            (b"foob".as_slice(), "MZXW6YQ="),
            (b"fooba".as_slice(), "MZXW6YTB"),
            (b"foobar".as_slice(), "MZXW6YTBOI======"),
        ];

        for (input, expected) in cases {
            let encoded = base32_encode(input);
            assert_eq!(encoded, expected);
            let decoded = base32_decode(&encoded).unwrap();
            assert_eq!(decoded, input);
        }
    }

    #[test]
    fn test_generate_totp_secret() {
        let secret = generate_totp_secret();
        assert_eq!(secret.len(), 32);
        let decoded = base32_decode(&secret).unwrap();
        assert_eq!(decoded.len(), 20);
    }

    #[test]
    fn test_generate_totp_uri() {
        let uri = generate_totp_uri("user@example.com", "JBSWY3DPEHPK3PXP", "MyApp");
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("issuer=MyApp"));
        assert!(uri.contains("MyApp%3Auser%40example.com"));
    }

    #[test]
    fn test_verify_totp() {
        // Test vectors from RFC 6238 or standard TOTP behavior using static secret
        let secret = "JBSWY3DPEHPK3PXP"; // "Hello!" in base32

        // Let's verify that a code generated for a specific time verifies successfully.
        let time = 1234567890u64; // arbitrary timestamp

        // Generate the code manually for step = time / 30
        let step = time / 30;
        let step_bytes = step.to_be_bytes();
        let decoded_secret = base32_decode(secret).unwrap();
        let mut mac = HmacSha1::new_from_slice(&decoded_secret).unwrap();
        mac.update(&step_bytes);
        let code_bytes = mac.finalize().into_bytes();
        let offset = (code_bytes[19] & 0x0f) as usize;
        let binary: u32 = (((code_bytes[offset] & 0x7f) as u32) << 24)
            | ((code_bytes[offset + 1] as u32) << 16)
            | ((code_bytes[offset + 2] as u32) << 8)
            | (code_bytes[offset + 3] as u32);
        let totp = binary % 1_000_000;
        let code_str = format!("{:06}", totp);

        // Code should verify at the correct time
        assert_eq!(verify_totp(secret, &code_str, time).unwrap(), Some(step));

        // Code should verify with drift tolerance: time - 29 (same window/drift step - 1 or 0)
        assert!(verify_totp(secret, &code_str, time - 29).unwrap().is_some());
        assert!(verify_totp(secret, &code_str, time + 29).unwrap().is_some());

        // But should fail if too far out of window
        assert!(verify_totp(secret, &code_str, time - 60).unwrap().is_none());
        assert!(verify_totp(secret, &code_str, time + 60).unwrap().is_none());
    }
}
