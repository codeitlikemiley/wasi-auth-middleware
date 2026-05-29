use crate::{AuthError, AuthStorage, EmailSender, RateLimiter};
use rand::Rng;

/// Generates a random **6-digit numeric** one-time password.
///
/// The returned string is always exactly 6 characters long and composed
/// entirely of ASCII digits (`100_000..1_000_000`).
pub fn generate_otp() -> String {
    let mut rng = rand::thread_rng();
    let code: u32 = rng.gen_range(100_000..1_000_000);
    code.to_string()
}

/// Generates an OTP, persists it in the given storage backend, and delivers it
/// to the user's email address.
///
/// The full flow is:
///
/// 1. Check if rate-limited if a `RateLimiter` is provided.
/// 2. [`generate_otp`] produces a fresh 6-digit code.
/// 3. The code is stored via [`AuthStorage::store_otp`] with an expiry timestamp
///    of `now + expiry_duration_secs`.
/// 4. A human-readable email containing the code and its validity period is sent
///    through the [`EmailSender`].
/// 5. Record the send action.
///
/// On success the generated OTP string is returned (useful in tests or for
/// logging/debugging in development).
///
/// # Arguments
///
/// * `email` — recipient email address.
/// * `storage` — backend that persists and later verifies OTPs.
/// * `sender` — transport used to deliver the email.
/// * `expiry_duration_secs` — how many seconds the OTP remains valid.
/// * `now` — the current Unix timestamp (seconds).
/// * `rate_limiter` — optional RateLimiter to check and record action limit.
///
/// # Errors
///
/// Returns [`AuthError::Crypto`] if the expiry timestamp overflows `u64` or rate-limited,
/// or propagates errors from storage or the email sender.
pub fn send_and_store_otp(
    email: &str,
    storage: &impl AuthStorage,
    sender: &impl EmailSender,
    expiry_duration_secs: u64,
    now: u64,
    rate_limiter: Option<&dyn RateLimiter>,
) -> Result<String, AuthError> {
    if let Some(limiter) = rate_limiter {
        if !limiter.check_rate_limit(email, "send_otp")? {
            return Err(AuthError::Crypto(
                "Rate limit exceeded for sending OTP".to_string(),
            ));
        }
        limiter.record_action(email, "send_otp")?;
    }

    let otp = generate_otp();
    let expires_at = now
        .checked_add(expiry_duration_secs)
        .ok_or_else(|| AuthError::Crypto("OTP expiry time overflow".to_string()))?;

    storage.store_otp(email, &otp, expires_at)?;

    let subject = "Your Secure Security Code";
    let expiry_text = if expiry_duration_secs < 60 {
        format!("{} seconds", expiry_duration_secs)
    } else {
        format!("{} minutes", expiry_duration_secs / 60)
    };
    let body = format!(
        "Your authentication security code is: {}\n\nThis code will expire in {}.",
        otp, expiry_text
    );

    sender.send_email(email, subject, &body)?;

    Ok(otp)
}

/// Verifies a submitted OTP against the value stored for the given email.
///
/// Delegates to [`AuthStorage::verify_otp`], which is expected to
/// check both correctness and expiry, and to **consume** the OTP on success.
/// Optionally checks and records verification rate limits.
///
/// Returns `Ok(true)` if the code is valid and not expired, `Ok(false)` if
/// invalid or already consumed, or an `Err` on storage failures.
pub fn verify_otp(
    email: &str,
    otp: &str,
    storage: &impl AuthStorage,
    rate_limiter: Option<&dyn RateLimiter>,
) -> Result<bool, AuthError> {
    if let Some(limiter) = rate_limiter {
        if !limiter.check_rate_limit(email, "verify_otp")? {
            return Err(AuthError::Crypto(
                "Rate limit exceeded for verifying OTP".to_string(),
            ));
        }
        limiter.record_action(email, "verify_otp")?;
    }
    storage.verify_otp(email, otp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasi_auth_traits::{InMemoryRateLimiter, InMemoryStorage, StdoutEmail};

    struct MockEmailSender {
        last_body: std::sync::Mutex<Option<String>>,
    }

    impl EmailSender for MockEmailSender {
        fn send_email(&self, _to: &str, _subject: &str, body: &str) -> Result<(), AuthError> {
            let mut last = self.last_body.lock().unwrap();
            *last = Some(body.to_string());
            Ok(())
        }
    }

    #[test]
    fn test_otp_flow() {
        let storage = InMemoryStorage::new();
        let sender = StdoutEmail::new();

        let email = "user@example.com";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let otp = send_and_store_otp(email, &storage, &sender, 300, now, None).unwrap();

        assert_eq!(otp.len(), 6);
        assert!(otp.chars().all(|c| c.is_ascii_digit()));

        // Verification success
        let ok = verify_otp(email, &otp, &storage, None).unwrap();
        assert!(ok);

        // Verification fail (consumed)
        let ok = verify_otp(email, &otp, &storage, None).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_otp_rate_limiting() {
        let storage = InMemoryStorage::new();
        let sender = StdoutEmail::new();
        let limiter = InMemoryRateLimiter::new(10, 2); // 10-second window, limit 2

        let email = "rate@example.com";
        let now = 1000;

        // 1st request
        let otp1 = send_and_store_otp(email, &storage, &sender, 300, now, Some(&limiter)).unwrap();
        // 2nd request
        let otp2 = send_and_store_otp(email, &storage, &sender, 300, now, Some(&limiter)).unwrap();
        // 3rd request should fail
        let err = send_and_store_otp(email, &storage, &sender, 300, now, Some(&limiter));
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("Rate limit exceeded"));

        // Now test verification rate limiting
        // We need another limiter to reset count or just test verify_otp limit
        let verify_limiter = InMemoryRateLimiter::new(10, 2);
        let _ = verify_otp(email, &otp1, &storage, Some(&verify_limiter)).unwrap();
        let _ = verify_otp(email, &otp2, &storage, Some(&verify_limiter)).unwrap();
        let err_verify = verify_otp(email, "000000", &storage, Some(&verify_limiter));
        assert!(err_verify.is_err());
        assert!(
            err_verify
                .unwrap_err()
                .to_string()
                .contains("Rate limit exceeded")
        );
    }

    #[test]
    fn test_otp_expiry_formatting_minutes() {
        let storage = InMemoryStorage::new();
        let sender = MockEmailSender {
            last_body: std::sync::Mutex::new(None),
        };

        let email = "user@example.com";
        let now = 1000;
        let _otp = send_and_store_otp(email, &storage, &sender, 300, now, None).unwrap();
        let body = sender.last_body.lock().unwrap().clone().unwrap();
        assert!(body.contains("expire in 5 minutes."));
    }

    #[test]
    fn test_otp_expiry_formatting_seconds() {
        let storage = InMemoryStorage::new();
        let sender = MockEmailSender {
            last_body: std::sync::Mutex::new(None),
        };

        let email = "user@example.com";
        let now = 1000;
        let _otp = send_and_store_otp(email, &storage, &sender, 45, now, None).unwrap();
        let body = sender.last_body.lock().unwrap().clone().unwrap();
        assert!(body.contains("expire in 45 seconds."));
    }

    #[test]
    fn test_otp_expiry_overflow() {
        let storage = InMemoryStorage::new();
        let sender = MockEmailSender {
            last_body: std::sync::Mutex::new(None),
        };

        let email = "user@example.com";
        let now = 1000;
        let res = send_and_store_otp(email, &storage, &sender, u64::MAX, now, None);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.to_string().contains("OTP expiry time overflow"));
    }
}
