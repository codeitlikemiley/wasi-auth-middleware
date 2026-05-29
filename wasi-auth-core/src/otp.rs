use crate::{AuthError, AuthStorage, EmailSender};
use rand::Rng;

pub fn generate_otp() -> String {
    let mut rng = rand::thread_rng();
    let code: u32 = rng.gen_range(100_000..1_000_000);
    code.to_string()
}

pub fn send_and_store_otp(
    email: &str,
    storage: &impl AuthStorage,
    sender: &impl EmailSender,
    expiry_duration_secs: u64,
    now: u64,
) -> Result<String, AuthError> {
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

pub fn verify_otp(email: &str, otp: &str, storage: &impl AuthStorage) -> Result<bool, AuthError> {
    storage.verify_otp(email, otp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasi_auth_traits::{InMemoryStorage, StdoutEmail};

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
        let otp = send_and_store_otp(email, &storage, &sender, 300, now).unwrap();

        assert_eq!(otp.len(), 6);
        assert!(otp.chars().all(|c| c.is_ascii_digit()));

        // Verification success
        let ok = verify_otp(email, &otp, &storage).unwrap();
        assert!(ok);

        // Verification fail (consumed)
        let ok = verify_otp(email, &otp, &storage).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_otp_expiry_formatting_minutes() {
        let storage = InMemoryStorage::new();
        let sender = MockEmailSender {
            last_body: std::sync::Mutex::new(None),
        };

        let email = "user@example.com";
        let now = 1000;
        let _otp = send_and_store_otp(email, &storage, &sender, 300, now).unwrap();
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
        let _otp = send_and_store_otp(email, &storage, &sender, 45, now).unwrap();
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
        let res = send_and_store_otp(email, &storage, &sender, u64::MAX, now);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.to_string().contains("OTP expiry time overflow"));
    }
}
