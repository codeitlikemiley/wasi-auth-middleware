use crate::{AuthError, AuthStorage, Session};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Internal representation of a stored one-time password and its expiration.
#[derive(Debug, Clone)]
struct OtpData {
    otp: String,
    expires_at: u64,
}

/// Thread-safe, in-memory [`AuthStorage`] implementation.
///
/// Data is stored in two `RwLock<HashMap<…>>` collections — one for sessions
/// and one for OTPs. This makes `InMemoryStorage` safe to share across threads
/// (e.g., within an `Arc`) while still allowing concurrent reads.
///
/// # Behaviour Notes
///
/// - **Expired session cleanup** — When [`get_session`](crate::AuthStorage::get_session)
///   encounters an expired session it automatically removes it from the map.
/// - **OTP consumption** — [`verify_otp`](crate::AuthStorage::verify_otp) always
///   removes the stored OTP on every verification attempt (regardless of whether
///   the code matched), preventing replay attacks.
/// - **No persistence** — All data lives only in process memory and is lost on
///   restart. Use one of the persistent backends (Spin KV, SQLite) for production.
#[derive(Debug)]
pub struct InMemoryStorage {
    sessions: RwLock<HashMap<String, Session>>,
    otps: RwLock<HashMap<String, OtpData>>,
    totp_secrets: RwLock<HashMap<String, String>>,
    blacklisted_jtis: RwLock<HashMap<String, u64>>,
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStorage {
    /// Creates a new, empty `InMemoryStorage`.
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            otps: RwLock::new(HashMap::new()),
            totp_secrets: RwLock::new(HashMap::new()),
            blacklisted_jtis: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the current time as seconds since the Unix epoch.
    fn get_now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

impl AuthStorage for InMemoryStorage {
    fn store_session(
        &self,
        session_id: &str,
        user_id: &str,
        roles: &[String],
        expires_at: u64,
    ) -> Result<(), AuthError> {
        let session = Session {
            session_id: session_id.to_string(),
            user_id: user_id.to_string(),
            roles: roles.to_vec(),
            expires_at,
        };
        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        sessions.insert(session_id.to_string(), session);
        Ok(())
    }

    fn get_session(&self, session_id: &str) -> Result<Option<Session>, AuthError> {
        let now = self.get_now();
        // Read lock first
        {
            let sessions = self
                .sessions
                .read()
                .map_err(|e| AuthError::Storage(e.to_string()))?;
            if let Some(session) = sessions.get(session_id) {
                if session.expires_at >= now {
                    return Ok(Some(session.clone()));
                }
            } else {
                return Ok(None);
            }
        }
        // Acquire write lock to delete expired session
        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        if let Some(session) = sessions.get(session_id) {
            if session.expires_at < now {
                sessions.remove(session_id);
            }
        }
        Ok(None)
    }

    fn delete_session(&self, session_id: &str) -> Result<(), AuthError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        sessions.remove(session_id);
        Ok(())
    }

    fn store_otp(&self, email: &str, otp: &str, expires_at: u64) -> Result<(), AuthError> {
        let stored_otp = {
            #[cfg(feature = "hash-otp")]
            {
                crate::hash_otp(otp)?
            }
            #[cfg(not(feature = "hash-otp"))]
            {
                otp.to_string()
            }
        };

        let otp_data = OtpData {
            otp: stored_otp,
            expires_at,
        };
        let mut otps = self
            .otps
            .write()
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        otps.insert(email.to_string(), otp_data);
        Ok(())
    }

    fn verify_otp(&self, email: &str, otp: &str) -> Result<bool, AuthError> {
        let now = self.get_now();
        let mut otps = self
            .otps
            .write()
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        if let Some(otp_data) = otps.remove(email) {
            if otp_data.expires_at >= now {
                #[cfg(feature = "hash-otp")]
                {
                    Ok(crate::verify_otp_hash(otp, &otp_data.otp))
                }
                #[cfg(not(feature = "hash-otp"))]
                {
                    Ok(otp_data.otp == otp)
                }
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    fn store_totp_secret(&self, email: &str, secret: &str) -> Result<(), AuthError> {
        let mut secrets = self
            .totp_secrets
            .write()
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        secrets.insert(email.to_string(), secret.to_string());
        Ok(())
    }

    fn get_totp_secret(&self, email: &str) -> Result<Option<String>, AuthError> {
        let secrets = self
            .totp_secrets
            .read()
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        Ok(secrets.get(email).cloned())
    }

    fn delete_totp_secret(&self, email: &str) -> Result<(), AuthError> {
        let mut secrets = self
            .totp_secrets
            .write()
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        secrets.remove(email);
        Ok(())
    }

    fn blacklist_jti(&self, jti: &str, expires_at: u64) -> Result<(), AuthError> {
        let mut blacklisted = self
            .blacklisted_jtis
            .write()
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        blacklisted.insert(jti.to_string(), expires_at);
        Ok(())
    }

    fn is_jti_blacklisted(&self, jti: &str) -> Result<bool, AuthError> {
        let now = self.get_now();
        {
            let blacklisted = self
                .blacklisted_jtis
                .read()
                .map_err(|e| AuthError::Storage(e.to_string()))?;
            if let Some(&expires_at) = blacklisted.get(jti) {
                if expires_at >= now {
                    return Ok(true);
                }
            } else {
                return Ok(false);
            }
        }
        let mut blacklisted = self
            .blacklisted_jtis
            .write()
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        if let Some(&expires_at) = blacklisted.get(jti) {
            if expires_at < now {
                blacklisted.remove(jti);
            }
        }
        Ok(false)
    }

    fn cleanup_expired(&self) -> Result<(), AuthError> {
        let now = self.get_now();
        {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| AuthError::Storage(e.to_string()))?;
            sessions.retain(|_, s| s.expires_at >= now);
        }
        {
            let mut otps = self
                .otps
                .write()
                .map_err(|e| AuthError::Storage(e.to_string()))?;
            otps.retain(|_, o| o.expires_at >= now);
        }
        {
            let mut blacklisted = self
                .blacklisted_jtis
                .write()
                .map_err(|e| AuthError::Storage(e.to_string()))?;
            blacklisted.retain(|_, &mut exp| exp >= now);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EmailSender;

    #[test]
    fn test_in_memory_storage_session() {
        let storage = InMemoryStorage::new();
        let now = storage.get_now();
        let session_id = "test-session";
        let user_id = "user-123";
        let roles = vec!["admin".to_string(), "user".to_string()];

        // 1. Session store and retrieve
        storage
            .store_session(session_id, user_id, &roles, now + 100)
            .unwrap();
        let retrieved = storage.get_session(session_id).unwrap().unwrap();
        assert_eq!(retrieved.session_id, session_id);
        assert_eq!(retrieved.user_id, user_id);
        assert_eq!(retrieved.roles, roles);
        assert_eq!(retrieved.expires_at, now + 100);

        // 2. Delete session
        storage.delete_session(session_id).unwrap();
        assert!(storage.get_session(session_id).unwrap().is_none());

        // 3. Expired session
        storage
            .store_session(session_id, user_id, &roles, now - 10)
            .unwrap();
        assert!(storage.get_session(session_id).unwrap().is_none());
        // Verify it was actually removed from the internal map
        let map = storage.sessions.read().unwrap();
        assert!(!map.contains_key(session_id));
    }

    #[test]
    fn test_in_memory_storage_otp() {
        let storage = InMemoryStorage::new();
        let now = storage.get_now();
        let email = "test@example.com";
        let otp = "123456";

        // 1. Valid OTP
        storage.store_otp(email, otp, now + 100).unwrap();
        assert!(storage.verify_otp(email, otp).unwrap());
        // OTP should be deleted after use
        assert!(!storage.verify_otp(email, otp).unwrap());

        // 2. Wrong OTP
        storage.store_otp(email, otp, now + 100).unwrap();
        assert!(!storage.verify_otp(email, "wrong").unwrap());
        // Verify it was deleted even after wrong try
        assert!(!storage.verify_otp(email, otp).unwrap());

        // 3. Expired OTP
        storage.store_otp(email, otp, now - 10).unwrap();
        assert!(!storage.verify_otp(email, otp).unwrap());
    }

    #[test]
    fn test_in_memory_storage_otp_hashing() {
        let storage = InMemoryStorage::new();
        let now = storage.get_now();
        let email = "test_hash@example.com";
        let otp = "123456";

        storage.store_otp(email, otp, now + 100).unwrap();

        let otps = storage.otps.read().unwrap();
        let stored_otp_data = otps.get(email).unwrap();

        #[cfg(feature = "hash-otp")]
        {
            assert_ne!(stored_otp_data.otp, otp);
            assert!(stored_otp_data.otp.contains("$argon2"));
        }
        #[cfg(not(feature = "hash-otp"))]
        {
            assert_eq!(stored_otp_data.otp, otp);
        }
    }

    #[test]
    fn test_in_memory_storage_totp() {
        let storage = InMemoryStorage::new();
        let email = "test@example.com";
        let secret = "JBSWY3DPEHPK3PXP";

        assert_eq!(storage.get_totp_secret(email).unwrap(), None);

        storage.store_totp_secret(email, secret).unwrap();
        assert_eq!(
            storage.get_totp_secret(email).unwrap(),
            Some(secret.to_string())
        );

        storage.delete_totp_secret(email).unwrap();
        assert_eq!(storage.get_totp_secret(email).unwrap(), None);
    }

    #[test]
    fn test_in_memory_storage_jti() {
        let storage = InMemoryStorage::new();
        let now = storage.get_now();
        let jti = "test-jti-123";

        assert!(!storage.is_jti_blacklisted(jti).unwrap());

        storage.blacklist_jti(jti, now + 10).unwrap();
        assert!(storage.is_jti_blacklisted(jti).unwrap());

        storage.blacklist_jti(jti, now - 10).unwrap();
        assert!(!storage.is_jti_blacklisted(jti).unwrap());
    }

    #[test]
    fn test_stdout_email() {
        let sender = crate::StdoutEmail::new();
        let res = sender.send_email("test@example.com", "Hello", "World");
        assert!(res.is_ok());
    }

    #[test]
    fn test_in_memory_cleanup_expired() {
        let storage = InMemoryStorage::new();
        let now = storage.get_now();

        // 1. Setup active and expired sessions
        storage
            .store_session("s-active", "u", &[], now + 100)
            .unwrap();
        storage
            .store_session("s-expired", "u", &[], now - 10)
            .unwrap();

        // 2. Setup active and expired OTPs
        storage
            .store_otp("o-active@test.com", "123456", now + 100)
            .unwrap();
        storage
            .store_otp("o-expired@test.com", "654321", now - 10)
            .unwrap();

        // 3. Setup active and expired blacklisted JTIs
        storage.blacklist_jti("j-active", now + 100).unwrap();
        storage.blacklist_jti("j-expired", now - 10).unwrap();

        // Run cleanup
        storage.cleanup_expired().unwrap();

        // Verify active ones still exist
        assert!(storage.get_session("s-active").unwrap().is_some());
        assert!(storage.is_jti_blacklisted("j-active").unwrap());

        // Verify expired ones are completely gone from maps (even without get_session/is_jti_blacklisted trigger)
        let sessions = storage.sessions.read().unwrap();
        assert!(!sessions.contains_key("s-expired"));

        let otps = storage.otps.read().unwrap();
        assert!(!otps.contains_key("o-expired@test.com"));

        let blacklisted = storage.blacklisted_jtis.read().unwrap();
        assert!(!blacklisted.contains_key("j-expired"));
    }
}
