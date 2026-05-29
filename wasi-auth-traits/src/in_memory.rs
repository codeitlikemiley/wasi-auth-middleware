use crate::{AuthError, AuthStorage, Session};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
struct OtpData {
    otp: String,
    expires_at: u64,
}

#[derive(Debug)]
pub struct InMemoryStorage {
    sessions: RwLock<HashMap<String, Session>>,
    otps: RwLock<HashMap<String, OtpData>>,
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            otps: RwLock::new(HashMap::new()),
        }
    }

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
        let otp_data = OtpData {
            otp: otp.to_string(),
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
            if otp_data.expires_at >= now && otp_data.otp == otp {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
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
    fn test_stdout_email() {
        let sender = crate::StdoutEmail::new();
        let res = sender.send_email("test@example.com", "Hello", "World");
        assert!(res.is_ok());
    }
}
