use crate::{AuthError, Session};

#[cfg(feature = "spin")]
pub struct SpinKeyValueStorage {
    #[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
    store_name: String,
}

#[cfg(feature = "spin")]
impl Default for SpinKeyValueStorage {
    fn default() -> Self {
        Self::open_default()
    }
}

#[cfg(feature = "spin")]
impl SpinKeyValueStorage {
    pub fn new(store_name: String) -> Self {
        #[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
        {
            Self { store_name }
        }
        #[cfg(not(all(target_arch = "wasm32", target_os = "wasi")))]
        {
            let _ = store_name;
            Self {}
        }
    }

    pub fn open_default() -> Self {
        Self::new("default".to_string())
    }

    #[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
    fn open_store(&self) -> Result<spin_sdk::key_value::Store, AuthError> {
        spin_sdk::key_value::Store::open(&self.store_name)
            .map_err(|e| AuthError::Storage(format!("Failed to open Spin KV store: {:?}", e)))
    }

    #[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
    fn get_now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

#[cfg(all(feature = "spin", target_arch = "wasm32", target_os = "wasi"))]
impl crate::AuthStorage for SpinKeyValueStorage {
    fn store_session(
        &self,
        session_id: &str,
        user_id: &str,
        roles: &[String],
        expires_at: u64,
    ) -> Result<(), AuthError> {
        let store = self.open_store()?;
        let session = Session {
            session_id: session_id.to_string(),
            user_id: user_id.to_string(),
            roles: roles.to_vec(),
            expires_at,
        };
        let serialized = serde_json::to_vec(&session)
            .map_err(|e| AuthError::Storage(format!("JSON serialization error: {}", e)))?;

        let key = format!("session:{}", session_id);
        store
            .set(&key, &serialized)
            .map_err(|e| AuthError::Storage(format!("Spin KV set error: {:?}", e)))?;
        Ok(())
    }

    fn get_session(&self, session_id: &str) -> Result<Option<Session>, AuthError> {
        let store = self.open_store()?;
        let key = format!("session:{}", session_id);

        match store.get(&key) {
            Ok(Some(bytes)) => {
                let session: Session = serde_json::from_slice(&bytes).map_err(|e| {
                    AuthError::Storage(format!("JSON deserialization error: {}", e))
                })?;
                if session.expires_at < self.get_now() {
                    let _ = store.delete(&key);
                    Ok(None)
                } else {
                    Ok(Some(session))
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AuthError::Storage(format!("Spin KV get error: {:?}", e))),
        }
    }

    fn delete_session(&self, session_id: &str) -> Result<(), AuthError> {
        let store = self.open_store()?;
        let key = format!("session:{}", session_id);
        store
            .delete(&key)
            .map_err(|e| AuthError::Storage(format!("Spin KV delete error: {:?}", e)))?;
        Ok(())
    }

    fn store_otp(&self, email: &str, otp: &str, expires_at: u64) -> Result<(), AuthError> {
        let store = self.open_store()?;
        let key = format!("otp:{}", email);

        #[derive(serde::Serialize, serde::Deserialize)]
        struct OtpData {
            otp: String,
            expires_at: u64,
        }

        let otp_data = OtpData {
            otp: otp.to_string(),
            expires_at,
        };

        let serialized = serde_json::to_vec(&otp_data)
            .map_err(|e| AuthError::Storage(format!("JSON serialization error: {}", e)))?;

        store
            .set(&key, &serialized)
            .map_err(|e| AuthError::Storage(format!("Spin KV set error: {:?}", e)))?;
        Ok(())
    }

    fn verify_otp(&self, email: &str, otp: &str) -> Result<bool, AuthError> {
        let store = self.open_store()?;
        let key = format!("otp:{}", email);

        #[derive(serde::Serialize, serde::Deserialize)]
        struct OtpData {
            otp: String,
            expires_at: u64,
        }

        match store.get(&key) {
            Ok(Some(bytes)) => {
                let otp_data: OtpData = serde_json::from_slice(&bytes).map_err(|e| {
                    AuthError::Storage(format!("JSON deserialization error: {}", e))
                })?;

                store.delete(&key).map_err(|e| {
                    AuthError::Storage(format!("Spin KV delete OTP error: {:?}", e))
                })?;
                if otp_data.expires_at >= self.get_now() && otp_data.otp == otp {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Ok(None) => Ok(false),
            Err(e) => Err(AuthError::Storage(format!("Spin KV get error: {:?}", e))),
        }
    }
}

#[cfg(all(feature = "spin", not(all(target_arch = "wasm32", target_os = "wasi"))))]
impl crate::AuthStorage for SpinKeyValueStorage {
    fn store_session(
        &self,
        _session_id: &str,
        _user_id: &str,
        _roles: &[String],
        _expires_at: u64,
    ) -> Result<(), AuthError> {
        Err(AuthError::Storage(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }
    fn get_session(&self, _session_id: &str) -> Result<Option<Session>, AuthError> {
        Err(AuthError::Storage(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }
    fn delete_session(&self, _session_id: &str) -> Result<(), AuthError> {
        Err(AuthError::Storage(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }
    fn store_otp(&self, _email: &str, _otp: &str, _expires_at: u64) -> Result<(), AuthError> {
        Err(AuthError::Storage(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }
    fn verify_otp(&self, _email: &str, _otp: &str) -> Result<bool, AuthError> {
        Err(AuthError::Storage(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }
}

#[cfg(all(
    test,
    feature = "spin",
    not(all(target_arch = "wasm32", target_os = "wasi"))
))]
mod tests {
    use super::*;
    use crate::AuthStorage;

    #[test]
    fn test_spin_kv_native_errors() {
        let storage = SpinKeyValueStorage::open_default();
        assert!(storage.store_session("s", "u", &[], 0).is_err());
        assert!(storage.get_session("s").is_err());
        assert!(storage.delete_session("s").is_err());
        assert!(storage.store_otp("e", "o", 0).is_err());
        assert!(storage.verify_otp("e", "o").is_err());
    }
}
