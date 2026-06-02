use crate::{AuthError, Session};

/// [`AuthStorage`](crate::AuthStorage) implementation backed by the
/// [Spin SDK key-value store](https://developer.fermyon.com/spin/v2/key-value-store-api-guide).
///
/// # Key Schema
///
/// | Data | Key pattern | Value |
/// |------|-------------|-------|
/// | Session | `session:{session_id}` | JSON-serialised [`Session`] |
/// | OTP | `otp:{email}` | JSON-serialised `{otp, expires_at}` |
///
/// # Platform Support
///
/// This backend is only functional when compiled for `wasm32-wasi` targets and
/// executed inside the Spin runtime. On native (non-WASI) platforms all trait
/// methods return [`AuthError::StorageError`].
///
/// Requires the `spin` feature flag.
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
    /// Creates a new `SpinKeyValueStorage` that will open the named Spin KV store.
    ///
    /// On native platforms the `store_name` is silently ignored since the Spin
    /// SDK is not available.
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

    /// Opens the `"default"` Spin key-value store.
    pub fn open_default() -> Self {
        Self::new("default".to_string())
    }

    /// Opens the underlying Spin KV store handle.
    #[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
    fn open_store(&self) -> Result<spin_sdk::key_value::Store, AuthError> {
        spin_sdk::key_value::Store::open(&self.store_name)
            .map_err(|e| AuthError::StorageError(format!("Failed to open Spin KV store: {:?}", e)))
    }

    /// Returns the current time as seconds since the Unix epoch.
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
            .map_err(|e| AuthError::StorageError(format!("JSON serialization error: {}", e)))?;

        let key = format!("session:{}", session_id);
        store
            .set(&key, &serialized)
            .map_err(|e| AuthError::StorageError(format!("Spin KV set error: {:?}", e)))?;
        Ok(())
    }

    fn get_session(&self, session_id: &str) -> Result<Option<Session>, AuthError> {
        let store = self.open_store()?;
        let key = format!("session:{}", session_id);

        match store.get(&key) {
            Ok(Some(bytes)) => {
                let session: Session = serde_json::from_slice(&bytes).map_err(|e| {
                    AuthError::StorageError(format!("JSON deserialization error: {}", e))
                })?;
                if session.expires_at < self.get_now() {
                    let _ = store.delete(&key);
                    Ok(None)
                } else {
                    Ok(Some(session))
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AuthError::StorageError(format!(
                "Spin KV get error: {:?}",
                e
            ))),
        }
    }

    fn delete_session(&self, session_id: &str) -> Result<(), AuthError> {
        let store = self.open_store()?;
        let key = format!("session:{}", session_id);
        store
            .delete(&key)
            .map_err(|e| AuthError::StorageError(format!("Spin KV delete error: {:?}", e)))?;
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

        let serialized = serde_json::to_vec(&otp_data)
            .map_err(|e| AuthError::StorageError(format!("JSON serialization error: {}", e)))?;

        store
            .set(&key, &serialized)
            .map_err(|e| AuthError::StorageError(format!("Spin KV set error: {:?}", e)))?;
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
                    AuthError::StorageError(format!("JSON deserialization error: {}", e))
                })?;

                store.delete(&key).map_err(|e| {
                    AuthError::StorageError(format!("Spin KV delete OTP error: {:?}", e))
                })?;
                if otp_data.expires_at >= self.get_now() {
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
            }
            Ok(None) => Ok(false),
            Err(e) => Err(AuthError::StorageError(format!(
                "Spin KV get error: {:?}",
                e
            ))),
        }
    }

    fn store_totp_secret(&self, email: &str, secret: &str) -> Result<(), AuthError> {
        let store = self.open_store()?;
        let key = format!("totp:{}", email);
        store
            .set(&key, secret.as_bytes())
            .map_err(|e| AuthError::StorageError(format!("Spin KV set TOTP error: {:?}", e)))?;
        Ok(())
    }

    fn get_totp_secret(&self, email: &str) -> Result<Option<String>, AuthError> {
        let store = self.open_store()?;
        let key = format!("totp:{}", email);
        match store.get(&key) {
            Ok(Some(bytes)) => {
                let s = String::from_utf8(bytes).map_err(|e| {
                    AuthError::StorageError(format!("Invalid UTF-8 in stored secret: {}", e))
                })?;
                Ok(Some(s))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AuthError::StorageError(format!(
                "Spin KV get TOTP error: {:?}",
                e
            ))),
        }
    }

    fn delete_totp_secret(&self, email: &str) -> Result<(), AuthError> {
        let store = self.open_store()?;
        let key = format!("totp:{}", email);
        store
            .delete(&key)
            .map_err(|e| AuthError::StorageError(format!("Spin KV delete TOTP error: {:?}", e)))?;
        Ok(())
    }

    fn blacklist_jti(&self, jti: &str, expires_at: u64) -> Result<(), AuthError> {
        let store = self.open_store()?;
        let key = format!("blacklist:{}", jti);
        let bytes = expires_at.to_be_bytes();
        store.set(&key, &bytes).map_err(|e| {
            AuthError::StorageError(format!("Spin KV blacklist JTI error: {:?}", e))
        })?;
        Ok(())
    }

    fn is_jti_blacklisted(&self, jti: &str) -> Result<bool, AuthError> {
        let store = self.open_store()?;
        let key = format!("blacklist:{}", jti);
        match store.get(&key) {
            Ok(Some(bytes)) => {
                if bytes.len() != 8 {
                    return Err(AuthError::StorageError(
                        "Invalid blacklisted JTI expiration length".to_string(),
                    ));
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                let expires_at = u64::from_be_bytes(arr);
                if expires_at < self.get_now() {
                    let _ = store.delete(&key);
                    Ok(false)
                } else {
                    Ok(true)
                }
            }
            Ok(None) => Ok(false),
            Err(e) => Err(AuthError::StorageError(format!(
                "Spin KV get blacklist error: {:?}",
                e
            ))),
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
        Err(AuthError::StorageError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }
    fn get_session(&self, _session_id: &str) -> Result<Option<Session>, AuthError> {
        Err(AuthError::StorageError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }
    fn delete_session(&self, _session_id: &str) -> Result<(), AuthError> {
        Err(AuthError::StorageError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }
    fn store_otp(&self, _email: &str, _otp: &str, _expires_at: u64) -> Result<(), AuthError> {
        Err(AuthError::StorageError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }
    fn verify_otp(&self, _email: &str, _otp: &str) -> Result<bool, AuthError> {
        Err(AuthError::StorageError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }
    fn store_totp_secret(&self, _email: &str, _secret: &str) -> Result<(), AuthError> {
        Err(AuthError::StorageError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }
    fn get_totp_secret(&self, _email: &str) -> Result<Option<String>, AuthError> {
        Err(AuthError::StorageError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }
    fn delete_totp_secret(&self, _email: &str) -> Result<(), AuthError> {
        Err(AuthError::StorageError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }
    fn blacklist_jti(&self, _jti: &str, _expires_at: u64) -> Result<(), AuthError> {
        Err(AuthError::StorageError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }
    fn is_jti_blacklisted(&self, _jti: &str) -> Result<bool, AuthError> {
        Err(AuthError::StorageError(
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
        assert!(storage.store_totp_secret("e", "s").is_err());
        assert!(storage.get_totp_secret("e").is_err());
        assert!(storage.delete_totp_secret("e").is_err());
        assert!(storage.blacklist_jti("j", 0).is_err());
        assert!(storage.is_jti_blacklisted("j").is_err());
    }
}

#[cfg(all(
    feature = "spin",
    target_arch = "wasm32",
    target_os = "wasi",
    feature = "passkey"
))]
#[async_trait::async_trait(?Send)]
impl passkey_server::PasskeyStore for SpinKeyValueStorage {
    async fn create_passkey(
        &self,
        user_id: String,
        cred_id: &str,
        public_key: &str,
        name: &str,
        counter: i64,
        created_at: i64,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        let store = self
            .open_store()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        let pk = passkey_server::types::StoredPasskey {
            user_id: user_id.clone(),
            cred_id: cred_id.to_string(),
            public_key: public_key.to_string(),
            name: name.to_string(),
            created_at,
            last_used_at: created_at,
            counter,
        };
        let serialized_pk = serde_json::to_vec(&pk)
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        let pk_key = format!("passkey:{}", cred_id);
        store
            .set(&pk_key, &serialized_pk)
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(format!("{:?}", e)))?;

        let list_key = format!("user_passkeys:{}", user_id);
        let mut list: Vec<String> = match store.get(&list_key) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
            _ => Vec::new(),
        };
        if !list.contains(&cred_id.to_string()) {
            list.push(cred_id.to_string());
            let serialized_list = serde_json::to_vec(&list)
                .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
            store.set(&list_key, &serialized_list).map_err(|e| {
                passkey_server::error::PasskeyError::DatabaseError(format!("{:?}", e))
            })?;
        }
        Ok(())
    }

    async fn get_passkey(
        &self,
        cred_id: &str,
    ) -> Result<Option<passkey_server::types::StoredPasskey>, passkey_server::error::PasskeyError>
    {
        let store = self
            .open_store()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        let key = format!("passkey:{}", cred_id);
        match store.get(&key) {
            Ok(Some(bytes)) => {
                let pk: passkey_server::types::StoredPasskey = serde_json::from_slice(&bytes)
                    .map_err(|e| {
                        passkey_server::error::PasskeyError::DatabaseError(e.to_string())
                    })?;
                Ok(Some(pk))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(passkey_server::error::PasskeyError::DatabaseError(format!(
                "{:?}",
                e
            ))),
        }
    }

    async fn list_passkeys(
        &self,
        user_id: String,
    ) -> Result<Vec<passkey_server::types::StoredPasskey>, passkey_server::error::PasskeyError>
    {
        let store = self
            .open_store()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        let list_key = format!("user_passkeys:{}", user_id);
        let list: Vec<String> = match store.get(&list_key) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
            _ => return Ok(Vec::new()),
        };

        let mut res = Vec::new();
        for cred_id in list {
            let key = format!("passkey:{}", cred_id);
            if let Ok(Some(bytes)) = store.get(&key) {
                if let Ok(pk) =
                    serde_json::from_slice::<passkey_server::types::StoredPasskey>(&bytes)
                {
                    res.push(pk);
                }
            }
        }
        Ok(res)
    }

    async fn delete_passkey(
        &self,
        user_id: String,
        cred_id: &str,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        let store = self
            .open_store()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        let pk_key = format!("passkey:{}", cred_id);
        if let Ok(Some(bytes)) = store.get(&pk_key) {
            if let Ok(pk) = serde_json::from_slice::<passkey_server::types::StoredPasskey>(&bytes) {
                if pk.user_id == user_id {
                    let _ = store.delete(&pk_key);
                }
            }
        }

        let list_key = format!("user_passkeys:{}", user_id);
        if let Ok(Some(bytes)) = store.get(&list_key) {
            if let Ok(mut list) = serde_json::from_slice::<Vec<String>>(&bytes) {
                if let Some(pos) = list.iter().position(|x| x == cred_id) {
                    list.remove(pos);
                    let serialized_list = serde_json::to_vec(&list).map_err(|e| {
                        passkey_server::error::PasskeyError::DatabaseError(e.to_string())
                    })?;
                    let _ = store.set(&list_key, &serialized_list);
                }
            }
        }
        Ok(())
    }

    async fn update_passkey_counter(
        &self,
        cred_id: &str,
        new_counter: i64,
        last_used_at: i64,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        let store = self
            .open_store()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        let key = format!("passkey:{}", cred_id);
        if let Ok(Some(bytes)) = store.get(&key) {
            if let Ok(mut pk) =
                serde_json::from_slice::<passkey_server::types::StoredPasskey>(&bytes)
            {
                pk.counter = new_counter;
                pk.last_used_at = last_used_at;
                let serialized = serde_json::to_vec(&pk).map_err(|e| {
                    passkey_server::error::PasskeyError::DatabaseError(e.to_string())
                })?;
                store.set(&key, &serialized).map_err(|e| {
                    passkey_server::error::PasskeyError::DatabaseError(format!("{:?}", e))
                })?;
            }
        }
        Ok(())
    }

    async fn update_passkey_name(
        &self,
        cred_id: &str,
        new_name: &str,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        let store = self
            .open_store()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        let key = format!("passkey:{}", cred_id);
        if let Ok(Some(bytes)) = store.get(&key) {
            if let Ok(mut pk) =
                serde_json::from_slice::<passkey_server::types::StoredPasskey>(&bytes)
            {
                pk.name = new_name.to_string();
                let serialized = serde_json::to_vec(&pk).map_err(|e| {
                    passkey_server::error::PasskeyError::DatabaseError(e.to_string())
                })?;
                store.set(&key, &serialized).map_err(|e| {
                    passkey_server::error::PasskeyError::DatabaseError(format!("{:?}", e))
                })?;
            }
        }
        Ok(())
    }

    async fn save_state(
        &self,
        id: &str,
        state_json: &str,
        expires_at: i64,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        let store = self
            .open_store()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        let state = passkey_server::types::PasskeyState {
            id: id.to_string(),
            state_json: state_json.to_string(),
            expires_at,
        };
        let serialized = serde_json::to_vec(&state)
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        let key = format!("passkey_state:{}", id);
        store
            .set(&key, &serialized)
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(format!("{:?}", e)))?;
        Ok(())
    }

    async fn get_state(
        &self,
        id: &str,
    ) -> Result<Option<passkey_server::types::PasskeyState>, passkey_server::error::PasskeyError>
    {
        let store = self
            .open_store()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        let key = format!("passkey_state:{}", id);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        match store.get(&key) {
            Ok(Some(bytes)) => {
                let state: passkey_server::types::PasskeyState = serde_json::from_slice(&bytes)
                    .map_err(|e| {
                        passkey_server::error::PasskeyError::DatabaseError(e.to_string())
                    })?;
                if state.expires_at < now {
                    let _ = store.delete(&key);
                    Ok(None)
                } else {
                    Ok(Some(state))
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(passkey_server::error::PasskeyError::DatabaseError(format!(
                "{:?}",
                e
            ))),
        }
    }

    async fn delete_state(&self, id: &str) -> Result<(), passkey_server::error::PasskeyError> {
        let store = self
            .open_store()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        let key = format!("passkey_state:{}", id);
        store
            .delete(&key)
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(format!("{:?}", e)))?;
        Ok(())
    }
}

#[cfg(all(
    feature = "spin",
    not(all(target_arch = "wasm32", target_os = "wasi")),
    feature = "passkey"
))]
#[async_trait::async_trait(?Send)]
impl passkey_server::PasskeyStore for SpinKeyValueStorage {
    async fn create_passkey(
        &self,
        _user_id: String,
        _cred_id: &str,
        _public_key: &str,
        _name: &str,
        _counter: i64,
        _created_at: i64,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }

    async fn get_passkey(
        &self,
        _cred_id: &str,
    ) -> Result<Option<passkey_server::types::StoredPasskey>, passkey_server::error::PasskeyError>
    {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }

    async fn list_passkeys(
        &self,
        _user_id: String,
    ) -> Result<Vec<passkey_server::types::StoredPasskey>, passkey_server::error::PasskeyError>
    {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }

    async fn delete_passkey(
        &self,
        _user_id: String,
        _cred_id: &str,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }

    async fn update_passkey_counter(
        &self,
        _cred_id: &str,
        _new_counter: i64,
        _last_used_at: i64,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }

    async fn update_passkey_name(
        &self,
        _cred_id: &str,
        _new_name: &str,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }

    async fn save_state(
        &self,
        _id: &str,
        _state_json: &str,
        _expires_at: i64,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }

    async fn get_state(
        &self,
        _id: &str,
    ) -> Result<Option<passkey_server::types::PasskeyState>, passkey_server::error::PasskeyError>
    {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }

    async fn delete_state(&self, _id: &str) -> Result<(), passkey_server::error::PasskeyError> {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "Spin KV is not supported on this platform".to_string(),
        ))
    }
}
