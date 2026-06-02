use crate::{AuthError, Session};

/// [`AuthStorage`](crate::AuthStorage) implementation backed by the
/// [Spin SDK SQLite database](https://developer.fermyon.com/spin/v2/sqlite-api-guide).
///
/// # Table Schema
///
/// Two tables are created automatically via [`new()`](Self::new) (using
/// `CREATE TABLE IF NOT EXISTS`):
///
/// ```sql
/// CREATE TABLE sessions (
///     session_id TEXT PRIMARY KEY,
///     user_id    TEXT    NOT NULL,
///     roles      TEXT    NOT NULL,   -- JSON array of role strings
///     expires_at INTEGER NOT NULL    -- Unix timestamp (seconds)
/// );
///
/// CREATE TABLE otps (
///     email      TEXT PRIMARY KEY,
///     otp        TEXT    NOT NULL,
///     expires_at INTEGER NOT NULL    -- Unix timestamp (seconds)
/// );
/// ```
///
/// # Platform Support
///
/// This backend is only functional when compiled for `wasm32-wasi` targets and
/// executed inside the Spin runtime. On native (non-WASI) platforms all trait
/// methods return [`AuthError::StorageError`](crate::AuthError::StorageError).
///
/// Requires the `sqlite` feature flag.
#[cfg(feature = "sqlite")]
pub struct SQLiteStorage {
    #[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
    db_name: String,
}

#[cfg(feature = "sqlite")]
impl Default for SQLiteStorage {
    fn default() -> Self {
        Self::open_default()
    }
}

#[cfg(feature = "sqlite")]
impl SQLiteStorage {
    /// Creates a new `SQLiteStorage` that connects to the named Spin SQLite database.
    ///
    /// On WASI targets the constructor automatically calls [`init_db`](Self::init_db)
    /// to create the `sessions` and `otps` tables if they do not already exist.
    /// Initialization errors are logged to `stderr` but do **not** prevent
    /// construction.
    ///
    /// On native platforms the `db_name` is silently ignored.
    pub fn new(db_name: String) -> Self {
        #[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
        {
            let storage = Self { db_name };
            if let Err(e) = storage.init_db() {
                eprintln!(
                    "Warning: Failed to initialize SQLite database tables: {:?}",
                    e
                );
            }
            storage
        }
        #[cfg(not(all(target_arch = "wasm32", target_os = "wasi")))]
        {
            let _ = db_name;
            Self {}
        }
    }

    /// Opens the `"default"` Spin SQLite database.
    pub fn open_default() -> Self {
        Self::new("default".to_string())
    }

    /// Opens a connection to the underlying Spin SQLite database.
    #[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
    fn open_connection(&self) -> Result<spin_sdk::sqlite::Connection, AuthError> {
        spin_sdk::sqlite::Connection::open(&self.db_name)
            .map_err(|e| AuthError::StorageError(format!("Failed to open Spin SQLite: {:?}", e)))
    }

    /// Initializes the database schema by creating the `sessions` and `otps`
    /// tables if they do not already exist.
    #[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
    fn init_db(&self) -> Result<(), AuthError> {
        let conn = self.open_connection()?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                roles TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );",
            &[],
        )
        .map_err(|e| {
            AuthError::StorageError(format!("Failed to create sessions table: {:?}", e))
        })?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS otps (
                email TEXT PRIMARY KEY,
                otp TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );",
            &[],
        )
        .map_err(|e| AuthError::StorageError(format!("Failed to create otps table: {:?}", e)))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS totp_secrets (
                email TEXT PRIMARY KEY,
                secret TEXT NOT NULL
            );",
            &[],
        )
        .map_err(|e| {
            AuthError::StorageError(format!("Failed to create totp_secrets table: {:?}", e))
        })?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS blacklisted_jtis (
                jti TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL
            );",
            &[],
        )
        .map_err(|e| {
            AuthError::StorageError(format!("Failed to create blacklisted_jtis table: {:?}", e))
        })?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS passkeys (
                user_id TEXT NOT NULL,
                cred_id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                name TEXT NOT NULL,
                counter INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                last_used_at INTEGER NOT NULL
            );",
            &[],
        )
        .map_err(|e| {
            AuthError::StorageError(format!("Failed to create passkeys table: {:?}", e))
        })?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS passkey_states (
                id TEXT PRIMARY KEY,
                state_json TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );",
            &[],
        )
        .map_err(|e| {
            AuthError::StorageError(format!("Failed to create passkey_states table: {:?}", e))
        })?;

        Ok(())
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

#[cfg(all(feature = "sqlite", target_arch = "wasm32", target_os = "wasi"))]
impl crate::AuthStorage for SQLiteStorage {
    fn store_session(
        &self,
        session_id: &str,
        user_id: &str,
        roles: &[String],
        expires_at: u64,
    ) -> Result<(), AuthError> {
        let conn = self.open_connection()?;
        let roles_json = serde_json::to_string(roles)
            .map_err(|e| AuthError::StorageError(format!("Roles serialization failed: {}", e)))?;

        use spin_sdk::sqlite::Value;
        let params = [
            Value::Text(session_id.to_string()),
            Value::Text(user_id.to_string()),
            Value::Text(roles_json),
            Value::Integer(expires_at as i64),
        ];

        conn.execute(
            "INSERT OR REPLACE INTO sessions (session_id, user_id, roles, expires_at) VALUES (?, ?, ?, ?)",
            &params
        ).map_err(|e| AuthError::StorageError(format!("SQLite execute error: {:?}", e)))?;
        Ok(())
    }

    fn get_session(&self, session_id: &str) -> Result<Option<Session>, AuthError> {
        let conn = self.open_connection()?;
        use spin_sdk::sqlite::Value;

        let row_set = conn
            .execute(
                "SELECT user_id, roles, expires_at FROM sessions WHERE session_id = ?",
                &[Value::Text(session_id.to_string())],
            )
            .map_err(|e| AuthError::StorageError(format!("SQLite query error: {:?}", e)))?;

        if let Some(row) = row_set.rows.first() {
            let user_id = match &row.values[0] {
                Value::Text(s) => s.clone(),
                _ => return Err(AuthError::StorageError("Invalid user_id type".to_string())),
            };
            let roles_str = match &row.values[1] {
                Value::Text(s) => s.clone(),
                _ => return Err(AuthError::StorageError("Invalid roles type".to_string())),
            };
            let expires_at_val = match &row.values[2] {
                Value::Integer(i) => *i,
                _ => {
                    return Err(AuthError::StorageError(
                        "Invalid expires_at type".to_string(),
                    ));
                }
            };

            let roles: Vec<String> = serde_json::from_str(&roles_str).map_err(|e| {
                AuthError::StorageError(format!("Roles deserialization failed: {}", e))
            })?;

            let expires_at = expires_at_val as u64;
            if expires_at < self.get_now() {
                let _ = conn.execute(
                    "DELETE FROM sessions WHERE session_id = ?",
                    &[Value::Text(session_id.to_string())],
                );
                Ok(None)
            } else {
                Ok(Some(Session {
                    session_id: session_id.to_string(),
                    user_id,
                    roles,
                    expires_at,
                }))
            }
        } else {
            Ok(None)
        }
    }

    fn delete_session(&self, session_id: &str) -> Result<(), AuthError> {
        let conn = self.open_connection()?;
        use spin_sdk::sqlite::Value;
        conn.execute(
            "DELETE FROM sessions WHERE session_id = ?",
            &[Value::Text(session_id.to_string())],
        )
        .map_err(|e| AuthError::StorageError(format!("SQLite delete error: {:?}", e)))?;
        Ok(())
    }

    fn store_otp(&self, email: &str, otp: &str, expires_at: u64) -> Result<(), AuthError> {
        let conn = self.open_connection()?;
        use spin_sdk::sqlite::Value;

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

        let params = [
            Value::Text(email.to_string()),
            Value::Text(stored_otp),
            Value::Integer(expires_at as i64),
        ];

        conn.execute(
            "INSERT OR REPLACE INTO otps (email, otp, expires_at) VALUES (?, ?, ?)",
            &params,
        )
        .map_err(|e| AuthError::StorageError(format!("SQLite store OTP error: {:?}", e)))?;
        Ok(())
    }

    fn verify_otp(&self, email: &str, otp: &str) -> Result<bool, AuthError> {
        let conn = self.open_connection()?;
        use spin_sdk::sqlite::Value;

        let row_set = conn
            .execute(
                "SELECT otp, expires_at FROM otps WHERE email = ?",
                &[Value::Text(email.to_string())],
            )
            .map_err(|e| AuthError::StorageError(format!("SQLite query OTP error: {:?}", e)))?;

        if let Some(row) = row_set.rows.first() {
            let db_otp = match &row.values[0] {
                Value::Text(s) => s.clone(),
                _ => return Err(AuthError::StorageError("Invalid otp type".to_string())),
            };
            let expires_at_val = match &row.values[1] {
                Value::Integer(i) => *i,
                _ => {
                    return Err(AuthError::StorageError(
                        "Invalid expires_at type".to_string(),
                    ));
                }
            };

            let expires_at = expires_at_val as u64;
            // Delete on use
            conn.execute(
                "DELETE FROM otps WHERE email = ?",
                &[Value::Text(email.to_string())],
            )
            .map_err(|e| AuthError::StorageError(format!("SQLite delete OTP error: {:?}", e)))?;

            if expires_at >= self.get_now() {
                #[cfg(feature = "hash-otp")]
                {
                    Ok(crate::verify_otp_hash(otp, &db_otp))
                }
                #[cfg(not(feature = "hash-otp"))]
                {
                    Ok(db_otp == otp)
                }
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    fn store_totp_secret(&self, email: &str, secret: &str) -> Result<(), AuthError> {
        let conn = self.open_connection()?;
        use spin_sdk::sqlite::Value;
        let params = [
            Value::Text(email.to_string()),
            Value::Text(secret.to_string()),
        ];
        conn.execute(
            "INSERT OR REPLACE INTO totp_secrets (email, secret) VALUES (?, ?)",
            &params,
        )
        .map_err(|e| AuthError::StorageError(format!("SQLite store TOTP secret error: {:?}", e)))?;
        Ok(())
    }

    fn get_totp_secret(&self, email: &str) -> Result<Option<String>, AuthError> {
        let conn = self.open_connection()?;
        use spin_sdk::sqlite::Value;
        let row_set = conn
            .execute(
                "SELECT secret FROM totp_secrets WHERE email = ?",
                &[Value::Text(email.to_string())],
            )
            .map_err(|e| {
                AuthError::StorageError(format!("SQLite query TOTP secret error: {:?}", e))
            })?;
        if let Some(row) = row_set.rows.first() {
            match &row.values[0] {
                Value::Text(s) => Ok(Some(s.clone())),
                _ => Err(AuthError::StorageError("Invalid secret type".to_string())),
            }
        } else {
            Ok(None)
        }
    }

    fn delete_totp_secret(&self, email: &str) -> Result<(), AuthError> {
        let conn = self.open_connection()?;
        use spin_sdk::sqlite::Value;
        conn.execute(
            "DELETE FROM totp_secrets WHERE email = ?",
            &[Value::Text(email.to_string())],
        )
        .map_err(|e| {
            AuthError::StorageError(format!("SQLite delete TOTP secret error: {:?}", e))
        })?;
        Ok(())
    }

    fn blacklist_jti(&self, jti: &str, expires_at: u64) -> Result<(), AuthError> {
        let conn = self.open_connection()?;
        use spin_sdk::sqlite::Value;
        let params = [
            Value::Text(jti.to_string()),
            Value::Integer(expires_at as i64),
        ];
        conn.execute(
            "INSERT OR REPLACE INTO blacklisted_jtis (jti, expires_at) VALUES (?, ?)",
            &params,
        )
        .map_err(|e| AuthError::StorageError(format!("SQLite blacklist JTI error: {:?}", e)))?;
        Ok(())
    }

    fn is_jti_blacklisted(&self, jti: &str) -> Result<bool, AuthError> {
        let conn = self.open_connection()?;
        use spin_sdk::sqlite::Value;
        let row_set = conn
            .execute(
                "SELECT expires_at FROM blacklisted_jtis WHERE jti = ?",
                &[Value::Text(jti.to_string())],
            )
            .map_err(|e| {
                AuthError::StorageError(format!("SQLite query blacklisted JTI error: {:?}", e))
            })?;
        if let Some(row) = row_set.rows.first() {
            let expires_at_val = match &row.values[0] {
                Value::Integer(i) => *i,
                _ => {
                    return Err(AuthError::StorageError(
                        "Invalid expires_at type".to_string(),
                    ));
                }
            };
            let expires_at = expires_at_val as u64;
            if expires_at < self.get_now() {
                let _ = conn.execute(
                    "DELETE FROM blacklisted_jtis WHERE jti = ?",
                    &[Value::Text(jti.to_string())],
                );
                Ok(false)
            } else {
                Ok(true)
            }
        } else {
            Ok(false)
        }
    }

    fn cleanup_expired(&self) -> Result<(), AuthError> {
        let conn = self.open_connection()?;
        let now = self.get_now() as i64;
        use spin_sdk::sqlite::Value;

        conn.execute(
            "DELETE FROM sessions WHERE expires_at < ?",
            &[Value::Integer(now)],
        )
        .map_err(|e| AuthError::StorageError(format!("SQLite cleanup sessions error: {:?}", e)))?;

        conn.execute(
            "DELETE FROM otps WHERE expires_at < ?",
            &[Value::Integer(now)],
        )
        .map_err(|e| AuthError::StorageError(format!("SQLite cleanup otps error: {:?}", e)))?;

        conn.execute(
            "DELETE FROM blacklisted_jtis WHERE expires_at < ?",
            &[Value::Integer(now)],
        )
        .map_err(|e| {
            AuthError::StorageError(format!("SQLite cleanup blacklisted JTIs error: {:?}", e))
        })?;

        Ok(())
    }
}

#[cfg(all(
    feature = "sqlite",
    not(all(target_arch = "wasm32", target_os = "wasi"))
))]
impl crate::AuthStorage for SQLiteStorage {
    fn store_session(
        &self,
        _session_id: &str,
        _user_id: &str,
        _roles: &[String],
        _expires_at: u64,
    ) -> Result<(), AuthError> {
        Err(AuthError::StorageError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn get_session(&self, _session_id: &str) -> Result<Option<Session>, AuthError> {
        Err(AuthError::StorageError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn delete_session(&self, _session_id: &str) -> Result<(), AuthError> {
        Err(AuthError::StorageError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn store_otp(&self, _email: &str, _otp: &str, _expires_at: u64) -> Result<(), AuthError> {
        Err(AuthError::StorageError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn verify_otp(&self, _email: &str, _otp: &str) -> Result<bool, AuthError> {
        Err(AuthError::StorageError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn store_totp_secret(&self, _email: &str, _secret: &str) -> Result<(), AuthError> {
        Err(AuthError::StorageError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn get_totp_secret(&self, _email: &str) -> Result<Option<String>, AuthError> {
        Err(AuthError::StorageError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn delete_totp_secret(&self, _email: &str) -> Result<(), AuthError> {
        Err(AuthError::StorageError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn blacklist_jti(&self, _jti: &str, _expires_at: u64) -> Result<(), AuthError> {
        Err(AuthError::StorageError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn is_jti_blacklisted(&self, _jti: &str) -> Result<bool, AuthError> {
        Err(AuthError::StorageError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
}

#[cfg(all(
    test,
    feature = "sqlite",
    not(all(target_arch = "wasm32", target_os = "wasi"))
))]
mod tests {
    use super::*;
    use crate::AuthStorage;

    #[test]
    fn test_sqlite_native_errors() {
        let storage = SQLiteStorage::open_default();
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
    feature = "sqlite",
    target_arch = "wasm32",
    target_os = "wasi",
    feature = "passkey"
))]
#[async_trait::async_trait(?Send)]
impl passkey_server::PasskeyStore for SQLiteStorage {
    async fn create_passkey(
        &self,
        user_id: String,
        cred_id: &str,
        public_key: &str,
        name: &str,
        counter: i64,
        created_at: i64,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        let conn = self
            .open_connection()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        use spin_sdk::sqlite::Value;
        let params = [
            Value::Text(user_id),
            Value::Text(cred_id.to_string()),
            Value::Text(public_key.to_string()),
            Value::Text(name.to_string()),
            Value::Integer(counter),
            Value::Integer(created_at),
            Value::Integer(created_at),
        ];
        conn.execute(
            "INSERT OR REPLACE INTO passkeys (user_id, cred_id, public_key, name, counter, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            &params
        ).map_err(|e| passkey_server::error::PasskeyError::DatabaseError(format!("{:?}", e)))?;
        Ok(())
    }

    async fn get_passkey(
        &self,
        cred_id: &str,
    ) -> Result<Option<passkey_server::types::StoredPasskey>, passkey_server::error::PasskeyError>
    {
        let conn = self
            .open_connection()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        use spin_sdk::sqlite::Value;
        let row_set = conn.execute(
            "SELECT user_id, public_key, name, created_at, last_used_at, counter FROM passkeys WHERE cred_id = ?",
            &[Value::Text(cred_id.to_string())]
        ).map_err(|e| passkey_server::error::PasskeyError::DatabaseError(format!("{:?}", e)))?;

        if let Some(row) = row_set.rows.first() {
            let user_id = match &row.values[0] {
                Value::Text(s) => s.clone(),
                _ => {
                    return Err(passkey_server::error::PasskeyError::DatabaseError(
                        "Invalid user_id type".to_string(),
                    ));
                }
            };
            let public_key = match &row.values[1] {
                Value::Text(s) => s.clone(),
                _ => {
                    return Err(passkey_server::error::PasskeyError::DatabaseError(
                        "Invalid public_key type".to_string(),
                    ));
                }
            };
            let name = match &row.values[2] {
                Value::Text(s) => s.clone(),
                _ => {
                    return Err(passkey_server::error::PasskeyError::DatabaseError(
                        "Invalid name type".to_string(),
                    ));
                }
            };
            let created_at = match &row.values[3] {
                Value::Integer(i) => *i,
                _ => {
                    return Err(passkey_server::error::PasskeyError::DatabaseError(
                        "Invalid created_at type".to_string(),
                    ));
                }
            };
            let last_used_at = match &row.values[4] {
                Value::Integer(i) => *i,
                _ => {
                    return Err(passkey_server::error::PasskeyError::DatabaseError(
                        "Invalid last_used_at type".to_string(),
                    ));
                }
            };
            let counter = match &row.values[5] {
                Value::Integer(i) => *i,
                _ => {
                    return Err(passkey_server::error::PasskeyError::DatabaseError(
                        "Invalid counter type".to_string(),
                    ));
                }
            };
            Ok(Some(passkey_server::types::StoredPasskey {
                user_id,
                cred_id: cred_id.to_string(),
                public_key,
                name,
                created_at,
                last_used_at,
                counter,
            }))
        } else {
            Ok(None)
        }
    }

    async fn list_passkeys(
        &self,
        user_id: String,
    ) -> Result<Vec<passkey_server::types::StoredPasskey>, passkey_server::error::PasskeyError>
    {
        let conn = self
            .open_connection()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        use spin_sdk::sqlite::Value;
        let row_set = conn.execute(
            "SELECT cred_id, public_key, name, created_at, last_used_at, counter FROM passkeys WHERE user_id = ?",
            &[Value::Text(user_id.clone())]
        ).map_err(|e| passkey_server::error::PasskeyError::DatabaseError(format!("{:?}", e)))?;

        let mut res = Vec::new();
        for row in row_set.rows {
            let cred_id = match &row.values[0] {
                Value::Text(s) => s.clone(),
                _ => continue,
            };
            let public_key = match &row.values[1] {
                Value::Text(s) => s.clone(),
                _ => continue,
            };
            let name = match &row.values[2] {
                Value::Text(s) => s.clone(),
                _ => continue,
            };
            let created_at = match &row.values[3] {
                Value::Integer(i) => *i,
                _ => continue,
            };
            let last_used_at = match &row.values[4] {
                Value::Integer(i) => *i,
                _ => continue,
            };
            let counter = match &row.values[5] {
                Value::Integer(i) => *i,
                _ => continue,
            };
            res.push(passkey_server::types::StoredPasskey {
                user_id: user_id.clone(),
                cred_id,
                public_key,
                name,
                created_at,
                last_used_at,
                counter,
            });
        }
        Ok(res)
    }

    async fn delete_passkey(
        &self,
        user_id: String,
        cred_id: &str,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        let conn = self
            .open_connection()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        use spin_sdk::sqlite::Value;
        conn.execute(
            "DELETE FROM passkeys WHERE user_id = ? AND cred_id = ?",
            &[Value::Text(user_id), Value::Text(cred_id.to_string())],
        )
        .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(format!("{:?}", e)))?;
        Ok(())
    }

    async fn update_passkey_counter(
        &self,
        cred_id: &str,
        new_counter: i64,
        last_used_at: i64,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        let conn = self
            .open_connection()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        use spin_sdk::sqlite::Value;
        let params = [
            Value::Integer(new_counter),
            Value::Integer(last_used_at),
            Value::Text(cred_id.to_string()),
        ];
        conn.execute(
            "UPDATE passkeys SET counter = ?, last_used_at = ? WHERE cred_id = ?",
            &params,
        )
        .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(format!("{:?}", e)))?;
        Ok(())
    }

    async fn update_passkey_name(
        &self,
        cred_id: &str,
        new_name: &str,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        let conn = self
            .open_connection()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        use spin_sdk::sqlite::Value;
        let params = [
            Value::Text(new_name.to_string()),
            Value::Text(cred_id.to_string()),
        ];
        conn.execute("UPDATE passkeys SET name = ? WHERE cred_id = ?", &params)
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(format!("{:?}", e)))?;
        Ok(())
    }

    async fn save_state(
        &self,
        id: &str,
        state_json: &str,
        expires_at: i64,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        let conn = self
            .open_connection()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        use spin_sdk::sqlite::Value;
        let params = [
            Value::Text(id.to_string()),
            Value::Text(state_json.to_string()),
            Value::Integer(expires_at),
        ];
        conn.execute(
            "INSERT OR REPLACE INTO passkey_states (id, state_json, expires_at) VALUES (?, ?, ?)",
            &params,
        )
        .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(format!("{:?}", e)))?;
        Ok(())
    }

    async fn get_state(
        &self,
        id: &str,
    ) -> Result<Option<passkey_server::types::PasskeyState>, passkey_server::error::PasskeyError>
    {
        let conn = self
            .open_connection()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        use spin_sdk::sqlite::Value;
        let row_set = conn
            .execute(
                "SELECT state_json, expires_at FROM passkey_states WHERE id = ?",
                &[Value::Text(id.to_string())],
            )
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(format!("{:?}", e)))?;

        if let Some(row) = row_set.rows.first() {
            let state_json = match &row.values[0] {
                Value::Text(s) => s.clone(),
                _ => {
                    return Err(passkey_server::error::PasskeyError::DatabaseError(
                        "Invalid state_json type".to_string(),
                    ));
                }
            };
            let expires_at_val = match &row.values[1] {
                Value::Integer(i) => *i,
                _ => {
                    return Err(passkey_server::error::PasskeyError::DatabaseError(
                        "Invalid expires_at type".to_string(),
                    ));
                }
            };

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);

            if expires_at_val < now {
                let _ = conn.execute(
                    "DELETE FROM passkey_states WHERE id = ?",
                    &[Value::Text(id.to_string())],
                );
                Ok(None)
            } else {
                Ok(Some(passkey_server::types::PasskeyState {
                    id: id.to_string(),
                    state_json,
                    expires_at: expires_at_val,
                }))
            }
        } else {
            Ok(None)
        }
    }

    async fn delete_state(&self, id: &str) -> Result<(), passkey_server::error::PasskeyError> {
        let conn = self
            .open_connection()
            .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(e.to_string()))?;
        use spin_sdk::sqlite::Value;
        conn.execute(
            "DELETE FROM passkey_states WHERE id = ?",
            &[Value::Text(id.to_string())],
        )
        .map_err(|e| passkey_server::error::PasskeyError::DatabaseError(format!("{:?}", e)))?;
        Ok(())
    }
}

#[cfg(all(
    feature = "sqlite",
    not(all(target_arch = "wasm32", target_os = "wasi")),
    feature = "passkey"
))]
#[async_trait::async_trait(?Send)]
impl passkey_server::PasskeyStore for SQLiteStorage {
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
            "SQLite is not supported on this platform".to_string(),
        ))
    }

    async fn get_passkey(
        &self,
        _cred_id: &str,
    ) -> Result<Option<passkey_server::types::StoredPasskey>, passkey_server::error::PasskeyError>
    {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }

    async fn list_passkeys(
        &self,
        _user_id: String,
    ) -> Result<Vec<passkey_server::types::StoredPasskey>, passkey_server::error::PasskeyError>
    {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }

    async fn delete_passkey(
        &self,
        _user_id: String,
        _cred_id: &str,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }

    async fn update_passkey_counter(
        &self,
        _cred_id: &str,
        _new_counter: i64,
        _last_used_at: i64,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }

    async fn update_passkey_name(
        &self,
        _cred_id: &str,
        _new_name: &str,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }

    async fn save_state(
        &self,
        _id: &str,
        _state_json: &str,
        _expires_at: i64,
    ) -> Result<(), passkey_server::error::PasskeyError> {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }

    async fn get_state(
        &self,
        _id: &str,
    ) -> Result<Option<passkey_server::types::PasskeyState>, passkey_server::error::PasskeyError>
    {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }

    async fn delete_state(&self, _id: &str) -> Result<(), passkey_server::error::PasskeyError> {
        Err(passkey_server::error::PasskeyError::DatabaseError(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
}
