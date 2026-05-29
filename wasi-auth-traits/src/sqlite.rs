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
/// methods return [`AuthError::Storage`](crate::AuthError::Storage).
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
            .map_err(|e| AuthError::Storage(format!("Failed to open Spin SQLite: {:?}", e)))
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
        .map_err(|e| AuthError::Storage(format!("Failed to create sessions table: {:?}", e)))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS otps (
                email TEXT PRIMARY KEY,
                otp TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );",
            &[],
        )
        .map_err(|e| AuthError::Storage(format!("Failed to create otps table: {:?}", e)))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS totp_secrets (
                email TEXT PRIMARY KEY,
                secret TEXT NOT NULL
            );",
            &[],
        )
        .map_err(|e| AuthError::Storage(format!("Failed to create totp_secrets table: {:?}", e)))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS blacklisted_jtis (
                jti TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL
            );",
            &[],
        )
        .map_err(|e| {
            AuthError::Storage(format!("Failed to create blacklisted_jtis table: {:?}", e))
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
            .map_err(|e| AuthError::Storage(format!("Roles serialization failed: {}", e)))?;

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
        ).map_err(|e| AuthError::Storage(format!("SQLite execute error: {:?}", e)))?;
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
            .map_err(|e| AuthError::Storage(format!("SQLite query error: {:?}", e)))?;

        if let Some(row) = row_set.rows.first() {
            let user_id = match &row.values[0] {
                Value::Text(s) => s.clone(),
                _ => return Err(AuthError::Storage("Invalid user_id type".to_string())),
            };
            let roles_str = match &row.values[1] {
                Value::Text(s) => s.clone(),
                _ => return Err(AuthError::Storage("Invalid roles type".to_string())),
            };
            let expires_at_val = match &row.values[2] {
                Value::Integer(i) => *i,
                _ => return Err(AuthError::Storage("Invalid expires_at type".to_string())),
            };

            let roles: Vec<String> = serde_json::from_str(&roles_str)
                .map_err(|e| AuthError::Storage(format!("Roles deserialization failed: {}", e)))?;

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
        .map_err(|e| AuthError::Storage(format!("SQLite delete error: {:?}", e)))?;
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
        .map_err(|e| AuthError::Storage(format!("SQLite store OTP error: {:?}", e)))?;
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
            .map_err(|e| AuthError::Storage(format!("SQLite query OTP error: {:?}", e)))?;

        if let Some(row) = row_set.rows.first() {
            let db_otp = match &row.values[0] {
                Value::Text(s) => s.clone(),
                _ => return Err(AuthError::Storage("Invalid otp type".to_string())),
            };
            let expires_at_val = match &row.values[1] {
                Value::Integer(i) => *i,
                _ => return Err(AuthError::Storage("Invalid expires_at type".to_string())),
            };

            let expires_at = expires_at_val as u64;
            // Delete on use
            conn.execute(
                "DELETE FROM otps WHERE email = ?",
                &[Value::Text(email.to_string())],
            )
            .map_err(|e| AuthError::Storage(format!("SQLite delete OTP error: {:?}", e)))?;

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
        .map_err(|e| AuthError::Storage(format!("SQLite store TOTP secret error: {:?}", e)))?;
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
            .map_err(|e| AuthError::Storage(format!("SQLite query TOTP secret error: {:?}", e)))?;
        if let Some(row) = row_set.rows.first() {
            match &row.values[0] {
                Value::Text(s) => Ok(Some(s.clone())),
                _ => Err(AuthError::Storage("Invalid secret type".to_string())),
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
        .map_err(|e| AuthError::Storage(format!("SQLite delete TOTP secret error: {:?}", e)))?;
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
        .map_err(|e| AuthError::Storage(format!("SQLite blacklist JTI error: {:?}", e)))?;
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
                AuthError::Storage(format!("SQLite query blacklisted JTI error: {:?}", e))
            })?;
        if let Some(row) = row_set.rows.first() {
            let expires_at_val = match &row.values[0] {
                Value::Integer(i) => *i,
                _ => return Err(AuthError::Storage("Invalid expires_at type".to_string())),
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
        .map_err(|e| AuthError::Storage(format!("SQLite cleanup sessions error: {:?}", e)))?;

        conn.execute(
            "DELETE FROM otps WHERE expires_at < ?",
            &[Value::Integer(now)],
        )
        .map_err(|e| AuthError::Storage(format!("SQLite cleanup otps error: {:?}", e)))?;

        conn.execute(
            "DELETE FROM blacklisted_jtis WHERE expires_at < ?",
            &[Value::Integer(now)],
        )
        .map_err(|e| {
            AuthError::Storage(format!("SQLite cleanup blacklisted JTIs error: {:?}", e))
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
        Err(AuthError::Storage(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn get_session(&self, _session_id: &str) -> Result<Option<Session>, AuthError> {
        Err(AuthError::Storage(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn delete_session(&self, _session_id: &str) -> Result<(), AuthError> {
        Err(AuthError::Storage(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn store_otp(&self, _email: &str, _otp: &str, _expires_at: u64) -> Result<(), AuthError> {
        Err(AuthError::Storage(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn verify_otp(&self, _email: &str, _otp: &str) -> Result<bool, AuthError> {
        Err(AuthError::Storage(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn store_totp_secret(&self, _email: &str, _secret: &str) -> Result<(), AuthError> {
        Err(AuthError::Storage(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn get_totp_secret(&self, _email: &str) -> Result<Option<String>, AuthError> {
        Err(AuthError::Storage(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn delete_totp_secret(&self, _email: &str) -> Result<(), AuthError> {
        Err(AuthError::Storage(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn blacklist_jti(&self, _jti: &str, _expires_at: u64) -> Result<(), AuthError> {
        Err(AuthError::Storage(
            "SQLite is not supported on this platform".to_string(),
        ))
    }
    fn is_jti_blacklisted(&self, _jti: &str) -> Result<bool, AuthError> {
        Err(AuthError::Storage(
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
