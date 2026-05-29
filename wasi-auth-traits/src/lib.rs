use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum AuthError {
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Crypto/Validation error: {0}")]
    Crypto(String),
    #[error("Email error: {0}")]
    Email(String),
    #[error("Other error: {0}")]
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub user_id: String,
    pub roles: Vec<String>,
    pub expires_at: u64,
}

pub trait AuthStorage {
    fn store_session(
        &self,
        session_id: &str,
        user_id: &str,
        roles: &[String],
        expires_at: u64,
    ) -> Result<(), AuthError>;
    fn get_session(&self, session_id: &str) -> Result<Option<Session>, AuthError>;
    fn delete_session(&self, session_id: &str) -> Result<(), AuthError>;
    fn store_otp(&self, email: &str, otp: &str, expires_at: u64) -> Result<(), AuthError>;
    fn verify_otp(&self, email: &str, otp: &str) -> Result<bool, AuthError>;
}

pub trait EmailSender {
    fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), AuthError>;
}

pub mod in_memory;
pub mod stdout_email;

#[cfg(feature = "spin")]
pub mod spin_kv;

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "http-email")]
pub mod http_email;

pub use in_memory::InMemoryStorage;
pub use stdout_email::StdoutEmail;

#[cfg(feature = "spin")]
pub use spin_kv::SpinKeyValueStorage;

#[cfg(feature = "sqlite")]
pub use sqlite::SQLiteStorage;

#[cfg(feature = "http-email")]
pub use http_email::HttpEmail;
