//! Core trait abstractions for the WASI authentication middleware framework.
//!
//! This crate defines the [`AuthStorage`] and [`EmailSender`] traits that form the
//! pluggable backend interface for session management, OTP (one-time password)
//! verification, and email delivery in the `wasi-auth-middleware` ecosystem.
//!
//! # Storage Backends
//!
//! | Backend | Type | Feature Flag |
//! |---------|------|--------------|
//! | [`InMemoryStorage`] | Thread-safe in-memory (`RwLock<HashMap>`) | *(always available)* |
//! | `SpinKeyValueStorage` | Spin SDK key-value store | `spin` |
//! | `SQLiteStorage` | Spin SDK SQLite database | `sqlite` |
//!
//! # Email Senders
//!
//! | Sender | Purpose | Feature Flag |
//! |--------|---------|--------------||
//! | [`StdoutEmail`] | Prints emails to stdout (dev/testing) | *(always available)* |
//! | `HttpEmail` | Sends emails via HTTP POST to an external service | `http-email` |
//!
//! # Feature Flags
//!
//! - **`spin`** — Enables `SpinKeyValueStorage`, which uses the Spin SDK's
//!   key-value store. Only functional on `wasm32-wasi` targets.
//! - **`sqlite`** — Enables `SQLiteStorage`, which uses the Spin SDK's SQLite
//!   support. Only functional on `wasm32-wasi` targets.
//! - **`http-email`** — Enables `HttpEmail`, which sends emails over HTTP.
//!   Uses the Spin SDK on WASI targets and `ureq` on native platforms.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur within the authentication middleware.
///
/// Each variant wraps a human-readable message describing the failure.
#[derive(Debug, Error, Clone)]
pub enum AuthError {
    #[error("Token expired: {0}")]
    TokenExpired(String),
    #[error("Signature mismatch: {0}")]
    SignatureMismatch(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Key missing: {0}")]
    KeyMissing(String),
    #[error("Session revoked: {0}")]
    SessionRevoked(String),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Email error: {0}")]
    EmailError(String),
    #[error("Other error: {0}")]
    Other(String),
}

impl AuthError {
    /// Returns a static string slice representing the error variant name.
    pub fn code(&self) -> &'static str {
        match self {
            AuthError::TokenExpired(_) => "TokenExpired",
            AuthError::SignatureMismatch(_) => "SignatureMismatch",
            AuthError::InvalidSignature(_) => "InvalidSignature",
            AuthError::KeyMissing(_) => "KeyMissing",
            AuthError::SessionRevoked(_) => "SessionRevoked",
            AuthError::StorageError(_) => "StorageError",
            AuthError::EmailError(_) => "EmailError",
            AuthError::Other(_) => "Other",
        }
    }

    /// Returns the wrapped error message string slice.
    pub fn message(&self) -> &str {
        match self {
            AuthError::TokenExpired(msg) => msg,
            AuthError::SignatureMismatch(msg) => msg,
            AuthError::InvalidSignature(msg) => msg,
            AuthError::KeyMissing(msg) => msg,
            AuthError::SessionRevoked(msg) => msg,
            AuthError::StorageError(msg) => msg,
            AuthError::EmailError(msg) => msg,
            AuthError::Other(msg) => msg,
        }
    }
}

/// Represents an authenticated user session.
///
/// Sessions are stored and retrieved through an [`AuthStorage`] implementation.
/// They carry the user's identity, assigned roles, and an expiration timestamp
/// so that backends can automatically clean up stale entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique identifier for this session (typically a UUID or random token).
    /// Used as the primary key when retrieving session details from storage.
    pub session_id: String,
    /// Identifier of the authenticated user who owns this session.
    /// This links the session to a specific user record.
    pub user_id: String,
    /// Authorization roles granted to the user for this session (e.g., `["admin", "editor"]`).
    /// These are used for role-based access control checks.
    pub roles: Vec<String>,
    /// Unix timestamp (seconds since epoch) after which the session is considered expired.
    /// Storage backends and middleware should reject sessions if `expires_at` is in the past.
    pub expires_at: u64,
}

/// Trait for pluggable authentication storage backends.
///
/// Implementors provide persistence for two kinds of data:
///
/// - **Sessions** — created after successful authentication, looked up on every
///   authenticated request, and explicitly deleted on logout.
/// - **One-Time Passwords (OTPs)** — short-lived codes sent to a user's email
///   address and verified once to complete a passwordless login flow.
///
/// All methods are synchronous and return [`Result<_, AuthError>`].
pub trait AuthStorage {
    /// Persists a new session (or replaces an existing one with the same `session_id`).
    ///
    /// # Arguments
    ///
    /// * `session_id` — Unique session identifier.
    /// * `user_id` — The authenticated user's identifier.
    /// * `roles` — Authorization roles associated with the session.
    /// * `expires_at` — Unix timestamp (seconds) after which the session expires.
    fn store_session(
        &self,
        session_id: &str,
        user_id: &str,
        roles: &[String],
        expires_at: u64,
    ) -> Result<(), AuthError>;

    /// Retrieves a session by its identifier.
    ///
    /// Returns `Ok(None)` if the session does not exist **or** has expired.
    /// Implementations should clean up expired sessions encountered during lookup.
    fn get_session(&self, session_id: &str) -> Result<Option<Session>, AuthError>;

    /// Deletes a session by its identifier (e.g., on user logout).
    ///
    /// Returns `Ok(())` even if the session did not exist.
    fn delete_session(&self, session_id: &str) -> Result<(), AuthError>;

    /// Stores a one-time password for the given email address.
    ///
    /// If an OTP already exists for `email`, it is replaced.
    ///
    /// # Arguments
    ///
    /// * `email` — The email address the OTP is associated with.
    /// * `otp` — The plaintext OTP code.
    /// * `expires_at` — Unix timestamp (seconds) after which the OTP is no longer valid.
    fn store_otp(&self, email: &str, otp: &str, expires_at: u64) -> Result<(), AuthError>;

    /// Verifies a one-time password for the given email address.
    ///
    /// The OTP is **consumed** (deleted) regardless of whether verification succeeds.
    /// This prevents replay attacks. Returns `Ok(true)` only when the OTP matches
    /// and has not expired; otherwise returns `Ok(false)`.
    fn verify_otp(&self, email: &str, otp: &str) -> Result<bool, AuthError>;

    /// Stores the TOTP secret key for the given email address.
    fn store_totp_secret(&self, _email: &str, _secret: &str) -> Result<(), AuthError> {
        Err(AuthError::Other("TOTP storage not implemented".to_string()))
    }

    /// Retrieves the TOTP secret key for the given email address.
    fn get_totp_secret(&self, _email: &str) -> Result<Option<String>, AuthError> {
        Err(AuthError::Other("TOTP storage not implemented".to_string()))
    }

    /// Deletes the TOTP secret key for the given email address (disables TOTP).
    fn delete_totp_secret(&self, _email: &str) -> Result<(), AuthError> {
        Err(AuthError::Other("TOTP storage not implemented".to_string()))
    }

    /// Blacklists a token or JWT ID (JTI) until the given expiration timestamp.
    fn blacklist_jti(&self, _jti: &str, _expires_at: u64) -> Result<(), AuthError> {
        Err(AuthError::Other(
            "JTI blacklisting not implemented".to_string(),
        ))
    }

    /// Checks if a token or JWT ID (JTI) is blacklisted.
    fn is_jti_blacklisted(&self, _jti: &str) -> Result<bool, AuthError> {
        Err(AuthError::Other(
            "JTI blacklisting not implemented".to_string(),
        ))
    }

    /// Deletes all expired sessions, expired OTPs, and expired blacklisted JTIs.
    ///
    /// This method is intended to be called periodically (e.g. via a cron job or scheduled task)
    /// to clean up stale data from the database and prevent storage growth.
    fn cleanup_expired(&self) -> Result<(), AuthError> {
        Ok(())
    }
}

/// Trait for pluggable email delivery backends.
///
/// Used by the authentication middleware to send one-time passwords and other
/// transactional messages to users.
pub trait EmailSender {
    /// Sends an email message.
    ///
    /// # Arguments
    ///
    /// * `to` — Recipient email address.
    /// * `subject` — Email subject line.
    /// * `body` — Plain-text email body.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::EmailError`] if delivery fails.
    fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), AuthError>;
}

/// Trait for pluggable rate limiting backends.
///
/// Implementors provide rate limiting checks and action recording to protect
/// endpoints (like OTP dispatch or login) from brute force attacks and abuse.
pub trait RateLimiter {
    /// Check if the action is allowed for the given key (IP, email, etc.).
    ///
    /// # Arguments
    ///
    /// * `key` - The identifier for the entity being rate-limited (e.g. an IP address or email address).
    /// * `action` - The specific action being performed (e.g. "send_otp", "login").
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if the action is allowed under current limits.
    /// * `Ok(false)` if the entity has exceeded limits and should be blocked.
    /// * `Err(AuthError)` if the rate limiter backend encounters an internal error.
    fn check_rate_limit(&self, key: &str, action: &str) -> Result<bool, AuthError>;

    /// Record an action occurrence for the given key.
    ///
    /// This increments the action count or records the timestamp of the attempt
    /// to ensure future limit checks account for this action.
    ///
    /// # Arguments
    ///
    /// * `key` - The identifier for the entity performing the action.
    /// * `action` - The specific action being recorded.
    ///
    /// # Errors
    ///
    /// Returns `Err(AuthError)` if recording the action fails (e.g., database lock failure).
    fn record_action(&self, key: &str, action: &str) -> Result<(), AuthError>;
}

pub mod in_memory;
pub mod rate_limiter;
pub mod stdout_email;

#[cfg(feature = "spin")]
pub mod spin_kv;

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "http-email")]
pub mod http_email;

pub use in_memory::InMemoryStorage;
pub use rate_limiter::InMemoryRateLimiter;
pub use stdout_email::StdoutEmail;

#[cfg(feature = "spin")]
pub use spin_kv::SpinKeyValueStorage;

#[cfg(feature = "sqlite")]
pub use sqlite::SQLiteStorage;

#[cfg(feature = "http-email")]
pub use http_email::HttpEmail;

/// Hash an OTP (One-Time Password) using Argon2.
///
/// This securely hashes the plaintext OTP so that it can be safely stored in the backend
/// without risk of exposure in case of storage leaks. Uses a randomly generated salt.
///
/// # Arguments
///
/// * `otp` - The plaintext OTP code to hash.
///
/// # Errors
///
/// Returns `Err(AuthError::Other)` if the Argon2 hashing routine fails.
#[cfg(feature = "hash-otp")]
pub fn hash_otp(otp: &str) -> Result<String, AuthError> {
    use argon2::{
        Argon2,
        password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
    };
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(otp.as_bytes(), &salt)
        .map_err(|e| AuthError::Other(format!("Argon2 hashing failed: {}", e)))?
        .to_string();
    Ok(password_hash)
}

/// Verify a plaintext OTP (One-Time Password) against its stored Argon2 hash.
///
/// # Arguments
///
/// * `otp` - The plaintext OTP provided by the user.
/// * `hashed_otp` - The Argon2 hash previously generated by `hash_otp` and stored.
///
/// # Returns
///
/// * `true` if the plaintext OTP matches the hash.
/// * `false` if the verification fails or if the hash is malformed.
#[cfg(feature = "hash-otp")]
pub fn verify_otp_hash(otp: &str, hashed_otp: &str) -> bool {
    use argon2::{Argon2, PasswordHash, password_hash::PasswordVerifier};
    let parsed_hash = match PasswordHash::new(hashed_otp) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(otp.as_bytes(), &parsed_hash)
        .is_ok()
}
