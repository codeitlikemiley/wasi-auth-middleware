//! Passkey (WebAuthn) helper wrappers and error mappings.
//!
//! This module provides helper functions to integrate WebAuthn authentication (passkeys) into the WASI middleware.
//! It wraps the underlying WebAuthn server implementation (`passkey-server`) to align with the `wasi-auth-middleware`'s
//! error reporting style and traits.
//!
//! # Architecture
//!
//! Passkey authentication follows a two-step handshake for both registration and login:
//! 1. **Registration**:
//!    - Call [`start_passkey_registration`] to get challenge options.
//!    - The client uses the WebAuthn API (`navigator.credentials.create`) and returns the response.
//!    - Call [`finish_passkey_registration`] to verify the credential and save it.
//! 2. **Login/Authentication**:
//!    - Call [`start_passkey_login`] to get challenge options.
//!    - The client uses the WebAuthn API (`navigator.credentials.get`) and returns the assertion response.
//!    - Call [`finish_passkey_login`] to verify the signature and authenticate the user.
use wasi_auth_traits::AuthError;

pub use passkey_server::{
    PasskeyConfig, PasskeyStore,
    types::{
        AssertionResponse, AttestationResponse, LoginResponse, PasskeyState,
        PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
        RegistrationResponse, StoredPasskey,
    },
};

fn map_passkey_error(err: passkey_server::error::PasskeyError) -> AuthError {
    match err {
        passkey_server::error::PasskeyError::InvalidChallenge => {
            AuthError::InvalidSignature("Challenge mismatch".to_string())
        }
        passkey_server::error::PasskeyError::OriginMismatch { expected, got } => {
            AuthError::InvalidSignature(format!(
                "Origin mismatch: expected {}, got {}",
                expected, got
            ))
        }
        passkey_server::error::PasskeyError::InvalidOperationType => {
            AuthError::InvalidSignature("Invalid WebAuthn operation type".to_string())
        }
        passkey_server::error::PasskeyError::RpIdHashMismatch => {
            AuthError::InvalidSignature("Relying Party ID hash mismatch".to_string())
        }
        passkey_server::error::PasskeyError::UserPresentFlagNotSet => {
            AuthError::InvalidSignature("User present flag not set by authenticator".to_string())
        }
        passkey_server::error::PasskeyError::InvalidSignature(msg) => {
            AuthError::InvalidSignature(msg)
        }
        passkey_server::error::PasskeyError::SignatureCounterRegression => {
            AuthError::SessionRevoked(
                "Signature counter regression detected (possible cloned credential)".to_string(),
            )
        }
        passkey_server::error::PasskeyError::PasskeyNotFound => {
            AuthError::KeyMissing("Registered passkey not found for this credential ID".to_string())
        }
        passkey_server::error::PasskeyError::UserHandleMismatch => AuthError::InvalidSignature(
            "User handle does not match registered passkey user ID".to_string(),
        ),
        passkey_server::error::PasskeyError::RegistrationSessionExpired => {
            AuthError::TokenExpired("Registration challenge session expired".to_string())
        }
        passkey_server::error::PasskeyError::LoginSessionExpired => {
            AuthError::TokenExpired("Login challenge session expired".to_string())
        }
        passkey_server::error::PasskeyError::SerializationError(msg) => {
            AuthError::StorageError(format!("Passkey state serialization failure: {}", msg))
        }
        passkey_server::error::PasskeyError::DatabaseError(msg) => {
            AuthError::StorageError(format!("Database error in passkey store: {}", msg))
        }
        passkey_server::error::PasskeyError::Base64Error(err) => {
            AuthError::InvalidSignature(format!("Base64 decoding error: {}", err))
        }
        passkey_server::error::PasskeyError::InternalError(msg) => {
            AuthError::Other(format!("Internal WebAuthn verification error: {}", msg))
        }
    }
}

/// Start a new passkey registration.
///
/// This initiates the WebAuthn registration process by generating cryptographic challenge
/// options (`PublicKeyCredentialCreationOptions`) that should be sent to the client/browser
/// to invoke the `navigator.credentials.create` API.
///
/// # Arguments
///
/// * `store` - A reference to the `PasskeyStore` implementation that will hold temporary challenges.
/// * `user_id` - The unique ID of the user registering the passkey.
/// * `username` - The user's login username.
/// * `display_name` - A friendly display name for the user.
/// * `config` - The Relying Party (RP) configuration (e.g. RP ID and Origin).
/// * `now_ms` - The current epoch time in milliseconds, used to set challenge expiration.
///
/// # Errors
///
/// Returns `Err(AuthError)` if the configuration is invalid or if the challenge cannot be generated.
pub async fn start_passkey_registration<S: PasskeyStore + ?Sized>(
    store: &S,
    user_id: &str,
    username: &str,
    display_name: &str,
    config: &PasskeyConfig,
    now_ms: i64,
) -> Result<PublicKeyCredentialCreationOptions, AuthError> {
    passkey_server::start_registration(store, user_id, username, display_name, config, now_ms)
        .await
        .map_err(map_passkey_error)
}

/// Complete a passkey registration.
///
/// Verifies the authenticator's response (`RegistrationResponse`) against the stored challenge
/// and, if valid, registers and persists the new public key credential in the `PasskeyStore`.
///
/// # Arguments
///
/// * `store` - A reference to the `PasskeyStore` implementation to verify the challenge and save the credential.
/// * `user_id` - The unique ID of the user completing registration.
/// * `config` - The Relying Party (RP) configuration.
/// * `response` - The registration credential data returned by the client-side WebAuthn API.
/// * `now_ms` - The current epoch time in milliseconds, used to check challenge expiration.
///
/// # Errors
///
/// Returns `Err(AuthError)` if the challenge has expired, if the signature/origin checks fail,
/// or if storing the credential fails.
pub async fn finish_passkey_registration<S: PasskeyStore + ?Sized>(
    store: &S,
    user_id: &str,
    config: &PasskeyConfig,
    response: RegistrationResponse,
    now_ms: i64,
) -> Result<(), AuthError> {
    passkey_server::finish_registration(store, user_id, config, response, now_ms)
        .await
        .map_err(map_passkey_error)
}

/// Start a passkey login flow.
///
/// Generates the WebAuthn challenge options (`PublicKeyCredentialRequestOptions`)
/// required by the client/browser to invoke `navigator.credentials.get`.
///
/// # Arguments
///
/// * `store` - A reference to the `PasskeyStore` implementation that will hold the temporary challenge.
/// * `config` - The Relying Party (RP) configuration.
/// * `now_ms` - The current epoch time in milliseconds, used to set challenge expiration.
///
/// # Errors
///
/// Returns `Err(AuthError)` if the challenge cannot be generated or saved.
pub async fn start_passkey_login<S: PasskeyStore + ?Sized>(
    store: &S,
    config: &PasskeyConfig,
    now_ms: i64,
) -> Result<PublicKeyCredentialRequestOptions, AuthError> {
    passkey_server::start_login(store, config, now_ms)
        .await
        .map_err(map_passkey_error)
}

/// Complete a passkey login flow, returning the authenticated user's ID.
///
/// Verifies the assertion response signature returned by the client, validates
/// that the credential exists, and checks the signature counter to detect and prevent
/// cloned credential replay attacks.
///
/// # Arguments
///
/// * `store` - A reference to the `PasskeyStore` implementation to load the credential and verify the assertion.
/// * `config` - The Relying Party (RP) configuration.
/// * `response` - The assertion/login response returned by the client-side WebAuthn API.
/// * `now_ms` - The current epoch time in milliseconds, used to check challenge expiration.
///
/// # Returns
///
/// Returns the authenticated user's ID on success.
///
/// # Errors
///
/// Returns `Err(AuthError)` if verification fails (e.g. invalid signature, expired challenge,
/// signature counter regression).
pub async fn finish_passkey_login<S: PasskeyStore + ?Sized>(
    store: &S,
    config: &PasskeyConfig,
    response: LoginResponse,
    now_ms: i64,
) -> Result<String, AuthError> {
    passkey_server::finish_login(store, config, response, now_ms)
        .await
        .map_err(map_passkey_error)
}
