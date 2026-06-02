//! Passkey (WebAuthn) helper wrappers and error mappings.

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
