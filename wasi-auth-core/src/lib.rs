//! # wasi-auth-core
//!
//! The central authentication engine for the `wasi-auth-middleware` system.
//!
//! This crate provides three pillars of authentication functionality:
//!
//! - **JWT (JSON Web Token)** — RS256 token generation and verification using a
//!   **pure-Rust** implementation built on the [`rsa`], [`sha2`], and [`base64`]
//!   crates. Notably, this does *not* depend on the `jsonwebtoken` crate, giving
//!   full control over header construction, signing, and claim validation.
//!
//! - **OAuth2 / OIDC** — A lightweight OAuth 2.0 Authorization Code client with
//!   OpenID Connect discovery support. The [`Oauth2Client`] struct provides static
//!   helpers for building authorization URLs, exchanging codes for tokens, and
//!   fetching user info, all delegated through a pluggable [`HttpClient`] trait.
//!
//! - **OTP (One-Time Password)** — Email-based one-time password flows: generate
//!   a 6-digit numeric code, persist it via [`AuthStorage`], deliver it via
//!   [`EmailSender`], and verify it on submission.
//!
//! ## Re-exports
//!
//! Key trait and type definitions are re-exported from the companion
//! [`wasi_auth_traits`] crate so that downstream consumers only need to depend on
//! `wasi-auth-core`.

pub mod jwt;
pub mod magic_link;
pub mod oauth;
pub mod otp;
pub mod totp;

pub use jwt::{
    Claims, ValidationOptions, extract_kid, generate_jwt, verify_jwt, verify_jwt_with_options,
};
pub use magic_link::{generate_magic_link, verify_magic_link};
pub use oauth::{HttpClient, OAuthConfig, Oauth2Client, TokenResponse, UserInfo};
pub use otp::{generate_otp, send_and_store_otp, verify_otp};
pub use totp::{generate_totp_secret, generate_totp_uri, verify_totp};
pub use wasi_auth_traits::{
    AuthError, AuthStorage, EmailSender, InMemoryRateLimiter, InMemoryStorage, RateLimiter,
    Session, StdoutEmail,
};

/// Returns a static status string confirming the crate is loaded and operational.
///
/// This is a lightweight health-check helper useful for diagnostics or readiness
/// probes — it performs no I/O and cannot fail.
pub fn check_core_status() -> &'static str {
    "WASI Auth Core is running"
}
