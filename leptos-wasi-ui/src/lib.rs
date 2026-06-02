//! # leptos-wasi-ui
//!
//! Premium, configurable Leptos UI components for WASI authentication.
//!
//! This crate provides a library of interactive UI components for integrating authentication
//! features (OTP, Magic Link, MFA, Passkeys, active session management) into Leptos applications.
//!
//! ## Components
//!
//! - [`LoginForm`]: Tabbed sign-in form for Email OTP, Magic Link, and TOTP.
//! - [`MagicLinkForm`]: Passwordless magic link request form.
//! - [`MfaStatus`]: Display current MFA status (Enabled/Disabled) and handle disable callbacks.
//! - [`OtpForm`]: Verification form to request and verify One-Time Passwords.
//! - [`PasskeyLoginButton`] / [`PasskeyRegisterButton`]: Trigger WebAuthn browser ceremonies.
//! - `PasskeyList` (under `passkey` feature): Manage registered passkeys.
//! - [`SessionList`]: List active user sessions and revoke them.
//! - [`TotpSetup`]: Wizard to setup TOTP MFA (Secret key display, provisioning URI, code verification).
//!
//! ## Features
//!
//! - `ssr`: Server-side rendering support.
//! - `hydrate`: Browser hydration support (links WebAuthn browser APIs).
//! - `csr`: Client-side rendering support.
//! - `passkey`: Enables passkey management list.

/// Interactive Leptos components for authentication workflows.
pub mod components;

pub use components::login_form::LoginForm;
pub use components::magic_link_form::MagicLinkForm;
pub use components::mfa_status::MfaStatus;
pub use components::otp_form::OtpForm;
pub use components::passkey_buttons::{PasskeyLoginButton, PasskeyRegisterButton};
pub use components::session_list::SessionList;
pub use components::totp_setup::TotpSetup;

#[cfg(feature = "passkey")]
pub use components::passkey_list::PasskeyList;
