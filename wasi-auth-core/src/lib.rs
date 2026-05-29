pub mod jwt;
pub mod oauth;
pub mod otp;

pub use jwt::{extract_kid, generate_jwt, verify_jwt, Claims};
pub use oauth::{HttpClient, OAuthConfig, Oauth2Client, TokenResponse, UserInfo};
pub use otp::{generate_otp, send_and_store_otp, verify_otp};
pub use wasi_auth_traits::{
    AuthError, AuthStorage, EmailSender, InMemoryStorage, Session, StdoutEmail,
};

pub fn check_core_status() -> &'static str {
    "WASI Auth Core is running"
}
