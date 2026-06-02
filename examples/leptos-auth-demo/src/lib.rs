#![allow(clippy::unused_unit, clippy::unit_arg, unused_variables)]
use leptos::prelude::*;
use leptos_router::components::*;
use leptos_router::path;
use leptos_wasi::prelude::Handler;
use leptos_wasi_auth::UserSession;
use leptos_wasi_ui::LoginForm;
#[cfg(feature = "passkey")]
use leptos_wasi_ui::PasskeyList;
use leptos_wasi_ui::TotpSetup as TotpSetupForm;
use leptos_wasi_ui::components::login_form::{OtpVerification, TotpVerification};
use leptos_wasi_ui::components::totp_setup::TotpSetupVerification;
use leptos_wasi_ui::{MfaStatus, SessionList};
use tracing::info;
use wasi_auth_core::OAuthConfig;
use wasi_auth_traits::{
    AuthStorage, EmailSender, InMemoryRateLimiter, InMemoryStorage, RateLimiter, StdoutEmail,
};

const PRIV_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD5q9efxvdHIwc3
nZzuPduIhsf8zhbnAUNBAcf1cq1N2t5C8Nve2aYUBe5gQhnFs1lxie6DNARZBWnP
nFV4n2ixIJ83VpJwrppED6CxcXqFMwZC304FSk+UYNhkCOaOc1rxZgpG+yYD0wR+
n3eJpyEl73qblbvcizv6S168Q5CImQp0n+4RXB0Lr87KlhOHhuE1Jsb5wBcxOJ72
IlPKpEU/9XLV4hZYAkMz9eP4g9qH8Rk5xrTXlRt/qXDwHETJwcEmQuOiTZuOii08
st+s/17I++3igpbhGgabSKxyYeimjHAowfebIQBHRyrTzWVU4TUGBC9lNMf8pKzN
+FEiYY8hAgMBAAECggEAQ/2G96zgNBAW7A9Q6BQST6icl3ysAfZ3ESHiCTZUeYor
0sDyr0pIDtXap334tLz1k5TDThmBQZjWysHBCNsoUGwYz6IUuPjja7txwECt484U
W2uiPJCTAU4qP3upBYvmbSyjidbk8E+rvqvAisznmwQPOIVbJmEIUU3rG4uutXOm
EF4Hj90TunstZs0s/lwevsjn6yMYK8uT1KGe8VKC6o/qskiwZ83QJTITqeidTNPL
uqROvBMkd/JpiyCxWSmnT0GJtc0aylOEFZOGevsCG+30dN4pRTEB6Dyoxt44icuN
5EHtHGxalxSlrMpsYH1zpZrOgr7AdpdXEi7hwI11TQKBgQD/bTbYrEcApQAp0h+3
oPPhM1hjXnrJna7UgsfW25Z4UElvhum4Ix86n0d9Nzjy+8TXRNIg4whQIKGwTCeQ
8pe/y2MgQMO1XMvZXS9ugWnOoGxShv8nURDPWzdBERF7f4Y0y7M9iNh5VntKKmBg
cDTzQRBiCCqToVc+4BYqbT2IowKBgQD6O1ITmnZTu5rVLnlfy2tLPlREa/ap+598
CuDpw3+h3BSI9uCTVIqPPlc0kKl1RpaKMA2Ar4Nrfl+7gwhci0iUiqRsBTGWkFMK
t3SyCqSfiUhanEwNEhckf7vMjd37ofPN3OyCwWAqg9lkrdeqWq9EaGlogHdU8Q7k
zldfXFjxawKBgCG1fxx/N+uc2vWp9mechTL+PLb4fAnplm4TSF5Ron0EU3y1eFjF
wdRRuvSKeiiPE345ZeXTMICqncwPcNVPPrmgFNfn1Cw2L+ziwGS8DYOoZkNJ75h3
uVk0N4mNwBnlTYfgLip7yd3RjPnPt+JiTIqh1pCpdT0AeOwiVKqKuikzAoGACqsA
wskxBjzXSwNiNU1M07ZijVA1AeYyVG16TT0CcfoZ/gTYai+OgLDdsuX/83oA7P9D
dBsHdUu79RiPALMHcx2+CMTn6k1Y3PoZRYXiotKNfR9wtpXw2qN/dCcQMawj4sDq
bGCmIungGMS4jxCyrC3vYH8plzt3sRWC8BPVzuUCgYEA3rpUrWyzKC4weZhLj5Fk
vNnoWqqfIFO4ARNqLlgq9h0zbDbkSwq60fkn9l02Kt0mSSo8pvikr+VgXQJYD5A4
qkoTi6fEdvvjYsxsGR3lMXcvZPG7XfmTyweb87IKhw5khiO2U06fp4RgQ8BbLRj3
5W+40tuIapBJ2EcG3+mAhPY=
-----END PRIVATE KEY-----"#;

const PUB_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+avXn8b3RyMHN52c7j3b
iIbH/M4W5wFDQQHH9XKtTdreQvDb3tmmFAXuYEIZxbNZcYnugzQEWQVpz5xVeJ9o
sSCfN1aScK6aRA+gsXF6hTMGQt9OBUpPlGDYZAjmjnNa8WYKRvsmA9MEfp93iach
Je96m5W73Is7+ktevEOQiJkKdJ/uEVwdC6/OypYTh4bhNSbG+cAXMTie9iJTyqRF
P/Vy1eIWWAJDM/Xj+IPah/EZOca015Ubf6lw8BxEycHBJkLjok2bjootPLLfrP9e
yPvt4oKW4RoGm0iscmHopoxwKMH3myEAR0cq081lVOE1BgQvZTTH/KSszfhRImGP
IQIDAQAB
-----END PUBLIC KEY-----"#;

#[derive(Clone, Debug)]
pub struct AppState {
    pub storage: std::sync::Arc<InMemoryStorage>,
    pub email_sender: std::sync::Arc<StdoutEmail>,
    pub oauth_config: OAuthConfig,
    pub rate_limiter: std::sync::Arc<InMemoryRateLimiter>,
    pub private_key_pem: &'static str,
    pub public_key_pem: &'static str,
}

impl Default for AppState {
    fn default() -> Self {
        let mock_port = std::env::var("MOCK_AUTH_PORT").unwrap_or_else(|_| "8081".to_string());
        let app_port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
        Self {
            storage: std::sync::Arc::new(InMemoryStorage::new()),
            email_sender: std::sync::Arc::new(StdoutEmail::new()),
            oauth_config: OAuthConfig {
                client_id: "client-id-123".to_string(),
                client_secret: "client-secret-123".to_string(),
                auth_url: format!("http://127.0.0.1:{}/authorize", mock_port),
                token_url: format!("http://127.0.0.1:{}/token", mock_port),
                userinfo_url: Some(format!("http://127.0.0.1:{}/userinfo", mock_port)),
                redirect_uri: format!("http://127.0.0.1:{}/callback", app_port),
            },
            rate_limiter: std::sync::Arc::new(InMemoryRateLimiter::default()),
            private_key_pem: PRIV_KEY_PEM,
            public_key_pem: PUB_KEY_PEM,
        }
    }
}

thread_local! {
    static STATE: AppState = AppState::default();
}

struct DemoFailingStorage;

impl AuthStorage for DemoFailingStorage {
    fn store_session(
        &self,
        _session_id: &str,
        _user_id: &str,
        _roles: &[String],
        _expires_at: u64,
    ) -> Result<(), wasi_auth_traits::AuthError> {
        Ok(())
    }

    fn get_session(
        &self,
        _session_id: &str,
    ) -> Result<Option<wasi_auth_traits::Session>, wasi_auth_traits::AuthError> {
        Err(wasi_auth_traits::AuthError::StorageError(
            "Simulated DB error".to_string(),
        ))
    }

    fn delete_session(&self, _session_id: &str) -> Result<(), wasi_auth_traits::AuthError> {
        Ok(())
    }

    fn store_otp(
        &self,
        _email: &str,
        _otp: &str,
        _expires_at: u64,
    ) -> Result<(), wasi_auth_traits::AuthError> {
        Ok(())
    }

    fn verify_otp(&self, _email: &str, _otp: &str) -> Result<bool, wasi_auth_traits::AuthError> {
        Ok(true)
    }
}

#[server(name = GetProtectedData, prefix = "/api", endpoint = "GetProtectedData")]
pub async fn get_protected_data() -> Result<String, ServerFnError> {
    let session_res = leptos_wasi_auth::expect_session();
    match session_res {
        Ok(session) => Ok(format!("Welcome, {}!", session.user_id)),
        Err(err) => {
            if let Some(resp_opts) = use_context::<leptos_wasi::response::ResponseOptions>() {
                let err_str = err.to_string();
                if err_str.contains("Key Missing") {
                    resp_opts.set_status(http::StatusCode::INTERNAL_SERVER_ERROR);
                    resp_opts.insert_header(
                        http::HeaderName::from_static("x-auth-error"),
                        http::HeaderValue::from_static("KeyMissing"),
                    );
                } else if err_str.contains("Internal Server Error") {
                    resp_opts.set_status(http::StatusCode::INTERNAL_SERVER_ERROR);
                    resp_opts.insert_header(
                        http::HeaderName::from_static("x-auth-error"),
                        http::HeaderValue::from_static("StorageError"),
                    );
                } else {
                    resp_opts.set_status(http::StatusCode::UNAUTHORIZED);
                    resp_opts.insert_header(
                        http::HeaderName::from_static("x-auth-error"),
                        http::HeaderValue::from_static("Other"),
                    );
                }
            }
            Err(err)
        }
    }
}

#[server(GetSession, "/api")]
pub async fn get_session() -> Result<Option<UserSession>, ServerFnError> {
    Ok(use_context::<Option<UserSession>>().flatten())
}

#[server(RequestOtp, "/api")]
pub async fn request_otp(email: String) -> Result<String, ServerFnError> {
    info!("ServerFn request_otp starting for email: {}", email);
    let state = STATE.with(|s| s.clone());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Check rate limit
    let limit_ok = state
        .rate_limiter
        .check_rate_limit(&email, "send_otp")
        .map_err(|e| ServerFnError::new(format!("Rate limiter check error: {:?}", e)))?;
    if !limit_ok {
        return Err(ServerFnError::new(
            "Rate limit exceeded. Too many requests.",
        ));
    }

    // Record rate limit action
    state
        .rate_limiter
        .record_action(&email, "send_otp")
        .map_err(|e| ServerFnError::new(format!("Rate limiter error: {:?}", e)))?;

    let otp = wasi_auth_core::otp::send_and_store_otp(
        &email,
        &*state.storage,
        &*state.email_sender,
        300,
        now,
        Some(&*state.rate_limiter),
    )
    .map_err(|e| ServerFnError::new(format!("Failed to send OTP: {:?}", e)))?;

    Ok(format!(
        "OTP sent successfully! (Dev Mode: code is {})",
        otp
    ))
}

#[server(VerifyOtp, "/api")]
pub async fn verify_otp(email: String, otp: String) -> Result<bool, ServerFnError> {
    info!("ServerFn verify_otp starting for email: {}", email);
    let state = STATE.with(|s| s.clone());

    // Check rate limit
    let limit_ok = state
        .rate_limiter
        .check_rate_limit(&email, "verify_otp")
        .map_err(|e| ServerFnError::new(format!("Rate limiter check error: {:?}", e)))?;
    if !limit_ok {
        return Err(ServerFnError::new(
            "Rate limit exceeded. Too many attempts.",
        ));
    }

    // Record rate limit action
    state
        .rate_limiter
        .record_action(&email, "verify_otp")
        .map_err(|e| ServerFnError::new(format!("Rate limiter error: {:?}", e)))?;

    let ok =
        wasi_auth_core::otp::verify_otp(&email, &otp, &*state.storage, Some(&*state.rate_limiter))
            .map_err(|e| ServerFnError::new(format!("Storage error: {:?}", e)))?;

    if ok {
        // Create cookie or JWT session
        let claims = wasi_auth_core::jwt::Claims {
            sub: email.clone(),
            iss: "leptos-auth-demo".to_string(),
            aud: "client-id-123".to_string(),
            exp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            iat: 0,
            nbf: None,
            jti: None,
            roles: vec!["user".to_string()],
            name: Some(email.split('@').next().unwrap_or("User").to_string()),
            email: Some(email),
        };

        let token = wasi_auth_core::jwt::generate_jwt(&claims, state.private_key_pem, None)
            .map_err(|e| ServerFnError::new(format!("JWT generation failed: {:?}", e)))?;

        // Store session in DB
        state
            .storage
            .store_session(&token, &claims.sub, &claims.roles, claims.exp)
            .map_err(|e| ServerFnError::new(format!("Session storage error: {:?}", e)))?;

        // Build Cookie and set it in ResponseOptions
        if let Some(resp_opts) = use_context::<leptos_wasi::response::ResponseOptions>() {
            let cookie_opts = leptos_wasi_auth::CookieOptions {
                name: "__Host-jwt".to_string(),
                http_only: true,
                secure: true,
                same_site: leptos_wasi_auth::SameSite::Lax,
                path: "/".to_string(),
                max_age_secs: Some(3600),
            };
            let cookie_header = leptos_wasi_auth::build_set_cookie_header(&token, &cookie_opts);
            resp_opts.insert_header(
                http::header::SET_COOKIE,
                http::HeaderValue::from_str(&cookie_header).unwrap(),
            );
        }

        Ok(true)
    } else {
        Err(ServerFnError::new("Invalid or expired OTP code"))
    }
}

#[allow(unused_variables)]
#[server(ExchangeOauth, "/api")]
pub async fn exchange_oauth(
    code: String,
    state: String,
    code_verifier: Option<String>,
) -> Result<bool, ServerFnError> {
    let state_app = STATE.with(|s| s.clone());

    // Mock exchange flow simulation
    let email = format!("oauth-{}@example.com", state.to_lowercase());

    let claims = wasi_auth_core::jwt::Claims {
        sub: email.clone(),
        iss: "leptos-auth-demo".to_string(),
        aud: "client-id-123".to_string(),
        exp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600,
        iat: 0,
        nbf: None,
        jti: None,
        roles: vec!["user".to_string()],
        name: Some(format!("{} User", state)),
        email: Some(email),
    };

    let token = wasi_auth_core::jwt::generate_jwt(&claims, state_app.private_key_pem, None)
        .map_err(|e| ServerFnError::new(format!("JWT generation failed: {:?}", e)))?;

    // Store session in DB
    state_app
        .storage
        .store_session(&token, &claims.sub, &claims.roles, claims.exp)
        .map_err(|e| ServerFnError::new(format!("Session storage error: {:?}", e)))?;

    // Build Cookie and set it in ResponseOptions
    if let Some(resp_opts) = use_context::<leptos_wasi::response::ResponseOptions>() {
        let cookie_opts = leptos_wasi_auth::CookieOptions {
            name: "__Host-jwt".to_string(),
            http_only: true,
            secure: true,
            same_site: leptos_wasi_auth::SameSite::Lax,
            path: "/".to_string(),
            max_age_secs: Some(3600),
        };
        let cookie_header = leptos_wasi_auth::build_set_cookie_header(&token, &cookie_opts);
        resp_opts.insert_header(
            http::header::SET_COOKIE,
            http::HeaderValue::from_str(&cookie_header).unwrap(),
        );
    }

    Ok(true)
}

#[server(Logout, "/api")]
pub async fn logout() -> Result<(), ServerFnError> {
    info!("ServerFn logout called. Invalidation request processed.");
    let state = STATE.with(|s| s.clone());

    if let Some(parts) = use_context::<http::request::Parts>() {
        let token = if let Some(cookie_val) = parts.headers.get(http::header::COOKIE) {
            if let Ok(cookie_str) = cookie_val.to_str() {
                leptos_wasi_auth::extract_cookie(cookie_str, "__Host-jwt")
            } else {
                None
            }
        } else {
            None
        };
        if let Some(t) = token {
            let _ = state.storage.delete_session(&t);
        }
    }

    // Set clear cookie header
    if let Some(resp_opts) = use_context::<leptos_wasi::response::ResponseOptions>() {
        let cookie_opts = leptos_wasi_auth::CookieOptions {
            name: "__Host-jwt".to_string(),
            http_only: true,
            secure: true,
            same_site: leptos_wasi_auth::SameSite::Lax,
            path: "/".to_string(),
            max_age_secs: None,
        };
        let clear_cookie = leptos_wasi_auth::build_clear_cookie_header(&cookie_opts);
        resp_opts.insert_header(
            http::header::SET_COOKIE,
            http::HeaderValue::from_str(&clear_cookie).unwrap(),
        );
    }

    Ok(())
}

#[server(RequestMagicLink, "/api")]
pub async fn request_magic_link(email: String) -> Result<String, ServerFnError> {
    info!("ServerFn request_magic_link starting for email: {}", email);
    let state = STATE.with(|s| s.clone());

    let base_url = "http://127.0.0.1:8080/magic-callback";
    let link = leptos_wasi_auth::generate_magic_link(
        &email,
        base_url,
        state.private_key_pem,
        None,
        300,
        "client-id-123",
        "leptos-auth-demo",
    )
    .map_err(|e| ServerFnError::new(format!("Failed to generate magic link: {:?}", e)))?;

    state
        .email_sender
        .send_email(
            &email,
            "Your Magic Login Link",
            &format!("Click this link to log in: {}", link),
        )
        .map_err(|e| ServerFnError::new(format!("Email send error: {:?}", e)))?;

    Ok(format!("Magic link sent! (Dev Link: {})", link))
}

#[server(VerifyMagicLinkToken, "/api")]
pub async fn verify_magic_link_token(token: String) -> Result<bool, ServerFnError> {
    let state = STATE.with(|s| s.clone());
    let email = leptos_wasi_auth::verify_magic_link(
        &token,
        state.public_key_pem,
        "client-id-123",
        "leptos-auth-demo",
        &*state.storage,
    )
    .map_err(|e| ServerFnError::new(format!("Verification failed: {:?}", e)))?;

    let claims = wasi_auth_core::jwt::Claims {
        sub: email.clone(),
        iss: "leptos-auth-demo".to_string(),
        aud: "client-id-123".to_string(),
        exp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600,
        iat: 0,
        nbf: None,
        jti: None,
        roles: vec!["user".to_string()],
        name: Some(email.split('@').next().unwrap_or("User").to_string()),
        email: Some(email),
    };

    let new_token = wasi_auth_core::jwt::generate_jwt(&claims, state.private_key_pem, None)
        .map_err(|e| ServerFnError::new(format!("JWT generation failed: {:?}", e)))?;

    state
        .storage
        .store_session(&new_token, &claims.sub, &claims.roles, claims.exp)
        .map_err(|e| ServerFnError::new(format!("Session storage error: {:?}", e)))?;

    if let Some(resp_opts) = use_context::<leptos_wasi::response::ResponseOptions>() {
        let cookie_opts = leptos_wasi_auth::CookieOptions {
            name: "__Host-jwt".to_string(),
            http_only: true,
            secure: true,
            same_site: leptos_wasi_auth::SameSite::Lax,
            path: "/".to_string(),
            max_age_secs: Some(3600),
        };
        let cookie_header = leptos_wasi_auth::build_set_cookie_header(&new_token, &cookie_opts);
        resp_opts.insert_header(
            http::header::SET_COOKIE,
            http::HeaderValue::from_str(&cookie_header).unwrap(),
        );
    }

    Ok(true)
}

#[server(SetupTotp, "/api")]
pub async fn setup_totp(email: String) -> Result<String, ServerFnError> {
    let state = STATE.with(|s| s.clone());
    let (_secret, uri) = leptos_wasi_auth::register_totp(&email, "LeptosAuthDemo", &*state.storage)
        .map_err(|e| ServerFnError::new(format!("TOTP setup failed: {:?}", e)))?;
    Ok(uri)
}

#[server(VerifyTotpLogin, "/api")]
pub async fn verify_totp_login_action(email: String, code: String) -> Result<bool, ServerFnError> {
    info!("ServerFn verify_totp_login starting for email: {}", email);
    let state = STATE.with(|s| s.clone());
    let ok = leptos_wasi_auth::verify_totp_login(&email, &code, &*state.storage)
        .map_err(|e| ServerFnError::new(format!("TOTP verification failed: {:?}", e)))?;

    if !ok {
        return Err(ServerFnError::new("Invalid TOTP code"));
    }

    let claims = wasi_auth_core::jwt::Claims {
        sub: email.clone(),
        iss: "leptos-auth-demo".to_string(),
        aud: "client-id-123".to_string(),
        exp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600,
        iat: 0,
        nbf: None,
        jti: None,
        roles: vec!["user".to_string()],
        name: Some(email.split('@').next().unwrap_or("User").to_string()),
        email: Some(email),
    };

    let token = wasi_auth_core::jwt::generate_jwt(&claims, state.private_key_pem, None)
        .map_err(|e| ServerFnError::new(format!("JWT generation failed: {:?}", e)))?;

    state
        .storage
        .store_session(&token, &claims.sub, &claims.roles, claims.exp)
        .map_err(|e| ServerFnError::new(format!("Session storage error: {:?}", e)))?;

    if let Some(resp_opts) = use_context::<leptos_wasi::response::ResponseOptions>() {
        let cookie_opts = leptos_wasi_auth::CookieOptions {
            name: "__Host-jwt".to_string(),
            http_only: true,
            secure: true,
            same_site: leptos_wasi_auth::SameSite::Lax,
            path: "/".to_string(),
            max_age_secs: Some(3600),
        };
        let cookie_header = leptos_wasi_auth::build_set_cookie_header(&token, &cookie_opts);
        resp_opts.insert_header(
            http::header::SET_COOKIE,
            http::HeaderValue::from_str(&cookie_header).unwrap(),
        );
    }

    Ok(true)
}

#[component]
pub fn App() -> impl IntoView {
    view! {
        <Router>
            <main>
                <Routes fallback=|| view! { <div>"404 Not Found"</div> }>
                    <Route path=path!("") view=Home/>
                    <Route path=path!("login") view=Login/>
                    <Route path=path!("dashboard") view=Dashboard/>
                    <Route path=path!("callback") view=OAuthCallback/>
                    <Route path=path!("magic-callback") view=MagicCallback/>
                    <Route path=path!("totp-setup") view=TotpSetup/>
                </Routes>
            </main>
        </Router>
    }
}

#[component]
pub fn Home() -> impl IntoView {
    view! {
        <div style="background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 40px; width: 100%; max-width: 480px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.3); text-align: center;">
            <span style="display: inline-block; padding: 4px 8px; font-size: 0.75rem; font-weight: 700; border-radius: 9999px; text-transform: uppercase; background: rgba(168, 85, 247, 0.2); color: #c084fc; margin-bottom: 16px;">"WASI Microservices - Antigravity Portal"</span>
            <h1 style="font-size: 2.25rem; margin-bottom: 12px; font-weight: 700; letter-spacing: -0.025em; background: linear-gradient(to right, #a5b4fc, #e879f9); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">"Hello from Leptos Auth Demo!"</h1>
            <p style="margin-bottom: 24px; color: #94a3b8; line-height: 1.6; font-size: 0.95rem;">
                "A secure, high-performance, WASI-native reference portal demonstrating cookie session management, PKCE authentication, and thread-safe rate limiting."
            </p>
            <div style="display: flex; flex-direction: column; gap: 12px;">
                <a href="/login" style="display: inline-flex; align-items: center; justify-content: center; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; border: none; outline: none; width: 100%; color: white; background: linear-gradient(135deg, #6366f1, #a855f7); box-shadow: 0 4px 14px 0 rgba(99, 102, 241, 0.3); text-decoration: none;">"Go to Login"</a>
                <a href="/dashboard" style="display: inline-flex; align-items: center; justify-content: center; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; border: none; outline: none; width: 100%; color: white; background: rgba(255, 255, 255, 0.08); border: 1px solid rgba(255, 255, 255, 0.1); text-decoration: none;">"Access Dashboard"</a>
            </div>
        </div>
    }
}

#[component]
pub fn MagicCallback() -> impl IntoView {
    let query = leptos_router::hooks::use_query_map();
    let token = move || query.with(|q| q.get("token").unwrap_or_default());

    let verify_action = Action::new(|t: &String| {
        let t = t.clone();
        async move { verify_magic_link_token(t).await }
    });

    Effect::new(move |_| {
        let token_val = token();
        if !token_val.is_empty() {
            verify_action.dispatch(token_val);
        }
    });

    let navigate = leptos_router::hooks::use_navigate();

    Effect::new(move |_| {
        if let Some(Ok(true)) = verify_action.value().get() {
            navigate("/dashboard", Default::default());
        }
    });

    view! {
        <div style="background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 40px; width: 100%; max-width: 480px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.3); text-align: center;">
            <h2 style="font-size: 1.75rem; margin-bottom: 16px; font-weight: 700; letter-spacing: -0.025em; color: #ffffff;">"Verifying Magic Link..."</h2>
            <p style="margin-bottom: 20px; color: #94a3b8; line-height: 1.6; font-size: 0.95rem;">"Logging you in securely."</p>
            {move || {
                match verify_action.value().get() {
                    Some(Err(e)) => view! {
                        <div style="padding: 12px 16px; border-radius: 8px; font-size: 0.9rem; margin-bottom: 20px; border: 1px solid rgba(239, 68, 68, 0.2); text-align: left; background: rgba(239, 68, 68, 0.1); color: #f87171;">
                            "Error: " {e.to_string()}
                        </div>
                    }.into_any(),
                    _ => view! {
                        <div style="margin: 20px auto; width: 40px; height: 40px; border: 4px solid rgba(255,255,255,0.1); border-top-color: #a855f7; border-radius: 50%; animation: spin 1s linear infinite;"></div>
                    }.into_any()
                }
            }}
        </div>
    }
}

#[component]
pub fn TotpSetup() -> impl IntoView {
    let setup_action = Action::new(|email: &String| {
        let email = email.clone();
        async move { setup_totp(email).await }
    });

    let verify_action = Action::new(|verification: &TotpSetupVerification| {
        let email = verification.email.clone();
        let code = verification.code.clone();
        async move { verify_totp_login_action(email, code).await }
    });

    let on_setup = Callback::new(move |email: String| {
        setup_action.dispatch(email);
    });

    let on_verify = Callback::new(move |verification: TotpSetupVerification| {
        verify_action.dispatch(verification);
    });

    let uri = Signal::derive(move || setup_action.value().get().and_then(|res| res.ok()));

    let setup_pending = Signal::derive(move || setup_action.pending().get());

    let setup_result = Signal::derive(move || {
        setup_action.value().get().map(|res| {
            res.map(|uri| {
                uri.split("secret=")
                    .nth(1)
                    .and_then(|s| s.split('&').next())
                    .unwrap_or("")
                    .to_string()
            })
            .map_err(|e| e.to_string())
        })
    });

    let verify_pending = Signal::derive(move || verify_action.pending().get());

    let verify_result = Signal::derive(move || {
        verify_action
            .value()
            .get()
            .map(|res| res.map_err(|e| e.to_string()))
    });

    let navigate = leptos_router::hooks::use_navigate();

    Effect::new(move |_| {
        if let Some(Ok(true)) = verify_action.value().get() {
            navigate("/dashboard", Default::default());
        }
    });

    view! {
        <TotpSetupForm
            uri=uri
            setup_pending=setup_pending
            setup_result=setup_result
            verify_pending=verify_pending
            verify_result=verify_result
            on_setup=on_setup
            on_verify=on_verify
        />
    }
}

#[component]
pub fn Login() -> impl IntoView {
    let request_otp_action = Action::new(|email: &String| {
        let email = email.clone();
        async move { request_otp(email).await }
    });

    let verify_otp_action = Action::new(|(email, otp): &(String, String)| {
        let email = email.clone();
        let otp = otp.clone();
        async move { verify_otp(email, otp).await }
    });

    let request_magic_link_action = Action::new(|email: &String| {
        let email = email.clone();
        async move { request_magic_link(email).await }
    });

    let verify_totp_action = Action::new(|(email, code): &(String, String)| {
        let email = email.clone();
        let code = code.clone();
        async move { verify_totp_login_action(email, code).await }
    });

    let request_otp_pending = Signal::derive(move || request_otp_action.pending().get());
    let request_otp_result = Signal::derive(move || {
        request_otp_action
            .value()
            .get()
            .map(|res| res.map_err(|e| e.to_string()))
    });

    let verify_otp_pending = Signal::derive(move || verify_otp_action.pending().get());
    let verify_otp_result = Signal::derive(move || {
        verify_otp_action
            .value()
            .get()
            .map(|res| res.map_err(|e| e.to_string()))
    });

    let request_magic_link_pending =
        Signal::derive(move || request_magic_link_action.pending().get());
    let request_magic_link_result = Signal::derive(move || {
        request_magic_link_action
            .value()
            .get()
            .map(|res| res.map_err(|e| e.to_string()))
    });

    let verify_totp_pending = Signal::derive(move || verify_totp_action.pending().get());
    let verify_totp_result = Signal::derive(move || {
        verify_totp_action
            .value()
            .get()
            .map(|res| res.map_err(|e| e.to_string()))
    });

    let passkey_login_pending = Signal::derive(move || false);

    let on_submit_otp = Callback::new(move |verification: OtpVerification| {
        verify_otp_action.dispatch((verification.email, verification.code));
    });

    let on_request_otp = Callback::new(move |email: String| {
        request_otp_action.dispatch(email);
    });

    let on_request_magic_link = Callback::new(move |email: String| {
        request_magic_link_action.dispatch(email);
    });

    let on_verify_totp = Callback::new(move |verification: TotpVerification| {
        verify_totp_action.dispatch((verification.email, verification.code));
    });

    let navigate = leptos_router::hooks::use_navigate();

    let navigate_otp = navigate.clone();
    Effect::new(move |_| {
        if let Some(Ok(true)) = verify_otp_action.value().get() {
            navigate_otp("/dashboard", Default::default());
        }
    });

    let navigate_totp = navigate;
    Effect::new(move |_| {
        if let Some(Ok(true)) = verify_totp_action.value().get() {
            navigate_totp("/dashboard", Default::default());
        }
    });

    view! {
        <div style="background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 40px; width: 100%; max-width: 480px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.3);">
            <LoginForm
                style="background: transparent; border: none; box-shadow: none; padding: 0; max-width: 100%; width: 100%;"
                show_oauth=false
                show_passkey=false
                request_otp_pending=request_otp_pending
                request_otp_result=request_otp_result
                verify_otp_pending=verify_otp_pending
                verify_otp_result=verify_otp_result
                request_magic_link_pending=request_magic_link_pending
                request_magic_link_result=request_magic_link_result
                verify_totp_pending=verify_totp_pending
                verify_totp_result=verify_totp_result
                passkey_login_pending=passkey_login_pending
                on_submit_otp=on_submit_otp
                on_request_otp=on_request_otp
                on_request_magic_link=on_request_magic_link
                on_verify_totp=on_verify_totp
            />

            // The 4 functional mock OAuth links underneath
            <div style="display: flex; align-items: center; text-align: center; margin: 24px 0; color: #475569; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em;"><div style="flex: 1; border-bottom: 1px solid rgba(255, 255, 255, 0.08); margin-right: 1em;"></div>"or continue with"<div style="flex: 1; border-bottom: 1px solid rgba(255, 255, 255, 0.08); margin-left: 1em;"></div></div>

            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px;">
                <a href="/callback?code=mock_google_code&state=Google" style="display: flex; align-items: center; justify-content: center; gap: 8px; padding: 12px; background: rgba(255, 255, 255, 0.04); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; color: #e2e8f0; text-decoration: none; font-weight: 500; font-size: 0.9rem;">"Google"</a>
                <a href="/callback?code=mock_github_code&state=GitHub" style="display: flex; align-items: center; justify-content: center; gap: 8px; padding: 12px; background: rgba(255, 255, 255, 0.04); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; color: #e2e8f0; text-decoration: none; font-weight: 500; font-size: 0.9rem;">"GitHub"</a>
                <a href="/callback?code=mock_discord_code&state=Discord" style="display: flex; align-items: center; justify-content: center; gap: 8px; padding: 12px; background: rgba(255, 255, 255, 0.04); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; color: #e2e8f0; text-decoration: none; font-weight: 500; font-size: 0.9rem;">"Discord"</a>
                <a href="/callback?code=mock_keycloak_code&state=Keycloak" style="display: flex; align-items: center; justify-content: center; gap: 8px; padding: 12px; background: rgba(255, 255, 255, 0.04); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; color: #e2e8f0; text-decoration: none; font-weight: 500; font-size: 0.9rem;">"Keycloak"</a>
            </div>

            <div style="margin-top: 24px; text-align: center;">
                <a href="/" style="color: #64748b; font-size: 0.85rem; text-decoration: none;">"← Back to Portal"</a>
            </div>
        </div>
    }
}

#[component]
pub fn Dashboard() -> impl IntoView {
    let session = use_context::<Option<UserSession>>().flatten();

    let logout_action = Action::new(|_: &()| async move { logout().await });

    let navigate = leptos_router::hooks::use_navigate();

    Effect::new(move |_| {
        if let Some(Ok(())) = logout_action.value().get() {
            navigate("/login", Default::default());
        }
    });

    let on_logout = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        logout_action.dispatch(());
    };

    // Mock signals/callbacks for SessionList
    let (sessions, set_sessions) = signal(vec![
        wasi_auth_traits::Session {
            session_id: "session_current_12345".to_string(),
            user_id: session
                .as_ref()
                .map(|s| s.user_id.clone())
                .unwrap_or_else(|| "mock_user".to_string()),
            roles: vec!["user".to_string()],
            expires_at: 1800000000,
        },
        wasi_auth_traits::Session {
            session_id: "session_other_67890".to_string(),
            user_id: session
                .as_ref()
                .map(|s| s.user_id.clone())
                .unwrap_or_else(|| "mock_user".to_string()),
            roles: vec!["user".to_string()],
            expires_at: 1800000000,
        },
    ]);
    let (current_session_id, _) = signal(Some("session_current_12345".to_string()));
    let (revoke_pending, set_revoke_pending) = signal(false);
    let (revoke_result, set_revoke_result) = signal(None::<Result<(), String>>);

    let on_revoke = Callback::new(move |id: String| {
        set_revoke_pending.set(true);
        leptos::task::spawn_local(async move {
            set_sessions.update(|list| {
                list.retain(|s| s.session_id != id);
            });
            set_revoke_pending.set(false);
            set_revoke_result.set(Some(Ok(())));
        });
    });

    let on_revoke_all = Callback::new(move |_: ()| {
        set_revoke_pending.set(true);
        leptos::task::spawn_local(async move {
            set_sessions.update(|list| {
                list.retain(|s| s.session_id == "session_current_12345");
            });
            set_revoke_pending.set(false);
            set_revoke_result.set(Some(Ok(())));
        });
    });

    // Mock signals/callbacks for MfaStatus
    let (totp_enabled, set_totp_enabled) = signal(true);
    let (disable_pending, set_disable_pending) = signal(false);
    let (disable_result, set_disable_result) = signal(None::<Result<(), String>>);

    let on_disable = Callback::new(move |_: ()| {
        set_disable_pending.set(true);
        leptos::task::spawn_local(async move {
            set_totp_enabled.set(false);
            set_disable_pending.set(false);
            set_disable_result.set(Some(Ok(())));
        });
    });

    // Mock signals/callbacks for PasskeyList
    #[cfg(feature = "passkey")]
    let (passkeys, set_passkeys) = signal(vec![
        wasi_auth_core::passkey::StoredPasskey {
            user_id: session
                .as_ref()
                .map(|s| s.user_id.clone())
                .unwrap_or_else(|| "mock_user".to_string()),
            cred_id: "cred_1".to_string(),
            public_key: "dummy_pk_1".to_string(),
            name: "Personal MacBook Pro".to_string(),
            created_at: 1700000000000,
            last_used_at: 1700005000000,
            counter: 0,
        },
        wasi_auth_core::passkey::StoredPasskey {
            user_id: session
                .as_ref()
                .map(|s| s.user_id.clone())
                .unwrap_or_else(|| "mock_user".to_string()),
            cred_id: "cred_2".to_string(),
            public_key: "dummy_pk_2".to_string(),
            name: "Work iPad".to_string(),
            created_at: 1700100000000,
            last_used_at: 0,
            counter: 0,
        },
    ]);
    #[cfg(feature = "passkey")]
    let (passkey_pending, set_passkey_pending) = signal(false);
    #[cfg(feature = "passkey")]
    let (rename_result, set_rename_result) = signal(None::<Result<(), String>>);
    #[cfg(feature = "passkey")]
    let (delete_result, set_delete_result) = signal(None::<Result<(), String>>);

    #[cfg(feature = "passkey")]
    let on_rename = Callback::new(move |(cred_id, new_name): (String, String)| {
        set_passkey_pending.set(true);
        leptos::task::spawn_local(async move {
            set_passkeys.update(|list| {
                if let Some(pk) = list.iter_mut().find(|p| p.cred_id == cred_id) {
                    pk.name = new_name;
                }
            });
            set_passkey_pending.set(false);
            set_rename_result.set(Some(Ok(())));
        });
    });

    #[cfg(feature = "passkey")]
    let on_delete = Callback::new(move |cred_id: String| {
        set_passkey_pending.set(true);
        leptos::task::spawn_local(async move {
            set_passkeys.update(|list| {
                list.retain(|p| p.cred_id != cred_id);
            });
            set_passkey_pending.set(false);
            set_delete_result.set(Some(Ok(())));
        });
    });

    view! {
        <div style="background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 20px; padding: 48px; width: 100%; max-width: 800px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.3);">
            <h2 style="font-size: 1.75rem; margin-bottom: 16px; font-weight: 700; letter-spacing: -0.025em; color: #ffffff;">"User Console"</h2>
            {match session {
                Some(user) => view! {
                    <div>
                        <div style="padding: 12px 16px; border-radius: 8px; font-size: 0.9rem; margin-bottom: 24px; border: 1px solid rgba(16, 185, 129, 0.2); text-align: left; background: rgba(16, 185, 129, 0.1); color: #34d399;">
                            "Successfully authenticated via WASI Direct Flow."
                        </div>
                        <div style="background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(255,255,255,0.06); border-radius: 12px; padding: 24px; margin-bottom: 30px;">
                            <div style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 12px; margin-bottom: 12px;">
                                <span style="color: #94a3b8; font-weight: 500;">"Subject / ID"</span>
                                <span style="font-family: monospace; color: white;">{user.user_id}</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 12px; margin-bottom: 12px;">
                                <span style="color: #94a3b8; font-weight: 500;">"Display Name"</span>
                                <span style="color: white;">{user.name.unwrap_or_else(|| "N/A".to_string())}</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 12px; margin-bottom: 12px;">
                                <span style="color: #94a3b8; font-weight: 500;">"Email Address"</span>
                                <span style="color: white;">{user.email.unwrap_or_else(|| "N/A".to_string())}</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; padding-bottom: 4px;">
                                <span style="color: #94a3b8; font-weight: 500;">"Granted Roles"</span>
                                <span style="display: inline-block; padding: 4px 8px; font-size: 0.75rem; font-weight: 700; border-radius: 9999px; text-transform: uppercase; background: rgba(168, 85, 247, 0.2); color: #c084fc;">{user.roles.join(", ")}</span>
                            </div>
                        </div>
                        <div style="display: flex; gap: 12px; margin-bottom: 30px;">
                            <form on:submit=on_logout style="margin: 0;">
                                <button type="submit" style="display: inline-flex; align-items: center; justify-content: center; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; border: none; outline: none; color: white; background: linear-gradient(135deg, #ef4444, #f43f5e);">
                                    {move || if logout_action.pending().get() { "Signing Out..." } else { "Sign Out" }}
                                </button>
                            </form>
                            <a href="/totp-setup" style="display: inline-flex; align-items: center; justify-content: center; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; border: none; outline: none; color: white; background: linear-gradient(135deg, #10b981, #14b8a6); text-decoration: none; box-shadow: 0 4px 14px 0 rgba(16, 185, 129, 0.3);">"Set up TOTP (MFA)"</a>
                        </div>
                        <div style="display: flex; flex-direction: column; gap: 24px;">
                            <SessionList
                                sessions=sessions
                                current_session_id=current_session_id
                                on_revoke=on_revoke
                                on_revoke_all=on_revoke_all
                                revoke_pending=revoke_pending
                                revoke_result=revoke_result
                            />

                            <MfaStatus
                                totp_enabled=totp_enabled
                                on_disable=on_disable
                                disable_pending=disable_pending
                                disable_result=disable_result
                            />

                            {move || {
                                #[cfg(feature = "passkey")]
                                {
                                    Some(view! {
                                        <PasskeyList
                                            passkeys=passkeys
                                            on_delete=on_delete
                                            on_rename=on_rename
                                            pending=passkey_pending
                                            rename_result=rename_result
                                            delete_result=delete_result
                                        />
                                    })
                                }
                                #[cfg(not(feature = "passkey"))]
                                {
                                    None::<leptos::prelude::AnyView>
                                }
                            }}
                        </div>
                    </div>
                }.into_any(),
                None => view! {
                    <div>
                        <div style="padding: 12px 16px; border-radius: 8px; font-size: 0.9rem; margin-bottom: 24px; border: 1px solid rgba(239, 68, 68, 0.2); text-align: left; background: rgba(239, 68, 68, 0.1); color: #f87171;">
                            "Access Denied: You are not logged in or session has expired."
                        </div>
                        <a href="/login" style="display: inline-flex; align-items: center; justify-content: center; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; border: none; outline: none; width: 100%; color: white; background: linear-gradient(135deg, #6366f1, #a855f7); box-shadow: 0 4px 14px 0 rgba(99, 102, 241, 0.3); max-width: 200px; text-decoration: none;">"Go to Login"</a>
                    </div>
                }.into_any()
            }}
        </div>
    }
}

#[component]
pub fn OAuthCallback() -> impl IntoView {
    let query = leptos_router::hooks::use_query_map();
    let code = move || query.with(|q| q.get("code").unwrap_or_default());
    let state = move || query.with(|q| q.get("state").unwrap_or_default());

    let exchange_action = Action::new(|(c, s): &(String, String)| {
        let c = c.clone();
        let s = s.clone();
        async move { exchange_oauth(c, s, None).await }
    });

    Effect::new(move |_| {
        let code_val = code();
        let state_val = state();
        if !code_val.is_empty() {
            exchange_action.dispatch((code_val, state_val));
        }
    });

    let navigate = leptos_router::hooks::use_navigate();

    Effect::new(move |_| {
        if let Some(Ok(true)) = exchange_action.value().get() {
            navigate("/dashboard", Default::default());
        }
    });

    view! {
        <div style="background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 40px; width: 100%; max-width: 480px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.3); text-align: center;">
            <h2 style="font-size: 1.75rem; margin-bottom: 16px; font-weight: 700; letter-spacing: -0.025em; color: #ffffff;">"Authenticating..."</h2>
            <p style="margin-bottom: 20px; color: #94a3b8; line-height: 1.6; font-size: 0.95rem;">"Processing social sign-in callback."</p>
            {move || {
                match exchange_action.value().get() {
                    Some(Err(e)) => view! {
                        <div style="padding: 12px 16px; border-radius: 8px; font-size: 0.9rem; margin-bottom: 20px; border: 1px solid rgba(239, 68, 68, 0.2); text-align: left; background: rgba(239, 68, 68, 0.1); color: #f87171;">
                            "Error exchanging code: " {e.to_string()}
                        </div>
                    }.into_any(),
                    _ => view! {
                        <div style="margin: 20px auto; width: 40px; height: 40px; border: 4px solid rgba(255,255,255,0.1); border-top-color: #6366f1; border-radius: 50%; animation: spin 1s linear infinite;"></div>
                    }.into_any()
                }
            }}
        </div>
    }
}

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html style="margin: 0; padding: 0; box-sizing: border-box;">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <AutoReload options=options.clone() />
                <HydrationScripts options=options />
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&amp;display=swap" rel="stylesheet" />
            </head>
            <body style="background-color: #080a10; background-image: radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.1) 0px, transparent 50%), radial-gradient(at 100% 100%, rgba(168, 85, 247, 0.1) 0px, transparent 50%); color: #e2e8f0; font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; overflow-x: hidden; margin: 0; padding: 0;">
                <App/>
            </body>
        </html>
    }
}

struct DemoApp;

impl wasi::exports::http::incoming_handler::Guest for DemoApp {
    fn handle(
        request: wasi::http::types::IncomingRequest,
        response_outparam: wasi::http::types::ResponseOutparam,
    ) {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .init();
        });
        use any_spawner::Executor;
        use leptos_wasi::executor::Executor as WasiExecutor;

        let executor = WasiExecutor::new(leptos_wasi::executor::Mode::Stalled);
        Executor::init_local_custom_executor(executor.clone()).unwrap();

        executor.run_until(async {
            let state = STATE.with(|s| s.clone());
            let conf = leptos::config::get_configuration(None).unwrap();
            let leptos_options = conf.leptos_options;

            Handler::build(request, response_outparam)
                .unwrap()
                .with_server_fn_axum::<GetSession>()
                .with_server_fn_axum::<RequestOtp>()
                .with_server_fn_axum::<VerifyOtp>()
                .with_server_fn_axum::<ExchangeOauth>()
                .with_server_fn_axum::<Logout>()
                .with_server_fn_axum::<RequestMagicLink>()
                .with_server_fn_axum::<VerifyMagicLinkToken>()
                .with_server_fn_axum::<SetupTotp>()
                .with_server_fn_axum::<VerifyTotpLogin>()
                .with_server_fn_axum::<GetProtectedData>()
                .generate_routes(App)
                .handle_with_context(
                    move || shell(leptos_options.clone()),
                    move || {
                        let parts = use_context::<http::request::Parts>();
                        let simulate_db_failure = parts
                            .as_ref()
                            .and_then(|p| p.headers.get("x-simulate-db-failure"))
                            .is_some();
                        let simulate_key_missing = parts
                            .as_ref()
                            .and_then(|p| p.headers.get("x-simulate-key-missing"))
                            .is_some();

                        let env_pub_key = std::env::var("JWT_PUBLIC_KEY").ok();
                        let public_key = if simulate_key_missing {
                            None
                        } else {
                            env_pub_key.as_deref().or(Some(state.public_key_pem))
                        };

                        if simulate_db_failure {
                            let failing_storage = DemoFailingStorage;
                            leptos_wasi_auth::provide_session_context(
                                Some(&failing_storage),
                                public_key,
                                Some("client-id-123"),
                                Some("leptos-auth-demo"),
                            );
                        } else {
                            leptos_wasi_auth::provide_session_context(
                                Some(&*state.storage),
                                public_key,
                                Some("client-id-123"),
                                Some("leptos-auth-demo"),
                            );
                        }
                    },
                )
                .await
                .unwrap();
        });
    }
}

wasi::http::proxy::export!(DemoApp with_types_in wasi);
