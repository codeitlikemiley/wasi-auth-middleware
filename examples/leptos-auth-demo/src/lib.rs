#![allow(clippy::unused_unit, clippy::unit_arg, unused_variables)]
use leptos::html;
use leptos::prelude::*;
use leptos_router::components::*;
use leptos_router::path;
use leptos_wasi::prelude::Handler;
use leptos_wasi_auth::UserSession;
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
        Self {
            storage: std::sync::Arc::new(InMemoryStorage::new()),
            email_sender: std::sync::Arc::new(StdoutEmail::new()),
            oauth_config: OAuthConfig {
                client_id: "client-id-123".to_string(),
                client_secret: "client-secret-123".to_string(),
                auth_url: "http://127.0.0.1:8080/authorize".to_string(),
                token_url: "http://127.0.0.1:8080/token".to_string(),
                userinfo_url: Some("http://127.0.0.1:8080/userinfo".to_string()),
                redirect_uri: "http://127.0.0.1:8080/callback".to_string(),
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
    let email_input = NodeRef::<html::Input>::new();
    let code_input = NodeRef::<html::Input>::new();

    let setup_action = Action::new(|email: &String| {
        let email = email.clone();
        async move { setup_totp(email).await }
    });

    let verify_action = Action::new(|(email, code): &(String, String)| {
        let email = email.clone();
        let code = code.clone();
        async move { verify_totp_login_action(email, code).await }
    });

    let on_setup = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let email = email_input.get().unwrap().value();
        setup_action.dispatch(email);
    };

    let on_verify = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let email = email_input.get().unwrap().value();
        let code = code_input.get().unwrap().value();
        verify_action.dispatch((email, code));
    };

    let navigate = leptos_router::hooks::use_navigate();

    Effect::new(move |_| {
        if let Some(Ok(true)) = verify_action.value().get() {
            navigate("/dashboard", Default::default());
        }
    });

    view! {
        <div style="background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 40px; width: 100%; max-width: 480px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.3);">
            <h2 style="font-size: 1.75rem; margin-bottom: 8px; font-weight: 700; letter-spacing: -0.025em; color: #ffffff;">"MFA: TOTP Setup"</h2>
            <p style="margin-bottom: 24px; color: #64748b; font-size: 0.95rem; line-height: 1.6;">"Register an authenticator app (Google Authenticator, Authy, etc.)."</p>

            {move || {
                match verify_action.value().get() {
                    Some(Err(err)) => view! {
                        <div style="padding: 12px 16px; border-radius: 8px; font-size: 0.9rem; margin-bottom: 20px; border: 1px solid rgba(239, 68, 68, 0.2); text-align: left; background: rgba(239, 68, 68, 0.1); color: #f87171;">
                            {err.to_string()}
                        </div>
                    }.into_any(),
                    _ => view! {}.into_any(),
                }
            }}

            <form on:submit=on_setup>
                <div style="margin-bottom: 20px; text-align: left;">
                    <label style="display: block; font-size: 0.85rem; font-weight: 600; color: #94a3b8; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.05em;">"Email Address"</label>
                    <input type="email" node_ref=email_input placeholder="name@domain.com" style="width: 100%; padding: 12px 16px; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; color: white; font-size: 1rem; font-family: inherit; transition: all 0.2s ease;" required=true/>
                </div>
                <button type="submit" style="display: inline-flex; align-items: center; justify-content: center; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; border: none; outline: none; width: 100%; color: white; background: linear-gradient(135deg, #6366f1, #a855f7); box-shadow: 0 4px 14px 0 rgba(99, 102, 241, 0.3); margin-bottom: 20px;">
                    {move || if setup_action.pending().get() { "Generating Secret..." } else { "Generate TOTP Key" }}
                </button>
            </form>

            {move || {
                match setup_action.value().get() {
                    Some(Ok(uri)) => {
                        let secret = uri.split("secret=").nth(1).and_then(|s| s.split('&').next()).unwrap_or("").to_string();
                        let uri_clone = uri.clone();
                        view! {
                            <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid rgba(255, 255, 255, 0.08);">
                                <div style="padding: 12px 16px; border-radius: 8px; font-size: 0.85rem; margin-bottom: 20px; border: 1px solid rgba(168, 85, 247, 0.2); background: rgba(168, 85, 247, 0.1); color: #c084fc; word-break: break-all; text-align: left;">
                                    <strong>"Secret Key: "</strong> <code style="font-family: monospace; background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">{secret}</code>
                                    <br/><br/>
                                    <strong>"Provisioning URI (for manual entry):"</strong>
                                    <pre style="white-space: pre-wrap; font-size: 0.75rem; background: rgba(0,0,0,0.4); padding: 8px; border-radius: 6px; margin: 8px 0 0 0; color: #e2e8f0; font-family: monospace;">{uri_clone}</pre>
                                </div>

                                <form on:submit=on_verify>
                                    <div style="margin-bottom: 20px; text-align: left;">
                                        <label style="display: block; font-size: 0.85rem; font-weight: 600; color: #94a3b8; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.05em;">"Enter 6-Digit Authenticator Code"</label>
                                        <input type="text" node_ref=code_input placeholder="123456" style="width: 100%; padding: 12px 16px; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; color: white; font-size: 1rem; font-family: inherit; transition: all 0.2s ease;" required=true/>
                                    </div>
                                    <button type="submit" style="display: inline-flex; align-items: center; justify-content: center; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; border: none; outline: none; width: 100%; color: white; background: linear-gradient(135deg, #10b981, #14b8a6); box-shadow: 0 4px 14px 0 rgba(16, 185, 129, 0.3);">
                                        {move || if verify_action.pending().get() { "Verifying..." } else { "Verify Code & Login" }}
                                    </button>
                                </form>
                            </div>
                        }.into_any()
                    }
                    Some(Err(err)) => view! {
                        <div style="padding: 12px 16px; border-radius: 8px; font-size: 0.9rem; margin-bottom: 20px; border: 1px solid rgba(239, 68, 68, 0.2); text-align: left; background: rgba(239, 68, 68, 0.1); color: #f87171;">
                            {err.to_string()}
                        </div>
                    }.into_any(),
                    None => view! {}.into_any()
                }
            }}

            <div style="margin-top: 24px; text-align: center;">
                <a href="/login" style="color: #64748b; font-size: 0.85rem; text-decoration: none;">"← Back to Login"</a>
            </div>
        </div>
    }
}

#[component]
pub fn Login() -> impl IntoView {
    let email_input = NodeRef::<html::Input>::new();
    let otp_input = NodeRef::<html::Input>::new();
    let totp_code_input = NodeRef::<html::Input>::new();

    // Mode selection: 0 = OTP, 1 = Magic Link, 2 = TOTP Login
    let auth_mode = RwSignal::new(0);

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

    let on_submit_main = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let email = email_input.get().unwrap().value();
        if auth_mode.get() == 0 {
            request_otp_action.dispatch(email);
        } else if auth_mode.get() == 1 {
            request_magic_link_action.dispatch(email);
        }
    };

    let on_verify_otp = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let email = email_input.get().unwrap().value();
        let otp = otp_input.get().unwrap().value();
        verify_otp_action.dispatch((email, otp));
    };

    let on_verify_totp = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let email = email_input.get().unwrap().value();
        let code = totp_code_input.get().unwrap().value();
        verify_totp_action.dispatch((email, code));
    };

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
            <h2 style="font-size: 1.75rem; margin-bottom: 8px; font-weight: 700; letter-spacing: -0.025em; color: #ffffff;">"Sign In"</h2>

            // Tab Selection for authentication methods
            <div style="display: flex; gap: 8px; margin-bottom: 24px; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 12px;">
                <button on:click=move |_| auth_mode.set(0) style=move || format!("flex: 1; padding: 8px; font-weight: 600; font-size: 0.85rem; border-radius: 6px; cursor: pointer; border: none; transition: all 0.2s; {}", if auth_mode.get() == 0 { "background: rgba(99, 102, 241, 0.2); color: #818cf8;" } else { "background: transparent; color: #64748b;" })>"OTP Code"</button>
                <button on:click=move |_| auth_mode.set(1) style=move || format!("flex: 1; padding: 8px; font-weight: 600; font-size: 0.85rem; border-radius: 6px; cursor: pointer; border: none; transition: all 0.2s; {}", if auth_mode.get() == 1 { "background: rgba(168, 85, 247, 0.2); color: #c084fc;" } else { "background: transparent; color: #64748b;" })>"Magic Link"</button>
                <button on:click=move |_| auth_mode.set(2) style=move || format!("flex: 1; padding: 8px; font-weight: 600; font-size: 0.85rem; border-radius: 6px; cursor: pointer; border: none; transition: all 0.2s; {}", if auth_mode.get() == 2 { "background: rgba(16, 185, 129, 0.2); color: #34d399;" } else { "background: transparent; color: #64748b;" })>"TOTP (MFA)"</button>
            </div>

            {move || {
                match request_otp_action.value().get() {
                    Some(Ok(msg)) => view! {
                        <div style="padding: 12px 16px; border-radius: 8px; font-size: 0.9rem; margin-bottom: 20px; border: 1px solid rgba(16, 185, 129, 0.2); text-align: left; background: rgba(16, 185, 129, 0.1); color: #34d399;">
                            {msg}
                        </div>
                    }.into_any(),
                    Some(Err(err)) => view! {
                        <div style="padding: 12px 16px; border-radius: 8px; font-size: 0.9rem; margin-bottom: 20px; border: 1px solid rgba(239, 68, 68, 0.2); text-align: left; background: rgba(239, 68, 68, 0.1); color: #f87171;">
                            {err.to_string()}
                        </div>
                    }.into_any(),
                    None => view! {}.into_any(),
                }
            }}

            {move || {
                match request_magic_link_action.value().get() {
                    Some(Ok(msg)) => view! {
                        <div style="padding: 12px 16px; border-radius: 8px; font-size: 0.9rem; margin-bottom: 20px; border: 1px solid rgba(168, 85, 247, 0.2); text-align: left; background: rgba(168, 85, 247, 0.1); color: #c084fc; word-break: break-all;">
                            {msg}
                        </div>
                    }.into_any(),
                    Some(Err(err)) => view! {
                        <div style="padding: 12px 16px; border-radius: 8px; font-size: 0.9rem; margin-bottom: 20px; border: 1px solid rgba(239, 68, 68, 0.2); text-align: left; background: rgba(239, 68, 68, 0.1); color: #f87171;">
                            {err.to_string()}
                        </div>
                    }.into_any(),
                    None => view! {}.into_any(),
                }
            }}

            {move || {
                match verify_otp_action.value().get() {
                    Some(Err(err)) => view! {
                        <div style="padding: 12px 16px; border-radius: 8px; font-size: 0.9rem; margin-bottom: 20px; border: 1px solid rgba(239, 68, 68, 0.2); text-align: left; background: rgba(239, 68, 68, 0.1); color: #f87171;">
                            {err.to_string()}
                        </div>
                    }.into_any(),
                    _ => view! {}.into_any(),
                }
            }}

            {move || {
                match verify_totp_action.value().get() {
                    Some(Err(err)) => view! {
                        <div style="padding: 12px 16px; border-radius: 8px; font-size: 0.9rem; margin-bottom: 20px; border: 1px solid rgba(239, 68, 68, 0.2); text-align: left; background: rgba(239, 68, 68, 0.1); color: #f87171;">
                            {err.to_string()}
                        </div>
                    }.into_any(),
                    _ => view! {}.into_any(),
                }
            }}

            {move || {
                if auth_mode.get() != 2 {
                    view! {
                        <form on:submit=on_submit_main>
                            <div style="margin-bottom: 20px; text-align: left;">
                                <label style="display: block; font-size: 0.85rem; font-weight: 600; color: #94a3b8; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.05em;">"Email Address"</label>
                                <input type="email" node_ref=email_input placeholder="name@domain.com" style="width: 100%; padding: 12px 16px; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; color: white; font-size: 1rem; font-family: inherit; transition: all 0.2s ease;" required=true/>
                            </div>
                            <button type="submit" style=move || format!("display: inline-flex; align-items: center; justify-content: center; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; border: none; outline: none; width: 100%; color: white; background: {}; margin-bottom: 20px;", if auth_mode.get() == 0 { "linear-gradient(135deg, #6366f1, #a855f7)" } else { "linear-gradient(135deg, #a855f7, #ec4899)" })>
                                {move || {
                                    if auth_mode.get() == 0 {
                                        if request_otp_action.pending().get() { "Sending Code..." } else { "Send OTP Code" }
                                    } else {
                                        if request_magic_link_action.pending().get() { "Sending Link..." } else { "Send Magic Link" }
                                    }
                                }}
                            </button>
                        </form>
                    }.into_any()
                } else {
                    view! {
                        <form on:submit=on_verify_totp>
                            <div style="margin-bottom: 20px; text-align: left;">
                                <label style="display: block; font-size: 0.85rem; font-weight: 600; color: #94a3b8; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.05em;">"Email Address"</label>
                                <input type="email" node_ref=email_input placeholder="name@domain.com" style="width: 100%; padding: 12px 16px; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; color: white; font-size: 1rem; font-family: inherit; transition: all 0.2s ease; margin-bottom: 16px;" required=true/>

                                <label style="display: block; font-size: 0.85rem; font-weight: 600; color: #94a3b8; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.05em;">"6-Digit Authenticator Code"</label>
                                <input type="text" node_ref=totp_code_input placeholder="123456" style="width: 100%; padding: 12px 16px; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; color: white; font-size: 1rem; font-family: inherit; transition: all 0.2s ease;" required=true/>
                            </div>
                            <button type="submit" style="display: inline-flex; align-items: center; justify-content: center; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; border: none; outline: none; width: 100%; color: white; background: linear-gradient(135deg, #10b981, #14b8a6); box-shadow: 0 4px 14px 0 rgba(16, 185, 129, 0.3); margin-bottom: 20px;">
                                {move || if verify_totp_action.pending().get() { "Verifying..." } else { "Verify & Login" }}
                            </button>
                        </form>
                    }.into_any()
                }
            }}

            {move || {
                if auth_mode.get() == 0 && request_otp_action.value().get().is_some() {
                    view! {
                        <form on:submit=on_verify_otp>
                            <div style="margin-bottom: 20px; text-align: left;">
                                <label style="display: block; font-size: 0.85rem; font-weight: 600; color: #94a3b8; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.05em;">"6-Digit Verification Code"</label>
                                <input type="text" node_ref=otp_input placeholder="123456" style="width: 100%; padding: 12px 16px; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; color: white; font-size: 1rem; font-family: inherit; transition: all 0.2s ease;" required=true/>
                            </div>
                            <button type="submit" style="display: inline-flex; align-items: center; justify-content: center; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; border: none; outline: none; width: 100%; color: white; background: linear-gradient(135deg, #10b981, #14b8a6); box-shadow: 0 4px 14px 0 rgba(16, 185, 129, 0.3);">
                                {move || if verify_otp_action.pending().get() { "Verifying..." } else { "Verify & Login" }}
                            </button>
                        </form>
                    }.into_any()
                } else {
                    view! {}.into_any()
                }
            }}

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
                        <div style="display: flex; gap: 12px;">
                            <form on:submit=on_logout style="margin: 0;">
                                <button type="submit" style="display: inline-flex; align-items: center; justify-content: center; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; border: none; outline: none; color: white; background: linear-gradient(135deg, #ef4444, #f43f5e);">
                                    {move || if logout_action.pending().get() { "Signing Out..." } else { "Sign Out" }}
                                </button>
                            </form>
                            <a href="/totp-setup" style="display: inline-flex; align-items: center; justify-content: center; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; border: none; outline: none; color: white; background: linear-gradient(135deg, #10b981, #14b8a6); text-decoration: none; box-shadow: 0 4px 14px 0 rgba(16, 185, 129, 0.3);">"Set up TOTP (MFA)"</a>
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
                .generate_routes(App)
                .handle_with_context(
                    move || shell(leptos_options.clone()),
                    move || {
                        // Extract session headers or cookies and verify JWT using SPKI PEM key
                        leptos_wasi_auth::provide_session_context(
                            Some(&*state.storage),
                            Some(state.public_key_pem),
                            Some("client-id-123"),
                            Some("leptos-auth-demo"),
                        );
                    },
                )
                .await
                .unwrap();
        });
    }
}

wasi::http::proxy::export!(DemoApp with_types_in wasi);
