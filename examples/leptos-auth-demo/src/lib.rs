use leptos::html;
use leptos::prelude::*;
use leptos_router::components::*;
use leptos_router::path;
use leptos_wasi::prelude::Handler;
use leptos_wasi_auth::{expect_session, UserSession};
use wasi_auth_core::{InMemoryStorage, OAuthConfig, Oauth2Client, Session, StdoutEmail};

// Using the official wasi crate instead of local wit-bindgen generation to avoid interface clashes.

#[derive(Clone, Debug)]
pub struct AppState {
    pub storage: std::sync::Arc<InMemoryStorage>,
    pub email_sender: std::sync::Arc<StdoutEmail>,
    pub oauth_config: OAuthConfig,
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
    let state = STATE.with(|s| s.clone());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let otp = wasi_auth_core::otp::send_and_store_otp(
        &email,
        &*state.storage,
        &*state.email_sender,
        300,
        now,
    )
    .map_err(|e| ServerFnError::new(format!("Failed to send OTP: {:?}", e)))?;

    Ok(format!(
        "OTP sent successfully! (Dev Mode: code is {})",
        otp
    ))
}

#[server(VerifyOtp, "/api")]
pub async fn verify_otp(email: String, otp: String) -> Result<bool, ServerFnError> {
    let state = STATE.with(|s| s.clone());
    let ok = wasi_auth_core::otp::verify_otp(&email, &otp, &*state.storage)
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
            roles: vec!["user".to_string()],
            name: Some(email.split('@').next().unwrap_or("User").to_string()),
            email: Some(email),
        };

        // Use dummy private key to sign for demo (dev only!)
        let dummy_priv_key = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAnz5u8v7p9qJgN2p7bCf... (dummy)
-----END RSA PRIVATE KEY-----"#;
        // In real app, we would sign with a real key or set a cookie.
        // For testing, just return true
        Ok(true)
    } else {
        Err(ServerFnError::new("Invalid or expired OTP code"))
    }
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
                </Routes>
            </main>
        </Router>
    }
}

#[component]
pub fn Home() -> impl IntoView {
    view! {
        <div style="padding: 20px; font-family: sans-serif;">
            <h1>"Hello from Leptos Auth Demo!"</h1>
            <p>"This is a WebAssembly-native application secure portal."</p>
            <div style="margin-top: 20px;">
                <a href="/login" style="margin-right: 15px;">"Login Portal"</a>
                <a href="/dashboard">"User Dashboard"</a>
            </div>
        </div>
    }
}

#[component]
pub fn Login() -> impl IntoView {
    let email_input = NodeRef::<html::Input>::new();
    let otp_input = NodeRef::<html::Input>::new();

    let request_otp_action = Action::new(|email: &String| {
        let email = email.clone();
        async move { request_otp(email).await }
    });

    let verify_otp_action = Action::new(|(email, otp): &(String, String)| {
        let email = email.clone();
        let otp = otp.clone();
        async move { verify_otp(email, otp).await }
    });

    let on_request = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let email = email_input.get().unwrap().value();
        request_otp_action.dispatch(email);
    };

    let on_verify = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let email = email_input.get().unwrap().value();
        let otp = otp_input.get().unwrap().value();
        verify_otp_action.dispatch((email, otp));
    };

    view! {
        <div style="padding: 20px; max-width: 400px; font-family: sans-serif;">
            <h2>"Login Portal"</h2>

            <form on:submit=on_request>
                <h3>"Email OTP Login"</h3>
                <input type="email" node_ref=email_input placeholder="user@example.com" required style="width: 100%; padding: 8px; margin-bottom: 10px;"/>
                <button type="submit" style="padding: 8px 12px;">"Send 6-digit OTP"</button>
            </form>

            <form on:submit=on_verify style="margin-top: 20px;">
                <input type="text" node_ref=otp_input placeholder="123456" required style="width: 100%; padding: 8px; margin-bottom: 10px;"/>
                <button type="submit" style="padding: 8px 12px;">"Verify Code & Login"</button>
            </form>

            <div style="margin-top: 30px;">
                <h3>"Social Sign-In"</h3>
                <div style="display: flex; gap: 10px;">
                    <a href="http://127.0.0.1:8080/authorize?client_id=client-id-123&redirect_uri=http://127.0.0.1:8080/callback&state=google&scope=openid" style="padding: 8px; border: 1px solid #ccc; text-decoration: none;">"Google"</a>
                    <a href="http://127.0.0.1:8080/authorize?client_id=client-id-123&redirect_uri=http://127.0.0.1:8080/callback&state=facebook&scope=openid" style="padding: 8px; border: 1px solid #ccc; text-decoration: none;">"Facebook"</a>
                    <a href="http://127.0.0.1:8080/authorize?client_id=client-id-123&redirect_uri=http://127.0.0.1:8080/callback&state=x&scope=openid" style="padding: 8px; border: 1px solid #ccc; text-decoration: none;">"X.com"</a>
                </div>
            </div>
        </div>
    }
}

#[component]
pub fn Dashboard() -> impl IntoView {
    let session = use_context::<Option<UserSession>>().flatten();

    view! {
        <div style="padding: 20px; font-family: sans-serif;">
            <h2>"User Dashboard"</h2>
            {match session {
                Some(user) => view! {
                    <div>
                        <p>"Welcome back, " <strong>{user.name.unwrap_or_else(|| "User".to_string())}</strong> "!"</p>
                        <p>"User ID: " {user.user_id}</p>
                        <p>"Roles: " {user.roles.join(", ")}</p>
                    </div>
                }.into_any(),
                None => view! {
                    <div>
                        <p style="color: red;">"Access Denied: You are not logged in."</p>
                        <a href="/login">"Go to Login"</a>
                    </div>
                }.into_any()
            }}
        </div>
    }
}

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html>
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <AutoReload options=options.clone() />
                <HydrationScripts options=options />
            </head>
            <body>
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
                .generate_routes(App)
                .handle_with_context(
                    move || shell(leptos_options.clone()),
                    move || {
                        // Extract session headers injected by interceptor and inject into Leptos context
                        leptos_wasi_auth::provide_session_context(
                            Some(&*state.storage),
                            None,
                            None,
                            None,
                        );
                    },
                )
                .await
                .unwrap();
        });
    }
}

wasi::http::proxy::export!(DemoApp with_types_in wasi);
