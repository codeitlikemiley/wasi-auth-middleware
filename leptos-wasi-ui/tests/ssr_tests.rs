#[cfg(feature = "ssr")]
mod tests {
    use leptos::prelude::*;
    use leptos_wasi_ui::{
        LoginForm, MagicLinkForm, OtpForm, PasskeyLoginButton, PasskeyRegisterButton, TotpSetup,
    };

    fn init_executor() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = any_spawner::Executor::init_futures_executor();
        });
    }

    #[test]
    fn test_login_form_render() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (request_otp_pending, _) = signal(false);
            let (request_otp_result, _) = signal(None);
            let (verify_otp_pending, _) = signal(false);
            let (verify_otp_result, _) = signal(None);
            let (request_magic_link_pending, _) = signal(false);
            let (request_magic_link_result, _) = signal(None);
            let (verify_totp_pending, _) = signal(false);
            let (verify_totp_result, _) = signal(None);
            let (passkey_login_pending, _) = signal(false);

            let html = view! {
                <LoginForm
                    request_otp_pending=request_otp_pending
                    request_otp_result=request_otp_result
                    verify_otp_pending=verify_otp_pending
                    verify_otp_result=verify_otp_result
                    request_magic_link_pending=request_magic_link_pending
                    request_magic_link_result=request_magic_link_result
                    verify_totp_pending=verify_totp_pending
                    verify_totp_result=verify_totp_result
                    passkey_login_pending=passkey_login_pending
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("Sign In"));
            assert!(html.contains("Email OTP"));
            assert!(html.contains("wasi-auth-login-form"));
            // Default glassmorphism styling
            assert!(html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[test]
    fn test_login_form_custom_style_class() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (request_otp_pending, _) = signal(false);
            let (request_otp_result, _) = signal(None);
            let (verify_otp_pending, _) = signal(false);
            let (verify_otp_result, _) = signal(None);
            let (request_magic_link_pending, _) = signal(false);
            let (request_magic_link_result, _) = signal(None);
            let (verify_totp_pending, _) = signal(false);
            let (verify_totp_result, _) = signal(None);
            let (passkey_login_pending, _) = signal(false);

            let html = view! {
                <LoginForm
                    class="my-custom-login-class"
                    style="border: 5px solid purple;"
                    request_otp_pending=request_otp_pending
                    request_otp_result=request_otp_result
                    verify_otp_pending=verify_otp_pending
                    verify_otp_result=verify_otp_result
                    request_magic_link_pending=request_magic_link_pending
                    request_magic_link_result=request_magic_link_result
                    verify_totp_pending=verify_totp_pending
                    verify_totp_result=verify_totp_result
                    passkey_login_pending=passkey_login_pending
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("my-custom-login-class"));
            assert!(html.contains("border: 5px solid purple;"));
        });
    }

    #[test]
    fn test_login_form_signals_and_props() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            // Test pending states and show_passkey
            let (request_otp_pending, _) = signal(true);
            let (request_otp_result, _) = signal(None);
            let (verify_otp_pending, _) = signal(false);
            let (verify_otp_result, _) = signal(None);
            let (request_magic_link_pending, _) = signal(false);
            let (request_magic_link_result, _) = signal(None);
            let (verify_totp_pending, _) = signal(false);
            let (verify_totp_result, _) = signal(None);
            let (passkey_login_pending, _) = signal(true);

            let html_pending = view! {
                <LoginForm
                    request_otp_pending=request_otp_pending
                    request_otp_result=request_otp_result
                    verify_otp_pending=verify_otp_pending
                    verify_otp_result=verify_otp_result
                    request_magic_link_pending=request_magic_link_pending
                    request_magic_link_result=request_magic_link_result
                    verify_totp_pending=verify_totp_pending
                    verify_totp_result=verify_totp_result
                    passkey_login_pending=passkey_login_pending
                    show_passkey=true
                />
            }
            .into_view()
            .to_html();

            assert!(html_pending.contains("Sending code..."));
            assert!(html_pending.contains("Starting Passkey..."));

            // Test error results
            let (request_otp_pending, _) = signal(false);
            let (request_otp_result, _) = signal(Some(Err("test_otp_error_msg".to_string())));
            let (passkey_login_pending, _) = signal(false);

            let html_error = view! {
                <LoginForm
                    request_otp_pending=request_otp_pending
                    request_otp_result=request_otp_result
                    verify_otp_pending=verify_otp_pending
                    verify_otp_result=verify_otp_result
                    request_magic_link_pending=request_magic_link_pending
                    request_magic_link_result=request_magic_link_result
                    verify_totp_pending=verify_totp_pending
                    verify_totp_result=verify_totp_result
                    passkey_login_pending=passkey_login_pending
                    show_passkey=false
                />
            }
            .into_view()
            .to_html();

            assert!(html_error.contains("test_otp_error_msg"));
            // Since show_passkey is false, should not render the passkey button
            assert!(!html_error.contains("Login with Passkey"));
            assert!(!html_error.contains("Starting Passkey..."));
        });
    }

    #[test]
    fn test_totp_setup_render() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (uri, _) = signal(None);
            let (setup_pending, _) = signal(false);
            let (setup_result, _) = signal(None);
            let (verify_pending, _) = signal(false);
            let (verify_result, _) = signal(None);

            let html = view! {
                <TotpSetup
                    uri=uri
                    setup_pending=setup_pending
                    setup_result=setup_result
                    verify_pending=verify_pending
                    verify_result=verify_result
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("MFA: TOTP Setup"));
            assert!(html.contains("wasi-auth-totp-setup"));
            assert!(html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[test]
    fn test_totp_setup_custom_style_class() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (uri, _) = signal(None);
            let (setup_pending, _) = signal(false);
            let (setup_result, _) = signal(None);
            let (verify_pending, _) = signal(false);
            let (verify_result, _) = signal(None);

            let html = view! {
                <TotpSetup
                    class="my-custom-totp-class"
                    style="padding: 99px;"
                    uri=uri
                    setup_pending=setup_pending
                    setup_result=setup_result
                    verify_pending=verify_pending
                    verify_result=verify_result
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("my-custom-totp-class"));
            assert!(html.contains("padding: 99px;"));
        });
    }

    #[test]
    fn test_totp_setup_signals() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (uri, _) = signal(None);
            let (setup_pending, _) = signal(true);
            let (setup_result, _) = signal(Some(Err("totp_init_failed".to_string())));
            let (verify_pending, _) = signal(false);
            let (verify_result, _) = signal(None);

            let html = view! {
                <TotpSetup
                    uri=uri
                    setup_pending=setup_pending
                    setup_result=setup_result
                    verify_pending=verify_pending
                    verify_result=verify_result
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("Initializing..."));
            assert!(html.contains("totp_init_failed"));
        });
    }

    #[test]
    fn test_otp_form_render() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (request_pending, _) = signal(false);
            let (request_result, _) = signal(None);
            let (verify_pending, _) = signal(false);
            let (verify_result, _) = signal(None);

            let html = view! {
                <OtpForm
                    request_pending=request_pending
                    request_result=request_result
                    verify_pending=verify_pending
                    verify_result=verify_result
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("One-Time Password"));
            assert!(html.contains("wasi-auth-otp-form"));
            assert!(html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[test]
    fn test_otp_form_custom_style_class() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (request_pending, _) = signal(false);
            let (request_result, _) = signal(None);
            let (verify_pending, _) = signal(false);
            let (verify_result, _) = signal(None);

            let html = view! {
                <OtpForm
                    class="custom-otp-class"
                    style="margin: 42px;"
                    request_pending=request_pending
                    request_result=request_result
                    verify_pending=verify_pending
                    verify_result=verify_result
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("custom-otp-class"));
            assert!(html.contains("margin: 42px;"));
        });
    }

    #[test]
    fn test_otp_form_signals() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (request_pending, _) = signal(true);
            let (request_result, _) = signal(Some(Err("otp_request_error".to_string())));
            let (verify_pending, _) = signal(false);
            let (verify_result, _) = signal(None);

            let html = view! {
                <OtpForm
                    request_pending=request_pending
                    request_result=request_result
                    verify_pending=verify_pending
                    verify_result=verify_result
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("Sending code..."));
            assert!(html.contains("otp_request_error"));
        });
    }

    #[test]
    fn test_magic_link_form_render() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (request_pending, _) = signal(false);
            let (request_result, _) = signal(None);

            let html = view! {
                <MagicLinkForm
                    request_pending=request_pending
                    request_result=request_result
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("Magic Link"));
            assert!(html.contains("wasi-auth-magic-link-form"));
            assert!(html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[test]
    fn test_magic_link_form_custom_style_class() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (request_pending, _) = signal(false);
            let (request_result, _) = signal(None);

            let html = view! {
                <MagicLinkForm
                    class="magic-custom"
                    style="display: block;"
                    request_pending=request_pending
                    request_result=request_result
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("magic-custom"));
            assert!(html.contains("display: block;"));
        });
    }

    #[test]
    fn test_magic_link_form_signals() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (request_pending, _) = signal(true);
            let (request_result, _) = signal(Some(Ok("test_sent_link_msg".to_string())));

            let html = view! {
                <MagicLinkForm
                    request_pending=request_pending
                    request_result=request_result
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("Sending link..."));
            assert!(html.contains("test_sent_link_msg"));
        });
    }

    #[test]
    fn test_passkey_register_button_render() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (options, _) = signal(None);
            let (pending, _) = signal(false);
            let success_cb = Callback::new(|_| {});
            let error_cb = Callback::new(|_| {});

            let html = view! {
                <PasskeyRegisterButton
                    options=options
                    on_register_success=success_cb
                    on_register_error=error_cb
                    pending=pending
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("Register Passkey"));
            assert!(html.contains("wasi-auth-passkey-button"));
            assert!(html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[test]
    fn test_passkey_register_button_custom_style_class() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (options, _) = signal(None);
            let (pending, _) = signal(false);
            let success_cb = Callback::new(|_| {});
            let error_cb = Callback::new(|_| {});

            let html = view! {
                <PasskeyRegisterButton
                    class="custom-reg-btn"
                    style="font-size: 24px;"
                    options=options
                    on_register_success=success_cb
                    on_register_error=error_cb
                    pending=pending
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("custom-reg-btn"));
            assert!(html.contains("font-size: 24px;"));
        });
    }

    #[test]
    fn test_passkey_register_button_signals() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (options, _) = signal(None);
            let (pending, _) = signal(true);
            let success_cb = Callback::new(|_| {});
            let error_cb = Callback::new(|_| {});

            let html = view! {
                <PasskeyRegisterButton
                    options=options
                    on_register_success=success_cb
                    on_register_error=error_cb
                    pending=pending
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("Starting ceremony..."));
            assert!(html.contains("disabled"));
        });
    }

    #[test]
    fn test_passkey_login_button_render() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (options, _) = signal(None);
            let (pending, _) = signal(false);
            let success_cb = Callback::new(|_| {});
            let error_cb = Callback::new(|_| {});

            let html = view! {
                <PasskeyLoginButton
                    options=options
                    on_login_success=success_cb
                    on_login_error=error_cb
                    pending=pending
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("Login with Passkey"));
            assert!(html.contains("wasi-auth-passkey-button"));
            assert!(html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[test]
    fn test_passkey_login_button_custom_style_class() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (options, _) = signal(None);
            let (pending, _) = signal(false);
            let success_cb = Callback::new(|_| {});
            let error_cb = Callback::new(|_| {});

            let html = view! {
                <PasskeyLoginButton
                    class="custom-login-btn"
                    style="color: rgb(255, 0, 0);"
                    options=options
                    on_login_success=success_cb
                    on_login_error=error_cb
                    pending=pending
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("custom-login-btn"));
            assert!(html.contains("color: rgb(255, 0, 0);"));
        });
    }

    #[test]
    fn test_passkey_login_button_signals() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (options, _) = signal(None);
            let (pending, _) = signal(true);
            let success_cb = Callback::new(|_| {});
            let error_cb = Callback::new(|_| {});

            let html = view! {
                <PasskeyLoginButton
                    options=options
                    on_login_success=success_cb
                    on_login_error=error_cb
                    pending=pending
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("Starting ceremony..."));
            assert!(html.contains("disabled"));
        });
    }
}
