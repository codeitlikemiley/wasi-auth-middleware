#[cfg(feature = "ssr")]
mod tests {
    use leptos::prelude::*;
    #[cfg(feature = "passkey")]
    use leptos_wasi_ui::PasskeyList;
    use leptos_wasi_ui::{
        LoginForm, MagicLinkForm, MfaStatus, OtpForm, PasskeyLoginButton, PasskeyRegisterButton,
        SessionList, TotpSetup,
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
                    on_request=Callback::new(|_| {})
                    on_verify=Callback::new(|_| {})
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
                    on_request=Callback::new(|_| {})
                    on_verify=Callback::new(|_| {})
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
                    on_request=Callback::new(|_| {})
                    on_verify=Callback::new(|_| {})
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
                    on_request=Callback::new(|_| {})
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
                    on_request=Callback::new(|_| {})
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
                    on_request=Callback::new(|_| {})
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

    #[test]
    fn test_login_form_use_default_styles_false() {
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
                    use_default_styles=false
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

            assert!(!html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[test]
    fn test_totp_setup_use_default_styles_false() {
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
                    use_default_styles=false
                    uri=uri
                    setup_pending=setup_pending
                    setup_result=setup_result
                    verify_pending=verify_pending
                    verify_result=verify_result
                />
            }
            .into_view()
            .to_html();

            assert!(!html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[test]
    fn test_otp_form_use_default_styles_false() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (request_pending, _) = signal(false);
            let (request_result, _) = signal(None);
            let (verify_pending, _) = signal(false);
            let (verify_result, _) = signal(None);

            let html = view! {
                <OtpForm
                    use_default_styles=false
                    request_pending=request_pending
                    request_result=request_result
                    verify_pending=verify_pending
                    verify_result=verify_result
                    on_request=Callback::new(|_| {})
                    on_verify=Callback::new(|_| {})
                />
            }
            .into_view()
            .to_html();

            assert!(!html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[test]
    fn test_magic_link_form_use_default_styles_false() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (request_pending, _) = signal(false);
            let (request_result, _) = signal(None);

            let html = view! {
                <MagicLinkForm
                    use_default_styles=false
                    request_pending=request_pending
                    request_result=request_result
                    on_request=Callback::new(|_| {})
                />
            }
            .into_view()
            .to_html();

            assert!(!html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[test]
    fn test_passkey_register_button_use_default_styles_false() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (options, _) = signal(None);
            let (pending, _) = signal(false);
            let success_cb = Callback::new(|_| {});
            let error_cb = Callback::new(|_| {});

            let html = view! {
                <PasskeyRegisterButton
                    use_default_styles=false
                    options=options
                    on_register_success=success_cb
                    on_register_error=error_cb
                    pending=pending
                />
            }
            .into_view()
            .to_html();

            assert!(!html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[test]
    fn test_passkey_login_button_use_default_styles_false() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (options, _) = signal(None);
            let (pending, _) = signal(false);
            let success_cb = Callback::new(|_| {});
            let error_cb = Callback::new(|_| {});

            let html = view! {
                <PasskeyLoginButton
                    use_default_styles=false
                    options=options
                    on_login_success=success_cb
                    on_login_error=error_cb
                    pending=pending
                />
            }
            .into_view()
            .to_html();

            assert!(!html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[test]
    fn test_session_list_render() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let sessions = vec![wasi_auth_traits::Session {
                session_id: "test-session-12345".to_string(),
                user_id: "user-1".to_string(),
                roles: vec!["admin".to_string()],
                expires_at: 9999999999,
            }];
            let (sessions_signal, _) = signal(sessions);
            let (current_session_id, _) = signal(Some("test-session-12345".to_string()));
            let (revoke_pending, _) = signal(false);
            let (revoke_result, _) = signal(None);
            let on_revoke = Callback::new(|id| {
                assert_eq!(id, "test-session-12345");
            });

            let html = view! {
                <SessionList
                    sessions=sessions_signal
                    current_session_id=current_session_id
                    on_revoke=on_revoke
                    revoke_pending=revoke_pending
                    revoke_result=revoke_result
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("Active Sessions"));
            assert!(html.contains("test-ses...")); // Truncated display
            assert!(html.contains("Current")); // Active session badge/highlight
            assert!(html.contains("ADMIN")); // Badged role in uppercase
            assert!(html.contains("Revoke"));
            assert!(html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[test]
    fn test_mfa_status_render() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (totp_enabled, _) = signal(true);
            let (disable_pending, _) = signal(false);
            let (disable_result, _) = signal(None);
            let on_disable = Callback::new(|_| {});

            let html = view! {
                <MfaStatus
                    totp_enabled=totp_enabled
                    on_disable=on_disable
                    disable_pending=disable_pending
                    disable_result=disable_result
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("Multi-Factor Authentication"));
            assert!(html.contains("Enabled"));
            assert!(html.contains("Disable Multi-Factor Authentication"));
            assert!(html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[cfg(feature = "passkey")]
    #[test]
    fn test_passkey_list_render() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let passkeys = vec![wasi_auth_core::passkey::StoredPasskey {
                user_id: "user-1".to_string(),
                cred_id: "cred_1".to_string(),
                public_key: "dummy_pk".to_string(),
                name: "My Macbook".to_string(),
                created_at: 1700000000000,
                last_used_at: 1700005000000,
                counter: 0,
            }];
            let (passkeys_signal, _) = signal(passkeys);
            let (pending_signal, _) = signal(false);
            let on_delete = Callback::new(|_| {});
            let on_rename = Callback::new(|_| {});

            let html = view! {
                <PasskeyList
                    passkeys=passkeys_signal
                    on_delete=on_delete
                    on_rename=on_rename
                    pending=pending_signal
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("Registered Passkeys"));
            assert!(html.contains("My Macbook"));
            assert!(html.contains("Added: "));
            assert!(html.contains("Last used: "));
        });
    }

    #[test]
    fn test_session_list_empty() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (sessions_signal, _) = signal(vec![]);
            let (current_session_id, _) = signal(None);
            let (revoke_pending, _) = signal(false);
            let (revoke_result, _) = signal(None);
            let on_revoke = Callback::new(|_| {});

            let html = view! {
                <SessionList
                    sessions=sessions_signal
                    current_session_id=current_session_id
                    on_revoke=on_revoke
                    revoke_pending=revoke_pending
                    revoke_result=revoke_result
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("No active sessions found."));
        });
    }

    #[test]
    fn test_session_list_non_ascii_session_id_panic() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let sessions = vec![wasi_auth_traits::Session {
                session_id: "🔑a🔑b🔑c🔑d🔑e🔑".to_string(),
                user_id: "user-1".to_string(),
                roles: vec![],
                expires_at: 1700000000,
            }];
            let (sessions_signal, _) = signal(sessions);
            let (current_session_id, _) = signal(None);
            let (revoke_pending, _) = signal(false);
            let (revoke_result, _) = signal(None);
            let on_revoke = Callback::new(|_| {});

            let html = view! {
                <SessionList
                    sessions=sessions_signal
                    current_session_id=current_session_id
                    on_revoke=on_revoke
                    revoke_pending=revoke_pending
                    revoke_result=revoke_result
                />
            }
            .into_view()
            .to_html();
            assert!(html.contains("🔑a🔑b🔑c🔑d..."));
        });
    }

    #[test]
    fn test_session_list_large_timestamp_dos() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let sessions = vec![wasi_auth_traits::Session {
                session_id: "session-ok".to_string(),
                user_id: "user-1".to_string(),
                roles: vec![],
                expires_at: 32503680000,
            }];
            let (sessions_signal, _) = signal(sessions);
            let (current_session_id, _) = signal(None);
            let (revoke_pending, _) = signal(false);
            let (revoke_result, _) = signal(None);
            let on_revoke = Callback::new(|_| {});

            let html = view! {
                <SessionList
                    sessions=sessions_signal
                    current_session_id=current_session_id
                    on_revoke=on_revoke
                    revoke_pending=revoke_pending
                    revoke_result=revoke_result
                />
            }
            .into_view()
            .to_html();
            assert!(html.contains("Expires: 3000-01-01 00:00:00 UTC"));
        });
    }

    #[cfg(feature = "passkey")]
    #[test]
    fn test_passkey_list_empty() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (passkeys_signal, _) = signal(vec![]);
            let (pending_signal, _) = signal(false);
            let on_delete = Callback::new(|_| {});
            let on_rename = Callback::new(|_| {});

            let html = view! {
                <PasskeyList
                    passkeys=passkeys_signal
                    on_delete=on_delete
                    on_rename=on_rename
                    pending=pending_signal
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("No registered passkeys yet."));
        });
    }

    #[test]
    fn test_mfa_status_disabled_state() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (totp_enabled, _) = signal(false);
            let (disable_pending, _) = signal(false);
            let (disable_result, _) = signal(None);
            let on_disable = Callback::new(|_| {});

            let html = view! {
                <MfaStatus
                    totp_enabled=totp_enabled
                    on_disable=on_disable
                    disable_pending=disable_pending
                    disable_result=disable_result
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("Disabled"));
            assert!(html.contains("To enable MFA, please complete the TOTP setup process."));
            assert!(!html.contains("Disable Multi-Factor Authentication"));
        });
    }

    #[test]
    fn test_mfa_status_pending_and_result() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (totp_enabled, _) = signal(true);
            let (disable_pending, _) = signal(true);
            let (disable_result, _) = signal(Some(Err("failed_to_disable".to_string())));
            let on_disable = Callback::new(|_| {});

            let html = view! {
                <MfaStatus
                    totp_enabled=totp_enabled
                    on_disable=on_disable
                    disable_pending=disable_pending
                    disable_result=disable_result
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("Disabling MFA..."));
            assert!(html.contains("failed_to_disable"));
        });
    }

    #[test]
    fn test_session_list_clamped_timestamp() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let sessions = vec![wasi_auth_traits::Session {
                session_id: "test-session-12345".to_string(),
                user_id: "user-1".to_string(),
                roles: vec![],
                expires_at: u64::MAX,
            }];
            let (sessions_signal, _) = signal(sessions);
            let (current_session_id, _) = signal(None);
            let (revoke_pending, _) = signal(false);
            let (revoke_result, _) = signal(None);
            let on_revoke = Callback::new(|_| {});

            let html = view! {
                <SessionList
                    sessions=sessions_signal
                    current_session_id=current_session_id
                    on_revoke=on_revoke
                    revoke_pending=revoke_pending
                    revoke_result=revoke_result
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("Expires: 9999-12-31 23:59:59 UTC"));
        });
    }

    #[cfg(feature = "passkey")]
    #[test]
    fn test_passkey_list_clamped_timestamp() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let passkeys = vec![wasi_auth_core::passkey::StoredPasskey {
                user_id: "user-1".to_string(),
                cred_id: "cred_1".to_string(),
                public_key: "dummy_pk".to_string(),
                name: "My Macbook".to_string(),
                created_at: i64::MAX,
                last_used_at: 0,
                counter: 0,
            }];
            let (passkeys_signal, _) = signal(passkeys);
            let (pending_signal, _) = signal(false);
            let on_delete = Callback::new(|_| {});
            let on_rename = Callback::new(|_| {});

            let html = view! {
                <PasskeyList
                    passkeys=passkeys_signal
                    on_delete=on_delete
                    on_rename=on_rename
                    pending=pending_signal
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("9999-12-31 23:59:59 UTC"));
        });
    }

    #[test]
    fn test_session_list_use_default_styles_false() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let sessions = vec![wasi_auth_traits::Session {
                session_id: "test-session-123".to_string(),
                user_id: "user-1".to_string(),
                roles: vec![],
                expires_at: 1700000000,
            }];
            let (sessions_signal, _) = signal(sessions);
            let (current_session_id, _) = signal(None);
            let (revoke_pending, _) = signal(false);
            let (revoke_result, _) = signal(None);
            let on_revoke = Callback::new(|_| {});

            let html = view! {
                <SessionList
                    use_default_styles=false
                    sessions=sessions_signal
                    current_session_id=current_session_id
                    on_revoke=on_revoke
                    revoke_pending=revoke_pending
                    revoke_result=revoke_result
                />
            }
            .into_view()
            .to_html();

            assert!(!html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[test]
    fn test_mfa_status_use_default_styles_false() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (totp_enabled, _) = signal(true);
            let (disable_pending, _) = signal(false);
            let (disable_result, _) = signal(None);
            let on_disable = Callback::new(|_| {});

            let html = view! {
                <MfaStatus
                    use_default_styles=false
                    totp_enabled=totp_enabled
                    on_disable=on_disable
                    disable_pending=disable_pending
                    disable_result=disable_result
                />
            }
            .into_view()
            .to_html();

            assert!(!html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[cfg(feature = "passkey")]
    #[test]
    fn test_passkey_list_use_default_styles_false() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let (passkeys_signal, _) = signal(vec![]);
            let (pending_signal, _) = signal(false);
            let on_delete = Callback::new(|_| {});
            let on_rename = Callback::new(|_| {});

            let html = view! {
                <PasskeyList
                    use_default_styles=false
                    passkeys=passkeys_signal
                    on_delete=on_delete
                    on_rename=on_rename
                    pending=pending_signal
                />
            }
            .into_view()
            .to_html();

            assert!(!html.contains("backdrop-filter: blur(16px)"));
        });
    }

    #[test]
    fn test_session_list_current_session_reactivity() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let sessions = vec![wasi_auth_traits::Session {
                session_id: "session-1".to_string(),
                user_id: "user-1".to_string(),
                roles: vec![],
                expires_at: 1700000000,
            }];
            let (sessions_signal, _) = signal(sessions);
            let (current_session_id, set_current_session_id) =
                signal(Some("session-1".to_string()));
            let (revoke_pending, _) = signal(false);
            let (revoke_result, _) = signal(None);
            let on_revoke = Callback::new(|_| {});

            let html_1 = view! {
                <SessionList
                    sessions=sessions_signal
                    current_session_id=current_session_id
                    on_revoke=on_revoke
                    revoke_pending=revoke_pending
                    revoke_result=revoke_result
                />
            }
            .into_view()
            .to_html();

            assert!(html_1.contains("Current"));

            set_current_session_id.set(Some("session-2".to_string()));

            let html_2 = view! {
                <SessionList
                    sessions=sessions_signal
                    current_session_id=current_session_id
                    on_revoke=on_revoke
                    revoke_pending=revoke_pending
                    revoke_result=revoke_result
                />
            }
            .into_view()
            .to_html();

            assert!(!html_2.contains("Current"));
        });
    }

    #[cfg(feature = "passkey")]
    #[test]
    fn test_passkey_list_disabled_during_pending() {
        init_executor();
        let owner = Owner::new();
        owner.with(|| {
            let passkeys = vec![wasi_auth_core::passkey::StoredPasskey {
                user_id: "user-1".to_string(),
                cred_id: "cred_1".to_string(),
                public_key: "dummy_pk".to_string(),
                name: "My Macbook".to_string(),
                created_at: 1700000000000,
                last_used_at: 0,
                counter: 0,
            }];
            let (passkeys_signal, _) = signal(passkeys);
            let (pending_signal, _) = signal(true);
            let on_delete = Callback::new(|_| {});
            let on_rename = Callback::new(|_| {});

            let html = view! {
                <PasskeyList
                    passkeys=passkeys_signal
                    on_delete=on_delete
                    on_rename=on_rename
                    pending=pending_signal
                />
            }
            .into_view()
            .to_html();

            assert!(html.contains("disabled"));
        });
    }
}
