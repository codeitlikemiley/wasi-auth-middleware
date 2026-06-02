use leptos::prelude::*;

const DEFAULT_CONTAINER_CLASS: &str = "wasi-auth-login-form";
const DEFAULT_CONTAINER_STYLE: &str = "background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.3); border-radius: 12px; padding: 24px; color: #f9fafb; font-family: sans-serif; max-width: 440px; width: 100%; box-sizing: border-box;";

const DEFAULT_INPUT_CLASS: &str = "wasi-auth-input";
const DEFAULT_INPUT_STYLE: &str = "background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 6px; padding: 10px 12px; color: #fff; width: 100%; box-sizing: border-box; transition: all 0.2s ease-in-out; outline: none; margin-top: 6px; margin-bottom: 16px; font-size: 14px;";

const DEFAULT_BUTTON_CLASS: &str = "wasi-auth-button";
const DEFAULT_BUTTON_STYLE: &str = "background: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; padding: 10px 16px; color: #fff; cursor: pointer; transition: all 0.2s ease-in-out; font-weight: 500; width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px; font-size: 14px;";

#[derive(Clone, Debug)]
pub struct OtpVerification {
    pub email: String,
    pub code: String,
}

#[derive(Clone, Debug)]
pub struct TotpVerification {
    pub email: String,
    pub code: String,
}

#[component]
pub fn LoginForm(
    #[prop(optional, into)] class: Option<TextProp>,
    #[prop(optional, into)] style: Option<TextProp>,
    #[prop(optional, into)] initial_email: Option<String>,
    #[prop(optional)] on_submit_otp: Option<Callback<OtpVerification>>,
    #[prop(optional)] on_request_otp: Option<Callback<String>>,
    #[prop(optional)] on_request_magic_link: Option<Callback<String>>,
    #[prop(optional)] on_verify_totp: Option<Callback<TotpVerification>>,
    #[prop(into)] request_otp_pending: Signal<bool>,
    #[prop(into)] request_otp_result: Signal<Option<Result<String, String>>>,
    #[prop(into)] verify_otp_pending: Signal<bool>,
    #[prop(into)] verify_otp_result: Signal<Option<Result<bool, String>>>,
    #[prop(into)] request_magic_link_pending: Signal<bool>,
    #[prop(into)] request_magic_link_result: Signal<Option<Result<String, String>>>,
    #[prop(into)] verify_totp_pending: Signal<bool>,
    #[prop(into)] verify_totp_result: Signal<Option<Result<bool, String>>>,
    #[prop(optional)] show_passkey: Option<bool>,
    #[prop(optional)] on_passkey_login: Option<Callback<()>>,
    #[prop(into)] passkey_login_pending: Signal<bool>,
    #[prop(optional)] show_oauth: Option<bool>,
    #[prop(optional, default = true)] use_default_styles: bool,
) -> impl IntoView {
    let (active_tab, set_active_tab) = leptos::prelude::signal(1); // 1 = OTP, 2 = Magic Link, 3 = TOTP
    let (email, set_email) = leptos::prelude::signal(initial_email.unwrap_or_default());
    let (otp_code, set_otp_code) = leptos::prelude::signal(String::new());
    let (totp_code, set_totp_code) = leptos::prelude::signal(String::new());
    let (otp_step, set_otp_step) = leptos::prelude::signal(1); // 1 = Request, 2 = Verify

    let merged_class = move || {
        let user_class = class
            .as_ref()
            .map(|c| format!(" {}", c.get()))
            .unwrap_or_default();
        format!("{}{}", DEFAULT_CONTAINER_CLASS, user_class)
    };
    let merged_style = move || {
        if use_default_styles {
            let user_style = style
                .as_ref()
                .map(|s| format!("; {}", s.get()))
                .unwrap_or_default();
            format!("{}{}", DEFAULT_CONTAINER_STYLE, user_style)
        } else {
            style
                .as_ref()
                .map(|s| s.get().to_string())
                .unwrap_or_default()
        }
    };

    let input_style = move || {
        if use_default_styles {
            DEFAULT_INPUT_STYLE
        } else {
            ""
        }
    };
    let button_style = move || {
        if use_default_styles {
            DEFAULT_BUTTON_STYLE
        } else {
            ""
        }
    };
    let label_style = move || {
        if use_default_styles {
            "font-size: 12px; font-weight: 500; color: rgba(255, 255, 255, 0.8);"
        } else {
            ""
        }
    };
    let secondary_button_style = move || {
        if use_default_styles {
            "margin-top: 10px; background: transparent; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 6px; padding: 10px 16px; color: rgba(255, 255, 255, 0.7); cursor: pointer; transition: all 0.2s ease-in-out; font-weight: 500; width: 100%; font-size: 14px;"
        } else {
            ""
        }
    };
    let h2_style = move || {
        if use_default_styles {
            "margin-top: 0; margin-bottom: 16px; font-size: 22px; font-weight: 600; text-align: center;"
        } else {
            ""
        }
    };
    let tab_bar_style = move || {
        if use_default_styles {
            "display: flex; border-bottom: 1px solid rgba(255, 255, 255, 0.1); margin-bottom: 20px;"
        } else {
            ""
        }
    };
    let form_field_style = move || {
        if use_default_styles {
            "display: flex; flex-direction: column; align-items: flex-start; width: 100%;"
        } else {
            ""
        }
    };
    let verify_text_style = move || {
        if use_default_styles {
            "margin-top: 0; margin-bottom: 16px; font-size: 13px; color: rgba(255, 255, 255, 0.6); text-align: center;"
        } else {
            ""
        }
    };
    let email_highlight_style = move || {
        if use_default_styles {
            "color: #fff; font-weight: 500;"
        } else {
            ""
        }
    };
    let divider_style = move || {
        if use_default_styles {
            "display: flex; align-items: center; margin-top: 24px; margin-bottom: 16px;"
        } else {
            ""
        }
    };
    let divider_line_style = move || {
        if use_default_styles {
            "flex: 1; height: 1px; background: rgba(255, 255, 255, 0.1);"
        } else {
            ""
        }
    };
    let divider_text_style = move || {
        if use_default_styles {
            "font-size: 12px; color: rgba(255, 255, 255, 0.4); padding: 0 8px;"
        } else {
            ""
        }
    };
    let passkey_btn_style = move || {
        if use_default_styles {
            "background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; padding: 10px 16px; color: #fff; cursor: pointer; transition: all 0.2s ease-in-out; font-weight: 500; width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px; font-size: 14px;"
        } else {
            ""
        }
    };
    let oauth_text_style = move || {
        if use_default_styles {
            "font-size: 11px; color: rgba(255, 255, 255, 0.4); padding: 0 8px; text-transform: uppercase; letter-spacing: 0.05em;"
        } else {
            ""
        }
    };
    let oauth_btn_style = move || {
        if use_default_styles {
            "background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; padding: 10px 12px; color: #fff; cursor: pointer; transition: all 0.2s ease-in-out; font-weight: 500; flex: 1; display: flex; align-items: center; justify-content: center; gap: 8px; font-size: 13px;"
        } else {
            ""
        }
    };
    let oauth_container_style = move || {
        if use_default_styles {
            "display: flex; gap: 12px;"
        } else {
            ""
        }
    };
    let error_box_style = move || {
        if use_default_styles {
            "margin-top: 16px; padding: 10px 12px; border-radius: 6px; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); color: #f87171; font-size: 13px; text-align: center;"
        } else {
            ""
        }
    };
    let success_box_style = move || {
        if use_default_styles {
            "margin-top: 16px; padding: 10px 12px; border-radius: 6px; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); color: #34d399; font-size: 13px; text-align: center;"
        } else {
            ""
        }
    };

    let tab_button_style = move |tab_id: i32| {
        move || {
            if use_default_styles {
                let is_active = active_tab.get() == tab_id;
                format!(
                    "background: transparent; border: none; border-bottom: 2px solid {}; padding: 10px 12px; color: {}; font-weight: 500; font-size: 14px; cursor: pointer; flex: 1; transition: all 0.2s;",
                    if is_active { "#fff" } else { "transparent" },
                    if is_active {
                        "#fff"
                    } else {
                        "rgba(255,255,255,0.5)"
                    }
                )
            } else {
                "".to_string()
            }
        }
    };

    // Automatically transition to OTP code verification once requested successfully
    Effect::new(move |_| {
        request_otp_result.with(|res| {
            if let Some(Ok(_)) = res {
                set_otp_step.set(2);
            }
        });
    });

    let handle_request_otp = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if request_otp_pending.get() {
            return;
        }
        if let Some(ref cb) = on_request_otp {
            email.with(|email_val| {
                if !email_val.trim().is_empty() {
                    cb.run(email_val.clone());
                }
            });
        }
    };

    let handle_verify_otp = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if verify_otp_pending.get() {
            return;
        }
        if let Some(ref cb) = on_submit_otp {
            let is_valid =
                email.with(|e| !e.trim().is_empty()) && otp_code.with(|c| !c.trim().is_empty());
            if is_valid {
                cb.run(OtpVerification {
                    email: email.get(),
                    code: otp_code.get(),
                });
            }
        }
    };

    let handle_request_magic_link = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if request_magic_link_pending.get() {
            return;
        }
        if let Some(ref cb) = on_request_magic_link {
            email.with(|email_val| {
                if !email_val.trim().is_empty() {
                    cb.run(email_val.clone());
                }
            });
        }
    };

    let handle_verify_totp = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if verify_totp_pending.get() {
            return;
        }
        if let Some(ref cb) = on_verify_totp {
            let is_valid =
                email.with(|e| !e.trim().is_empty()) && totp_code.with(|c| !c.trim().is_empty());
            if is_valid {
                cb.run(TotpVerification {
                    email: email.get(),
                    code: totp_code.get(),
                });
            }
        }
    };

    let handle_back_otp = move |_| {
        set_otp_step.set(1);
        set_otp_code.set(String::new());
    };

    let display_passkey = show_passkey.unwrap_or(true);

    view! {
        <div class=merged_class style=merged_style>
            {if use_default_styles {
                Some(view! {
                    <style>
                        {r#"
                        .wasi-auth-input:focus {
                            border-color: rgba(255, 255, 255, 0.3) !important;
                            background: rgba(255, 255, 255, 0.08) !important;
                            box-shadow: 0 0 0 2px rgba(255, 255, 255, 0.05);
                        }
                        .wasi-auth-button:hover {
                            background: rgba(255, 255, 255, 0.15) !important;
                            border-color: rgba(255, 255, 255, 0.25) !important;
                        }
                        .wasi-auth-button:disabled {
                            opacity: 0.5;
                            cursor: not-allowed;
                        }
                        .wasi-auth-oauth-button:hover {
                            background: rgba(255, 255, 255, 0.1) !important;
                            border-color: rgba(255, 255, 255, 0.2) !important;
                        }
                        .wasi-auth-secondary-button:hover {
                            background: rgba(255, 255, 255, 0.08) !important;
                            border-color: rgba(255, 255, 255, 0.2) !important;
                        }
                        "#}
                    </style>
                })
            } else {
                None
            }}

            <h2 style=h2_style>
                "Sign In"
            </h2>

            // Tab bar
            <div style=tab_bar_style>
                <button
                    type="button"
                    style=tab_button_style(1)
                    on:click=move |_| set_active_tab.set(1)
                >
                    "Email OTP"
                </button>
                <button
                    type="button"
                    style=tab_button_style(2)
                    on:click=move |_| set_active_tab.set(2)
                >
                    "Magic Link"
                </button>
                <button
                    type="button"
                    style=tab_button_style(3)
                    on:click=move |_| set_active_tab.set(3)
                >
                    "MFA TOTP"
                </button>
            </div>

            // Active Tab Content
            {move || match active_tab.get() {
                1 => {
                    if otp_step.get() == 1 {
                        view! {
                            <div>
                                <form on:submit=handle_request_otp>
                                    <div style=form_field_style>
                                        <label style=label_style>
                                            "Email Address"
                                        </label>
                                        <input
                                            type="email"
                                            placeholder="email@example.com"
                                            class=DEFAULT_INPUT_CLASS
                                            style=input_style
                                            required
                                            prop:value=email
                                            on:input=move |ev| set_email.set(event_target_value(&ev))
                                            disabled=move || request_otp_pending.get()
                                        />
                                    </div>

                                    <button
                                        type="submit"
                                        class=DEFAULT_BUTTON_CLASS
                                        style=button_style
                                        disabled=move || request_otp_pending.get()
                                    >
                                        {move || if request_otp_pending.get() { "Sending code..." } else { "Send OTP Code" }}
                                    </button>
                                </form>

                                {move || {
                                    request_otp_result.with(|res| {
                                        res.as_ref().and_then(|r| {
                                            if let Err(err) = r {
                                                Some(view! {
                                                    <div style=error_box_style>
                                                        {err.clone()}
                                                    </div>
                                                }.into_any())
                                            } else {
                                                None
                                            }
                                        })
                                    })
                                }}
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div>
                                <p style=verify_text_style>
                                    "Enter the verification code sent to "<span style=email_highlight_style>{email}</span>
                                </p>
                                <form on:submit=handle_verify_otp>
                                    <div style=form_field_style>
                                        <label style=label_style>
                                            "Verification Code"
                                        </label>
                                        <input
                                            type="text"
                                            placeholder="123456"
                                            class=DEFAULT_INPUT_CLASS
                                            style=input_style
                                            required
                                            prop:value=otp_code
                                            on:input=move |ev| set_otp_code.set(event_target_value(&ev))
                                            disabled=move || verify_otp_pending.get()
                                        />
                                    </div>

                                    <button
                                        type="submit"
                                        class=DEFAULT_BUTTON_CLASS
                                        style=button_style
                                        disabled=move || verify_otp_pending.get()
                                    >
                                        {move || if verify_otp_pending.get() { "Verifying..." } else { "Verify Code" }}
                                    </button>

                                    <button
                                        type="button"
                                        class="wasi-auth-secondary-button"
                                        style=secondary_button_style
                                        on:click=handle_back_otp
                                        disabled=move || verify_otp_pending.get()
                                    >
                                        "Change Email / Go Back"
                                    </button>
                                </form>

                                {move || {
                                    verify_otp_result.with(|res| {
                                        res.as_ref().map(|r| {
                                            match r {
                                                Ok(success) => {
                                                    if *success {
                                                        view! {
                                                            <div style=success_box_style>
                                                                "Verification successful!"
                                                            </div>
                                                        }.into_any()
                                                    } else {
                                                        view! {
                                                            <div style=error_box_style>
                                                                "Invalid OTP code. Please try again."
                                                            </div>
                                                        }.into_any()
                                                    }
                                                }
                                                Err(err) => view! {
                                                    <div style=error_box_style>
                                                        {err.clone()}
                                                    </div>
                                                }.into_any()
                                            }
                                        })
                                    })
                                }}
                            </div>
                        }.into_any()
                    }
                }
                2 => {
                    view! {
                        <div>
                            <form on:submit=handle_request_magic_link>
                                <div style=form_field_style>
                                    <label style=label_style>
                                        "Email Address"
                                    </label>
                                    <input
                                        type="email"
                                        placeholder="email@example.com"
                                        class=DEFAULT_INPUT_CLASS
                                        style=input_style
                                        required
                                        prop:value=email
                                        on:input=move |ev| set_email.set(event_target_value(&ev))
                                        disabled=move || request_magic_link_pending.get()
                                    />
                                </div>

                                <button
                                    type="submit"
                                    class=DEFAULT_BUTTON_CLASS
                                    style=button_style
                                    disabled=move || request_magic_link_pending.get()
                                >
                                    {move || if request_magic_link_pending.get() { "Sending link..." } else { "Send Magic Link" }}
                                </button>
                            </form>

                            {move || {
                                request_magic_link_result.with(|res| {
                                    res.as_ref().map(|r| {
                                        match r {
                                            Ok(msg) => view! {
                                                <div style=success_box_style>
                                                    {msg.clone()}
                                                </div>
                                            }.into_any(),
                                            Err(err) => view! {
                                                <div style=error_box_style>
                                                    {err.clone()}
                                                </div>
                                            }.into_any()
                                        }
                                    })
                                })
                            }}
                        </div>
                    }.into_any()
                }
                3 => {
                    view! {
                        <div>
                            <form on:submit=handle_verify_totp>
                                <div style=form_field_style>
                                    <label style=label_style>
                                        "Email Address"
                                    </label>
                                    <input
                                        type="email"
                                        placeholder="email@example.com"
                                        class=DEFAULT_INPUT_CLASS
                                        style=input_style
                                        required
                                        prop:value=email
                                        on:input=move |ev| set_email.set(event_target_value(&ev))
                                        disabled=move || verify_totp_pending.get()
                                    />
                                </div>
                                <div style=form_field_style>
                                    <label style=label_style>
                                        "MFA Authenticator Code"
                                    </label>
                                    <input
                                        type="text"
                                        placeholder="123456"
                                        class=DEFAULT_INPUT_CLASS
                                        style=input_style
                                        required
                                        prop:value=totp_code
                                        on:input=move |ev| set_totp_code.set(event_target_value(&ev))
                                        disabled=move || verify_totp_pending.get()
                                    />
                                </div>

                                <button
                                    type="submit"
                                    class=DEFAULT_BUTTON_CLASS
                                    style=button_style
                                    disabled=move || verify_totp_pending.get()
                                >
                                    {move || if verify_totp_pending.get() { "Verifying..." } else { "Verify & Sign In" }}
                                </button>
                            </form>

                            {move || {
                                verify_totp_result.with(|res| {
                                    res.as_ref().map(|r| {
                                        match r {
                                            Ok(success) => {
                                                if *success {
                                                    view! {
                                                        <div style=success_box_style>
                                                            "TOTP login successful!"
                                                        </div>
                                                    }.into_any()
                                                } else {
                                                    view! {
                                                        <div style=error_box_style>
                                                            "Invalid TOTP code. Please try again."
                                                        </div>
                                                    }.into_any()
                                                }
                                            }
                                            Err(err) => view! {
                                                <div style=error_box_style>
                                                    {err.clone()}
                                                </div>
                                            }.into_any()
                                        }
                                    })
                                })
                            }}
                        </div>
                    }.into_any()
                }
                _ => leptos::prelude::IntoView::into_view(()).into_any()
            }}

            // Passkey option
            {move || if display_passkey {
                view! {
                    <div>
                        <div style=divider_style>
                            <div style=divider_line_style></div>
                            <span style=divider_text_style>"OR"</span>
                            <div style=divider_line_style></div>
                        </div>

                        <button
                            type="button"
                            class="wasi-auth-passkey-login-button"
                            style=passkey_btn_style
                            disabled=move || passkey_login_pending.get()
                            on:click=move |_| {
                                if let Some(ref cb) = on_passkey_login {
                                    cb.run(());
                                }
                            }
                        >
                            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width: 18px; height: 18px; flex-shrink: 0;" xmlns="http://www.w3.org/2000/svg">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 009 11a5 5 0 00-10 0c0 1.05.15 2.07.433 3.036l.64 2.222A3.01 3.01 0 003 18.11V21h3v-2.89a3 3 0 01.378-1.468z" />
                                <path stroke-linecap="round" stroke-linejoin="round" d="M12 11c0-3.517 1.009-6.799 2.753-9.571m-3.44 2.04l-.054.09A13.916 13.916 0 0015 11a5 5 0 0010 0c0-1.05-.15-2.07-.433-3.036l-.64-2.222A3.01 3.01 0 0021 5.89V3h-3v2.89a3 3 0 01-.378 1.468z" />
                            </svg>
                            {move || if passkey_login_pending.get() { "Starting Passkey..." } else { "Login with Passkey" }}
                        </button>
                    </div>
                }.into_any()
            } else {
                leptos::prelude::IntoView::into_view(()).into_any()
            }}

            // OAuth2 option title and buttons
            {move || if show_oauth.unwrap_or(true) {
                view! {
                    <div style=divider_style>
                        <div style=divider_line_style></div>
                        <span style=oauth_text_style>"Sign in with"</span>
                        <div style=divider_line_style></div>
                    </div>

                    <div style=oauth_container_style>
                        <button
                            type="button"
                            class="wasi-auth-oauth-button"
                            style=oauth_btn_style
                        >
                            <svg fill="currentColor" viewBox="0 0 24 24" style="width: 16px; height: 16px; flex-shrink: 0;" xmlns="http://www.w3.org/2000/svg">
                                <path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.48 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.577.688.479C19.137 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
                            </svg>
                            "GitHub"
                        </button>
                        <button
                            type="button"
                            class="wasi-auth-oauth-button"
                            style=oauth_btn_style
                        >
                            <svg viewBox="0 0 24 24" fill="currentColor" style="width: 16px; height: 16px; flex-shrink: 0;" xmlns="http://www.w3.org/2000/svg">
                                <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
                                <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
                                <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" fill="#FBBC05" />
                                <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" fill="#EA4335" />
                            </svg>
                            "Google"
                        </button>
                    </div>
                }.into_any()
            } else {
                leptos::prelude::IntoView::into_view(()).into_any()
            }}
        </div>
    }
}
