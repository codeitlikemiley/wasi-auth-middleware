use leptos::prelude::*;

const DEFAULT_CONTAINER_CLASS: &str = "wasi-auth-mfa-status";
const DEFAULT_CONTAINER_STYLE: &str = "background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.3); border-radius: 12px; padding: 24px; color: #f9fafb; font-family: sans-serif; max-width: 440px; width: 100%; box-sizing: border-box;";

const DEFAULT_BUTTON_CLASS: &str = "wasi-auth-button wasi-auth-button-danger";
const DEFAULT_BUTTON_STYLE: &str = "background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 6px; padding: 10px 16px; color: #f87171; cursor: pointer; transition: all 0.2s ease-in-out; font-weight: 500; width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px; font-size: 14px;";

const DEFAULT_BADGE_STYLE_ENABLED: &str = "background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); color: #34d399; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 4px; margin-bottom: 16px;";
const DEFAULT_BADGE_STYLE_DISABLED: &str = "background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); color: #f87171; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 4px; margin-bottom: 16px;";

#[component]
pub fn MfaStatus(
    #[prop(optional, into)] class: Option<TextProp>,
    #[prop(optional, into)] style: Option<TextProp>,
    #[prop(into)] totp_enabled: Signal<bool>,
    #[prop(optional)] on_disable: Option<Callback<()>>,
    #[prop(into)] disable_pending: Signal<bool>,
    #[prop(into)] disable_result: Signal<Option<Result<(), String>>>,
    #[prop(optional, default = true)] use_default_styles: bool,
) -> impl IntoView {
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

    let h2_style = move || {
        if use_default_styles {
            "margin-top: 0; margin-bottom: 8px; font-size: 20px; font-weight: 600; text-align: center;"
        } else {
            ""
        }
    };

    let p_style = move || {
        if use_default_styles {
            "margin-top: 0; margin-bottom: 20px; font-size: 14px; color: rgba(255, 255, 255, 0.6); text-align: center; line-height: 1.5;"
        } else {
            ""
        }
    };

    let badge_style = move || {
        if use_default_styles {
            if totp_enabled.get() {
                DEFAULT_BADGE_STYLE_ENABLED
            } else {
                DEFAULT_BADGE_STYLE_DISABLED
            }
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

    let handle_disable = move |_| {
        if disable_pending.get() {
            return;
        }
        if let Some(ref cb) = on_disable {
            cb.run(());
        }
    };

    view! {
        <div class=merged_class style=merged_style>
            {if use_default_styles {
                Some(view! {
                    <style>
                        {r#"
                        .wasi-auth-button-danger:hover:not(:disabled) {
                            background: rgba(239, 68, 68, 0.25) !important;
                            border-color: rgba(239, 68, 68, 0.35) !important;
                        }
                        .wasi-auth-button-danger:disabled {
                            opacity: 0.5;
                            cursor: not-allowed;
                        }
                        "#}
                    </style>
                })
            } else {
                None
            }}

            <div style="display: flex; flex-direction: column; align-items: center; text-align: center;">
                <h2 style=h2_style>
                    "Multi-Factor Authentication"
                </h2>

                // Status Badge
                <div style=badge_style>
                    {move || if totp_enabled.get() {
                        view! {
                            <>
                                <span style="display: inline-block; width: 8px; height: 8px; background-color: #10b981; border-radius: 50%; margin-right: 4px;"></span>
                                "Enabled"
                            </>
                        }.into_any()
                    } else {
                        view! {
                            <>
                                <span style="display: inline-block; width: 8px; height: 8px; background-color: #ef4444; border-radius: 50%; margin-right: 4px;"></span>
                                "Disabled"
                            </>
                        }.into_any()
                    }}
                </div>

                // Large Decorative Icon (Shield)
                {move || if totp_enabled.get() {
                    view! {
                        <svg fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="width: 48px; height: 48px; margin-bottom: 16px; color: #34d399;" xmlns="http://www.w3.org/2000/svg">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                        </svg>
                    }.into_any()
                } else {
                    view! {
                        <svg fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="width: 48px; height: 48px; margin-bottom: 16px; color: #f87171;" xmlns="http://www.w3.org/2000/svg">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.248-8.25-3.285zM12 17h.008v.008H12V17z" />
                        </svg>
                    }.into_any()
                }}

                // Status Description
                <p style=p_style>
                    {move || if totp_enabled.get() {
                        "Multi-Factor Authentication (MFA) adds an extra layer of security to your account by requiring a verification code when you sign in. Your account is currently protected."
                    } else {
                        "Multi-Factor Authentication (MFA) is currently disabled. We strongly recommend enabling TOTP MFA to prevent unauthorized access to your account."
                    }}
                </p>

                // Action Button / Setup Prompt
                {move || if totp_enabled.get() {
                    view! {
                        <div style="width: 100%;">
                            <button
                                type="button"
                                class=DEFAULT_BUTTON_CLASS
                                style=button_style
                                on:click=handle_disable
                                disabled=move || disable_pending.get() || on_disable.is_none()
                            >
                                {move || if disable_pending.get() {
                                    "Disabling MFA..."
                                } else {
                                    "Disable Multi-Factor Authentication"
                                }}
                            </button>
                        </div>
                    }.into_any()
                } else {
                    view! {
                        <div style="font-size: 13px; color: rgba(255, 255, 255, 0.4); font-style: italic;">
                            "To enable MFA, please complete the TOTP setup process."
                        </div>
                    }.into_any()
                }}

                // Feedback Alert Boxes
                {move || {
                    disable_result.with(|res| {
                        res.as_ref().map(|r| {
                            match r {
                                Ok(_) => view! {
                                    <div style=success_box_style>
                                        "MFA has been successfully disabled."
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
        </div>
    }
}
