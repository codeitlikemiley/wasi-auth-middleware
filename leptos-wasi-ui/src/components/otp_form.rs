use leptos::prelude::*;

const DEFAULT_CONTAINER_CLASS: &str = "wasi-auth-otp-form";
const DEFAULT_CONTAINER_STYLE: &str = "background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.3); border-radius: 12px; padding: 24px; color: #f9fafb; font-family: sans-serif; max-width: 400px; width: 100%; box-sizing: border-box;";

const DEFAULT_INPUT_CLASS: &str = "wasi-auth-input";
const DEFAULT_INPUT_STYLE: &str = "background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 6px; padding: 10px 12px; color: #fff; width: 100%; box-sizing: border-box; transition: all 0.2s ease-in-out; outline: none; margin-top: 6px; margin-bottom: 16px; font-size: 14px;";

const DEFAULT_BUTTON_CLASS: &str = "wasi-auth-button";
const DEFAULT_BUTTON_STYLE: &str = "background: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; padding: 10px 16px; color: #fff; cursor: pointer; transition: all 0.2s ease-in-out; font-weight: 500; width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px; font-size: 14px;";

#[component]
pub fn OtpForm(
    #[prop(optional, into)] class: Option<TextProp>,
    #[prop(optional, into)] style: Option<TextProp>,
    // Required callbacks to avoid silent failures
    on_request: Callback<String>,
    on_verify: Callback<(String, String)>,
    #[prop(into)] request_pending: Signal<bool>,
    #[prop(into)] request_result: Signal<Option<Result<String, String>>>,
    #[prop(into)] verify_pending: Signal<bool>,
    #[prop(into)] verify_result: Signal<Option<Result<bool, String>>>,
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
            "margin-top: 0; margin-bottom: 20px; font-size: 14px; color: rgba(255, 255, 255, 0.6); text-align: center;"
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
    let label_style = move || {
        if use_default_styles {
            "font-size: 12px; font-weight: 500; color: rgba(255, 255, 255, 0.8);"
        } else {
            ""
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
    let secondary_button_style = move || {
        if use_default_styles {
            "margin-top: 10px; background: transparent; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 6px; padding: 10px 16px; color: rgba(255, 255, 255, 0.7); cursor: pointer; transition: all 0.2s ease-in-out; font-weight: 500; width: 100%; font-size: 14px;"
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
    let success_box_style = move || {
        if use_default_styles {
            "margin-top: 16px; padding: 10px 12px; border-radius: 6px; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); color: #34d399; font-size: 13px; text-align: center;"
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

    let (email, set_email) = leptos::prelude::signal(String::new());
    let (code, set_code) = leptos::prelude::signal(String::new());
    let (step, set_step) = leptos::prelude::signal(1); // 1 = Request, 2 = Verify

    // Transition dynamically to verification step using borrowed .with check
    Effect::new(move |_| {
        if request_result.with(|res| matches!(res, Some(Ok(_)))) {
            set_step.set(2);
        }
    });

    let handle_request = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if request_pending.get() {
            return;
        }

        email.with(|e| {
            if !e.trim().is_empty() {
                on_request.run(e.clone());
            }
        });
    };

    let handle_verify = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if verify_pending.get() {
            return;
        }

        email.with(|e| {
            code.with(|c| {
                if !e.trim().is_empty() && !c.trim().is_empty() {
                    on_verify.run((e.clone(), c.clone()));
                }
            })
        });
    };

    let handle_back = move |_| {
        set_step.set(1);
        set_code.set(String::new());
    };

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
                "One-Time Password"
            </h2>

            {move || if step.get() == 1 {
                view! {
                    <div>
                        <p style=p_style>
                            "Enter your email to request a login verification code."
                        </p>

                        <form on:submit=handle_request>
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
                                    disabled=request_pending
                                />
                            </div>

                            <button
                                type="submit"
                                class=DEFAULT_BUTTON_CLASS
                                style=button_style
                                disabled=request_pending
                            >
                                {move || if request_pending.get() { "Sending code..." } else { "Send OTP Code" }}
                            </button>
                        </form>

                        {move || {
                            request_result.with(|res| {
                                res.as_ref().and_then(|inner| {
                                    if let Err(err) = inner {
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
                        <p style=p_style>
                            "Enter the verification code sent to "<span style=email_highlight_style>{email}</span>
                        </p>

                        <form on:submit=handle_verify>
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
                                    prop:value=code
                                    on:input=move |ev| set_code.set(event_target_value(&ev))
                                    disabled=verify_pending
                                />
                            </div>

                            <button
                                type="submit"
                                class=DEFAULT_BUTTON_CLASS
                                style=button_style
                                disabled=verify_pending
                            >
                                {move || if verify_pending.get() { "Verifying..." } else { "Verify Code" }}
                            </button>

                            <button
                                type="button"
                                class="wasi-auth-secondary-button"
                                style=secondary_button_style
                                on:click=handle_back
                                disabled=verify_pending
                            >
                                "Change Email / Go Back"
                            </button>
                        </form>

                        {move || {
                            verify_result.with(|res| {
                                res.as_ref().map(|inner| {
                                    match inner {
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
                                                        "Invalid verification code. Please try again."
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
            }}
        </div>
    }
}
