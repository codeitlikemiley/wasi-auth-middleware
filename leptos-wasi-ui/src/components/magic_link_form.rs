use leptos::prelude::*;

const DEFAULT_CONTAINER_CLASS: &str = "wasi-auth-magic-link-form";
const DEFAULT_CONTAINER_STYLE: &str = "background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.3); border-radius: 12px; padding: 24px; color: #f9fafb; font-family: sans-serif; max-width: 400px; width: 100%; box-sizing: border-box;";

const DEFAULT_INPUT_CLASS: &str = "wasi-auth-input";
const DEFAULT_INPUT_STYLE: &str = "background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 6px; padding: 10px 12px; color: #fff; width: 100%; box-sizing: border-box; transition: all 0.2s ease-in-out; outline: none; margin-top: 6px; margin-bottom: 16px; font-size: 14px;";

const DEFAULT_BUTTON_CLASS: &str = "wasi-auth-button";
const DEFAULT_BUTTON_STYLE: &str = "background: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; padding: 10px 16px; color: #fff; cursor: pointer; transition: all 0.2s ease-in-out; font-weight: 500; width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px; font-size: 14px;";

#[component]
pub fn MagicLinkForm(
    #[prop(optional, into)] class: Option<TextProp>,
    #[prop(optional, into)] style: Option<TextProp>,
    // Make callback required to prevent silent failure
    on_request: Callback<String>,
    #[prop(into)] request_pending: Signal<bool>,
    #[prop(into)] request_result: Signal<Option<Result<String, String>>>,
    // Add option to bypass inline default styling
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

    let handle_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if request_pending.get() {
            return;
        }

        // Zero-allocation empty check using .with()
        email.with(|e| {
            if !e.trim().is_empty() {
                on_request.run(e.clone());
            }
        });
    };

    view! {
        <div class=merged_class style=merged_style>
            // Native hover/focus stylesheet (only if default styling is enabled)
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
                        "#}
                    </style>
                })
            } else {
                None
            }}

            <h2 style=h2_style>
                "Magic Link"
            </h2>
            <p style=p_style>
                "Enter your email to receive a passwordless login link."
            </p>

            <form on:submit=handle_submit>
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
                        disabled=request_pending // Leptos 0.8 handles Signal<bool> directly
                    />
                </div>

                <button
                    type="submit"
                    class=DEFAULT_BUTTON_CLASS
                    style=button_style
                    disabled=request_pending // Direct Signal<bool> binding
                >
                    {move || if request_pending.get() { "Sending link..." } else { "Send Magic Link" }}
                </button>
            </form>

            // Avoid cloning result strings by using .with()
            {move || {
                request_result.with(|res| {
                    res.as_ref().map(|inner| {
                        match inner {
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
    }
}
