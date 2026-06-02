use leptos::prelude::*;

const DEFAULT_CONTAINER_CLASS: &str = "wasi-auth-magic-link-form";
const DEFAULT_CONTAINER_STYLE: &str = "background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.3); border-radius: 12px; padding: 24px; color: #f9fafb; font-family: sans-serif; max-width: 400px; width: 100%; box-sizing: border-box;";

const DEFAULT_INPUT_CLASS: &str = "wasi-auth-input";
const DEFAULT_INPUT_STYLE: &str = "background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 6px; padding: 10px 12px; color: #fff; width: 100%; box-sizing: border-box; transition: all 0.2s ease-in-out; outline: none; margin-top: 6px; margin-bottom: 16px; font-size: 14px;";

const DEFAULT_BUTTON_CLASS: &str = "wasi-auth-button";
const DEFAULT_BUTTON_STYLE: &str = "background: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; padding: 10px 16px; color: #fff; cursor: pointer; transition: all 0.2s ease-in-out; font-weight: 500; width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px; font-size: 14px;";

#[component]
pub fn MagicLinkForm(
    #[prop(optional, into)] class: Option<String>,
    #[prop(optional, into)] style: Option<String>,
    #[prop(optional)] on_request: Option<Callback<String>>,
    #[prop(into)] request_pending: Signal<bool>,
    #[prop(into)] request_result: Signal<Option<Result<String, String>>>,
) -> impl IntoView {
    let merged_class = format!("{} {}", DEFAULT_CONTAINER_CLASS, class.unwrap_or_default());
    let merged_style = format!("{}; {}", DEFAULT_CONTAINER_STYLE, style.unwrap_or_default());

    let (email, set_email) = leptos::prelude::signal(String::new());

    let handle_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if request_pending.get() {
            return;
        }
        if let Some(ref cb) = on_request {
            let email_val = email.get();
            if !email_val.trim().is_empty() {
                cb.run(email_val);
            }
        }
    };

    view! {
        <div class=merged_class style=merged_style>
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

            <h2 style="margin-top: 0; margin-bottom: 8px; font-size: 20px; font-weight: 600; text-align: center;">
                "Magic Link"
            </h2>
            <p style="margin-top: 0; margin-bottom: 20px; font-size: 14px; color: rgba(255, 255, 255, 0.6); text-align: center;">
                "Enter your email to receive a passwordless login link."
            </p>

            <form on:submit=handle_submit>
                <div style="display: flex; flex-direction: column; align-items: flex-start; width: 100%;">
                    <label style="font-size: 12px; font-weight: 500; color: rgba(255, 255, 255, 0.8);">
                        "Email Address"
                    </label>
                    <input
                        type="email"
                        placeholder="email@example.com"
                        class=DEFAULT_INPUT_CLASS
                        style=DEFAULT_INPUT_STYLE
                        required
                        prop:value=email
                        on:input=move |ev| set_email.set(event_target_value(&ev))
                        disabled=move || request_pending.get()
                    />
                </div>

                <button
                    type="submit"
                    class=DEFAULT_BUTTON_CLASS
                    style=DEFAULT_BUTTON_STYLE
                    disabled=move || request_pending.get()
                >
                    {move || if request_pending.get() { "Sending link..." } else { "Send Magic Link" }}
                </button>
            </form>

            {move || {
                request_result.get().map(|res| {
                    match res {
                        Ok(msg) => view! {
                            <div style="margin-top: 16px; padding: 10px 12px; border-radius: 6px; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); color: #34d399; font-size: 13px; text-align: center;">
                                {msg}
                            </div>
                        }.into_any(),
                        Err(err) => view! {
                            <div style="margin-top: 16px; padding: 10px 12px; border-radius: 6px; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); color: #f87171; font-size: 13px; text-align: center;">
                                {err}
                            </div>
                        }.into_any()
                    }
                })
            }}
        </div>
    }
}
