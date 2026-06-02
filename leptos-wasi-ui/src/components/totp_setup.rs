use leptos::prelude::*;

const DEFAULT_CONTAINER_CLASS: &str = "wasi-auth-totp-setup";
const DEFAULT_CONTAINER_STYLE: &str = "background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.3); border-radius: 12px; padding: 24px; color: #f9fafb; font-family: sans-serif; max-width: 440px; width: 100%; box-sizing: border-box;";

const DEFAULT_INPUT_CLASS: &str = "wasi-auth-input";
const DEFAULT_INPUT_STYLE: &str = "background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 6px; padding: 10px 12px; color: #fff; width: 100%; box-sizing: border-box; transition: all 0.2s ease-in-out; outline: none; margin-top: 6px; margin-bottom: 16px; font-size: 14px;";

const DEFAULT_BUTTON_CLASS: &str = "wasi-auth-button";
const DEFAULT_BUTTON_STYLE: &str = "background: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; padding: 10px 16px; color: #fff; cursor: pointer; transition: all 0.2s ease-in-out; font-weight: 500; width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px; font-size: 14px;";

#[component]
pub fn TotpSetup(
    #[prop(optional, into)] class: Option<String>,
    #[prop(optional, into)] style: Option<String>,
    #[prop(into)] uri: Signal<Option<String>>,
    #[prop(optional)] on_setup: Option<Callback<String>>,
    #[prop(optional)] on_verify: Option<Callback<(String, String)>>,
    #[prop(into)] setup_pending: Signal<bool>,
    #[prop(into)] setup_result: Signal<Option<Result<String, String>>>,
    #[prop(into)] verify_pending: Signal<bool>,
    #[prop(into)] verify_result: Signal<Option<Result<bool, String>>>,
) -> impl IntoView {
    let merged_class = format!("{} {}", DEFAULT_CONTAINER_CLASS, class.unwrap_or_default());
    let merged_style = format!("{}; {}", DEFAULT_CONTAINER_STYLE, style.unwrap_or_default());

    let (email, set_email) = leptos::prelude::signal(String::new());
    let (code, set_code) = leptos::prelude::signal(String::new());
    let (step, set_step) = leptos::prelude::signal(1); // 1 = Initialize, 2 = Verify

    // Automatically transition to setup display / verification once initiated
    Effect::new(move |_| {
        if uri.get().is_some() || setup_result.get().is_some() {
            set_step.set(2);
        }
    });

    let secret_key = move || {
        if let Some(Ok(ref sec)) = setup_result.get() {
            Some(sec.clone())
        } else if let Some(ref uri_str) = uri.get() {
            if let Some(pos) = uri_str.find("secret=") {
                let start = pos + 7;
                let end = uri_str[start..]
                    .find('&')
                    .map(|p| start + p)
                    .unwrap_or(uri_str.len());
                Some(uri_str[start..end].to_string())
            } else {
                None
            }
        } else {
            None
        }
    };

    let handle_setup = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if setup_pending.get() {
            return;
        }
        if let Some(ref cb) = on_setup {
            let email_val = email.get();
            if !email_val.trim().is_empty() {
                cb.run(email_val);
            }
        }
    };

    let handle_verify = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if verify_pending.get() {
            return;
        }
        if let Some(ref cb) = on_verify {
            let email_val = email.get();
            let code_val = code.get();
            if !email_val.trim().is_empty() && !code_val.trim().is_empty() {
                cb.run((email_val, code_val));
            }
        }
    };

    let handle_back = move |_| {
        set_step.set(1);
        set_code.set(String::new());
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
                .wasi-auth-secondary-button:hover {
                    background: rgba(255, 255, 255, 0.08) !important;
                    border-color: rgba(255, 255, 255, 0.2) !important;
                }
                "#}
            </style>

            <h2 style="margin-top: 0; margin-bottom: 8px; font-size: 20px; font-weight: 600; text-align: center;">
                "MFA: TOTP Setup"
            </h2>

            {move || if step.get() == 1 {
                view! {
                    <div>
                        <p style="margin-top: 0; margin-bottom: 20px; font-size: 14px; color: rgba(255, 255, 255, 0.6); text-align: center;">
                            "Configure your authenticator app to enable Multi-Factor Authentication."
                        </p>

                        <form on:submit=handle_setup>
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
                                    disabled=move || setup_pending.get()
                                />
                            </div>

                            <button
                                type="submit"
                                class=DEFAULT_BUTTON_CLASS
                                style=DEFAULT_BUTTON_STYLE
                                disabled=move || setup_pending.get()
                            >
                                {move || if setup_pending.get() { "Initializing..." } else { "Start TOTP Setup" }}
                            </button>
                        </form>

                        {move || {
                            setup_result.get().and_then(|res| {
                                if let Err(err) = res {
                                    Some(view! {
                                        <div style="margin-top: 16px; padding: 10px 12px; border-radius: 6px; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); color: #f87171; font-size: 13px; text-align: center;">
                                            {err}
                                        </div>
                                    }.into_any())
                                } else {
                                    None
                                }
                            })
                        }}
                    </div>
                }.into_any()
            } else {
                view! {
                    <div>
                        <p style="margin-top: 0; margin-bottom: 20px; font-size: 14px; color: rgba(255, 255, 255, 0.6); text-align: center;">
                            "Scan the QR code or manually input the secret key into your authenticator app (such as Google Authenticator or Authy)."
                        </p>

                        <div style="background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 8px; padding: 16px; margin-bottom: 20px; display: flex; flex-direction: column; gap: 12px; font-size: 13px;">
                            {move || secret_key().map(|sec| view! {
                                <div>
                                    <span style="color: rgba(255,255,255,0.5); font-weight:500;">"Secret Key (Base32):"</span>
                                    <div style="background: rgba(0,0,0,0.2); border: 1px dashed rgba(255,255,255,0.1); border-radius:4px; padding:8px; margin-top:4px; font-family:monospace; font-size:14px; word-break:break-all; text-align:center; color:#fff; user-select:all;">
                                        {sec}
                                    </div>
                                </div>
                            })}

                            {move || uri.get().map(|u| view! {
                                <div>
                                    <span style="color: rgba(255,255,255,0.5); font-weight:500;">"Provisioning URI:"</span>
                                    <div style="background: rgba(0,0,0,0.2); border: 1px dashed rgba(255,255,255,0.1); border-radius:4px; padding:8px; margin-top:4px; font-family:monospace; font-size:11px; word-break:break-all; color:rgba(255,255,255,0.8); user-select:all; max-height: 80px; overflow-y: auto;">
                                        {u}
                                    </div>
                                </div>
                            })}
                        </div>

                        <form on:submit=handle_verify>
                            <div style="display: flex; flex-direction: column; align-items: flex-start; width: 100%;">
                                <label style="font-size: 12px; font-weight: 500; color: rgba(255, 255, 255, 0.8);">
                                    "Enter 6-digit Code"
                                </label>
                                <input
                                    type="text"
                                    placeholder="123456"
                                    class=DEFAULT_INPUT_CLASS
                                    style=DEFAULT_INPUT_STYLE
                                    required
                                    prop:value=code
                                    on:input=move |ev| set_code.set(event_target_value(&ev))
                                    disabled=move || verify_pending.get()
                                />
                            </div>

                            <button
                                type="submit"
                                class=DEFAULT_BUTTON_CLASS
                                style=DEFAULT_BUTTON_STYLE
                                disabled=move || verify_pending.get()
                            >
                                {move || if verify_pending.get() { "Verifying..." } else { "Verify & Enable TOTP" }}
                            </button>

                            <button
                                type="button"
                                class="wasi-auth-secondary-button"
                                style="margin-top: 10px; background: transparent; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 6px; padding: 10px 16px; color: rgba(255, 255, 255, 0.7); cursor: pointer; transition: all 0.2s ease-in-out; font-weight: 500; width: 100%; font-size: 14px;"
                                on:click=handle_back
                                disabled=move || verify_pending.get()
                            >
                                "Restart / Go Back"
                            </button>
                        </form>

                        {move || {
                            verify_result.get().map(|res| {
                                match res {
                                    Ok(success) => {
                                        if success {
                                            view! {
                                                <div style="margin-top: 16px; padding: 10px 12px; border-radius: 6px; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); color: #34d399; font-size: 13px; text-align: center;">
                                                    "TOTP successfully enabled!"
                                                </div>
                                            }.into_any()
                                        } else {
                                            view! {
                                                <div style="margin-top: 16px; padding: 10px 12px; border-radius: 6px; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); color: #f87171; font-size: 13px; text-align: center;">
                                                    "Invalid code. Setup verification failed."
                                                </div>
                                            }.into_any()
                                        }
                                    }
                                    Err(err) => view! {
                                        <div style="margin-top: 16px; padding: 10px 12px; border-radius: 6px; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); color: #f87171; font-size: 13px; text-align: center;">
                                            {err}
                                        </div>
                                    }.into_any()
                                }
                            })
                        }}
                    </div>
                }.into_any()
            }}
        </div>
    }
}
