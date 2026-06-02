use leptos::prelude::*;

const DEFAULT_BUTTON_CLASS: &str = "wasi-auth-passkey-button";

#[cfg(all(target_arch = "wasm32", any(feature = "hydrate", feature = "csr")))]
use wasm_bindgen::prelude::*;

#[cfg(all(target_arch = "wasm32", any(feature = "hydrate", feature = "csr")))]
#[wasm_bindgen(inline_js = r#"
export function base64url_to_bytes(base64url) {
    const padding = '='.repeat((4 - base64url.length % 4) % 4);
    const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}
export function bytes_to_base64url(bytes) {
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64 = window.btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
export function prepare_creation_options(options) {
    const opt = JSON.parse(JSON.stringify(options));
    if (typeof opt.challenge === 'string') {
        opt.challenge = base64url_to_bytes(opt.challenge);
    }
    if (opt.user && typeof opt.user.id === 'string') {
        opt.user.id = base64url_to_bytes(opt.user.id);
    }
    if (Array.isArray(opt.excludeCredentials)) {
        for (const cred of opt.excludeCredentials) {
            if (typeof cred.id === 'string') {
                cred.id = base64url_to_bytes(cred.id);
            }
        }
    }
    return opt;
}
export function prepare_request_options(options) {
    const opt = JSON.parse(JSON.stringify(options));
    if (typeof opt.challenge === 'string') {
        opt.challenge = base64url_to_bytes(opt.challenge);
    }
    if (Array.isArray(opt.allowCredentials)) {
        for (const cred of opt.allowCredentials) {
            if (typeof cred.id === 'string') {
                cred.id = base64url_to_bytes(cred.id);
            }
        }
    }
    return opt;
}
export function extract_creation_response(credential) {
    const rawId = bytes_to_base64url(new Uint8Array(credential.rawId));
    const response = credential.response;
    const clientDataJSON = bytes_to_base64url(new Uint8Array(response.clientDataJSON));
    const attestationObject = bytes_to_base64url(new Uint8Array(response.attestationObject));
    let transports = [];
    if (typeof response.getTransports === 'function') {
        transports = response.getTransports();
    }
    return {
        id: credential.id,
        rawId: rawId,
        type: credential.type,
        response: {
            clientDataJSON: clientDataJSON,
            attestationObject: attestationObject,
            transports: transports
        }
    };
}
export function extract_request_response(credential) {
    const rawId = bytes_to_base64url(new Uint8Array(credential.rawId));
    const response = credential.response;
    const clientDataJSON = bytes_to_base64url(new Uint8Array(response.clientDataJSON));
    const authenticatorData = bytes_to_base64url(new Uint8Array(response.authenticatorData));
    const signature = bytes_to_base64url(new Uint8Array(response.signature));
    let userHandle = null;
    if (response.userHandle) {
        userHandle = bytes_to_base64url(new Uint8Array(response.userHandle));
    }
    return {
        id: credential.id,
        rawId: rawId,
        type: credential.type,
        response: {
            clientDataJSON: clientDataJSON,
            authenticatorData: authenticatorData,
            signature: signature,
            userHandle: userHandle
        }
    };
}
"#)]
extern "C" {
    #[wasm_bindgen(catch)]
    fn prepare_creation_options(
        options: &wasm_bindgen::JsValue,
    ) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;

    #[wasm_bindgen(catch)]
    fn prepare_request_options(
        options: &wasm_bindgen::JsValue,
    ) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;

    #[wasm_bindgen(catch)]
    fn extract_creation_response(
        credential: &wasm_bindgen::JsValue,
    ) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;

    #[wasm_bindgen(catch)]
    fn extract_request_response(
        credential: &wasm_bindgen::JsValue,
    ) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;
}

#[cfg(all(target_arch = "wasm32", any(feature = "hydrate", feature = "csr")))]
async fn run_register_ceremony(options_json: String) -> Result<String, String> {
    let window = web_sys::window().ok_or("No global window found")?;
    let navigator = window.navigator();
    let credentials = navigator.credentials();

    let parsed_options = js_sys::JSON::parse(&options_json)
        .map_err(|e| format!("Failed to parse options JSON: {:?}", e))?;

    let prepared = prepare_creation_options(&parsed_options)
        .map_err(|e| format!("Failed to prepare creation options: {:?}", e))?;

    let mut creation_options = web_sys::CredentialCreationOptions::new();
    creation_options.publicKey(&prepared);

    let promise = credentials
        .create_with_options(&creation_options)
        .map_err(|e| format!("Failed to call credentials.create: {:?}", e))?;

    let js_fut = wasm_bindgen_futures::JsFuture::from(promise);
    let credential = js_fut
        .await
        .map_err(|e| format!("Credential creation rejected: {:?}", e))?;

    let extracted = extract_creation_response(&credential)
        .map_err(|e| format!("Failed to extract creation response: {:?}", e))?;

    let response_json = js_sys::JSON::stringify(&extracted)
        .map_err(|e| format!("Failed to stringify response: {:?}", e))?
        .as_string()
        .ok_or("Stringify returned non-string")?;

    Ok(response_json)
}

#[cfg(all(target_arch = "wasm32", any(feature = "hydrate", feature = "csr")))]
async fn run_login_ceremony(options_json: String) -> Result<String, String> {
    let window = web_sys::window().ok_or("No global window found")?;
    let navigator = window.navigator();
    let credentials = navigator.credentials();

    let parsed_options = js_sys::JSON::parse(&options_json)
        .map_err(|e| format!("Failed to parse options JSON: {:?}", e))?;

    let prepared = prepare_request_options(&parsed_options)
        .map_err(|e| format!("Failed to prepare request options: {:?}", e))?;

    let mut request_options = web_sys::CredentialRequestOptions::new();
    request_options.publicKey(&prepared);

    let promise = credentials
        .get_with_options(&request_options)
        .map_err(|e| format!("Failed to call credentials.get: {:?}", e))?;

    let js_fut = wasm_bindgen_futures::JsFuture::from(promise);
    let credential = js_fut
        .await
        .map_err(|e| format!("Credential request rejected: {:?}", e))?;

    let extracted = extract_request_response(&credential)
        .map_err(|e| format!("Failed to extract request response: {:?}", e))?;

    let response_json = js_sys::JSON::stringify(&extracted)
        .map_err(|e| format!("Failed to stringify response: {:?}", e))?
        .as_string()
        .ok_or("Stringify returned non-string")?;

    Ok(response_json)
}

// Fallback stubs for non-wasm32 environments to keep component code clean and avoid conditional compilation blocks inside components
#[cfg(not(all(target_arch = "wasm32", any(feature = "hydrate", feature = "csr"))))]
async fn run_register_ceremony(_options_json: String) -> Result<String, String> {
    Err("WebAuthn register ceremony is only supported in browser environments".to_string())
}

#[cfg(not(all(target_arch = "wasm32", any(feature = "hydrate", feature = "csr"))))]
async fn run_login_ceremony(_options_json: String) -> Result<String, String> {
    Err("WebAuthn login ceremony is only supported in browser environments".to_string())
}

/// Generic private button component that handles ceremony execution, error handling,
/// dynamic class/style merging, and reactive signal observation.
#[allow(clippy::too_many_arguments)]
fn passkey_button_internal<F, Fut>(
    class: Option<TextProp>,
    style: Option<TextProp>,
    options: Signal<Option<String>>,
    pending: Signal<bool>,
    on_click: Option<Callback<()>>,
    on_success: Callback<String>,
    on_error: Callback<String>,
    default_text: &'static str,
    ceremony_fn: F,
    icon: impl IntoView + 'static,
    use_default_styles: bool,
) -> impl IntoView
where
    F: Fn(String) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<String, String>> + Send + 'static,
{
    let merged_class = move || {
        let user_class = class
            .as_ref()
            .map(|c| format!(" {}", c.get()))
            .unwrap_or_default();
        format!("{}{}", DEFAULT_BUTTON_CLASS, user_class)
    };
    let merged_style = move || {
        style
            .as_ref()
            .map(|s| s.get().to_string())
            .unwrap_or_default()
    };
    let (waiting_for_options, set_waiting_for_options) = leptos::prelude::signal(false);

    let ceremony_fn_clone = ceremony_fn.clone();
    let on_success_clone = on_success;
    let on_error_clone = on_error;

    // Effect that runs once options become available (e.g. after a click fetches them)
    Effect::new(move |_| {
        // If ceremony is no longer pending and options are still None (e.g., fetching failed),
        // reset the waiting flag to prevent UI from locking.
        if !pending.get() && options.with(|opt| opt.is_none()) {
            set_waiting_for_options.set(false);
        }

        // Use untrack here to avoid setting up a cyclic tracking dependency on waiting_for_options
        if waiting_for_options.get_untracked() {
            let opt_str_opt = options.with(|opt| opt.clone());
            if let Some(opt_str) = opt_str_opt {
                set_waiting_for_options.set(false);
                let ceremony_fn = ceremony_fn_clone.clone();
                leptos::task::spawn_local(async move {
                    match ceremony_fn(opt_str).await {
                        Ok(res) => on_success_clone.run(res),
                        Err(err) => on_error_clone.run(err),
                    }
                });
            }
        }
    });

    let handle_click = move |_| {
        if pending.get() {
            return;
        }
        if let Some(ref cb) = on_click {
            cb.run(());
        }

        if let Some(opt_str) = options.with(|opt| opt.clone()) {
            let ceremony_fn = ceremony_fn.clone();
            leptos::task::spawn_local(async move {
                match ceremony_fn(opt_str).await {
                    Ok(res) => on_success.run(res),
                    Err(err) => on_error.run(err),
                }
            });
        } else {
            set_waiting_for_options.set(true);
        }
    };

    view! {
        {if use_default_styles {
            Some(view! {
                <style>
                    {r#"
                    .wasi-auth-passkey-button {
                        background: rgba(255, 255, 255, 0.08);
                        backdrop-filter: blur(16px);
                        -webkit-backdrop-filter: blur(16px);
                        border: 1px solid rgba(255, 255, 255, 0.08);
                        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
                        border-radius: 8px;
                        padding: 10px 20px;
                        color: #fff;
                        cursor: pointer;
                        font-weight: 500;
                        font-family: sans-serif;
                        transition: all 0.2s ease-in-out;
                        display: inline-flex;
                        align-items: center;
                        justify-content: center;
                        gap: 8px;
                    }
                    .wasi-auth-passkey-button:hover:not(:disabled) {
                        background: rgba(255, 255, 255, 0.15) !important;
                        border-color: rgba(255, 255, 255, 0.2) !important;
                    }
                    .wasi-auth-passkey-button:disabled {
                        opacity: 0.5;
                        cursor: not-allowed;
                    }
                    "#}
                </style>
            })
        } else {
            None
        }}
        <button
            type="button"
            class=merged_class
            style=merged_style
            on:click=handle_click
            disabled=move || pending.get()
        >
            {icon}
            {move || if pending.get() { "Starting ceremony..." } else { default_text }}
        </button>
    }
}

#[component]
pub fn PasskeyRegisterButton(
    #[prop(optional, into)] class: Option<TextProp>,
    #[prop(optional, into)] style: Option<TextProp>,
    #[prop(into)] options: Signal<Option<String>>,
    on_register_success: Callback<String>,
    on_register_error: Callback<String>,
    #[prop(into)] pending: Signal<bool>,
    #[prop(optional)] on_click: Option<Callback<()>>,
    #[prop(optional, default = true)] use_default_styles: bool,
) -> impl IntoView {
    let icon = view! {
        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width: 18px; height: 18px; flex-shrink: 0;" xmlns="http://www.w3.org/2000/svg">
            <path stroke-linecap="round" stroke-linejoin="round" d="M15 7a2 2 0 012 2m-2 4a5 5 0 11-4-4 1.9 1.9 0 011 0M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
    };

    view! {
        {passkey_button_internal(
            class,
            style,
            options,
            pending,
            on_click,
            on_register_success,
            on_register_error,
            "Register Passkey",
            run_register_ceremony,
            icon,
            use_default_styles,
        )}
    }
}

#[component]
pub fn PasskeyLoginButton(
    #[prop(optional, into)] class: Option<TextProp>,
    #[prop(optional, into)] style: Option<TextProp>,
    #[prop(into)] options: Signal<Option<String>>,
    on_login_success: Callback<String>,
    on_login_error: Callback<String>,
    #[prop(into)] pending: Signal<bool>,
    #[prop(optional)] on_click: Option<Callback<()>>,
    #[prop(optional, default = true)] use_default_styles: bool,
) -> impl IntoView {
    let icon = view! {
        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width: 18px; height: 18px; flex-shrink: 0;" xmlns="http://www.w3.org/2000/svg">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 009 11a5 5 0 00-10 0c0 1.05.15 2.07.433 3.036l.64 2.222A3.01 3.01 0 003 18.11V21h3v-2.89a3 3 0 01.378-1.468z" />
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 11c0-3.517 1.009-6.799 2.753-9.571m3.44 2.04l-.054.09A13.916 13.916 0 0015 11a5 5 0 0010 0c0-1.05-.15-2.07-.433-3.036l-.64-2.222A3.01 3.01 0 0021 5.89V3h-3v2.89a3 3 0 01-.378 1.468z" />
        </svg>
    };

    view! {
        {passkey_button_internal(
            class,
            style,
            options,
            pending,
            on_click,
            on_login_success,
            on_login_error,
            "Login with Passkey",
            run_login_ceremony,
            icon,
            use_default_styles,
        )}
    }
}
