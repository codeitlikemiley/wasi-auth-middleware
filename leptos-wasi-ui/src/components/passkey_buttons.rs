use leptos::prelude::*;

const DEFAULT_BUTTON_CLASS: &str = "wasi-auth-passkey-button";
const DEFAULT_BUTTON_STYLE: &str = "background: rgba(255, 255, 255, 0.08); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3); border-radius: 8px; padding: 10px 20px; color: #fff; cursor: pointer; font-weight: 500; font-family: sans-serif; transition: all 0.2s ease-in-out; display: inline-flex; align-items: center; justify-content: center; gap: 8px;";

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

#[component]
pub fn PasskeyRegisterButton(
    #[prop(optional, into)] class: Option<String>,
    #[prop(optional, into)] style: Option<String>,
    #[prop(into)] options: Signal<Option<String>>,
    on_register_success: Callback<String>,
    on_register_error: Callback<String>,
    #[prop(into)] pending: Signal<bool>,
    #[prop(optional)] on_click: Option<Callback<()>>,
) -> impl IntoView {
    let merged_class = format!("{} {}", DEFAULT_BUTTON_CLASS, class.unwrap_or_default());
    let merged_style = format!("{}; {}", DEFAULT_BUTTON_STYLE, style.unwrap_or_default());

    let (waiting_for_options, set_waiting_for_options) = leptos::prelude::signal(false);

    #[cfg(not(all(target_arch = "wasm32", any(feature = "hydrate", feature = "csr"))))]
    {
        let _ = options;
        let _ = on_register_success;
        let _ = on_register_error;
        let _ = waiting_for_options;
        let _ = set_waiting_for_options;
    }

    #[cfg(all(target_arch = "wasm32", any(feature = "hydrate", feature = "csr")))]
    {
        let on_success = on_register_success.clone();
        let on_error = on_register_error.clone();
        Effect::new(move |_| {
            if waiting_for_options.get() {
                if let Some(opt_str) = options.get() {
                    set_waiting_for_options.set(false);
                    let on_success = on_success.clone();
                    let on_error = on_error.clone();
                    leptos::prelude::spawn_local(async move {
                        match run_register_ceremony(opt_str).await {
                            Ok(res) => on_success.run(res),
                            Err(err) => on_error.run(err),
                        }
                    });
                }
            }
        });
    }

    let handle_click = move |_| {
        if pending.get() {
            return;
        }
        if let Some(ref cb) = on_click {
            cb.run(());
        }

        #[cfg(all(target_arch = "wasm32", any(feature = "hydrate", feature = "csr")))]
        {
            if let Some(opt_str) = options.get() {
                let on_success = on_register_success.clone();
                let on_error = on_register_error.clone();
                leptos::prelude::spawn_local(async move {
                    match run_register_ceremony(opt_str).await {
                        Ok(res) => on_success.run(res),
                        Err(err) => on_error.run(err),
                    }
                });
            } else {
                set_waiting_for_options.set(true);
            }
        }
    };

    view! {
        <button
            type="button"
            class=merged_class
            style=merged_style
            on:click=handle_click
            disabled=move || pending.get()
        >
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width: 18px; height: 18px; flex-shrink: 0;" xmlns="http://www.w3.org/2000/svg">
                <path stroke-linecap="round" stroke-linejoin="round" d="M15 7a2 2 0 012 2m-2 4a5 5 0 11-4-4 1.9 1.9 0 011 0M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            {move || if pending.get() { "Starting ceremony..." } else { "Register Passkey" }}
        </button>
    }
}

#[component]
pub fn PasskeyLoginButton(
    #[prop(optional, into)] class: Option<String>,
    #[prop(optional, into)] style: Option<String>,
    #[prop(into)] options: Signal<Option<String>>,
    on_login_success: Callback<String>,
    on_login_error: Callback<String>,
    #[prop(into)] pending: Signal<bool>,
    #[prop(optional)] on_click: Option<Callback<()>>,
) -> impl IntoView {
    let merged_class = format!("{} {}", DEFAULT_BUTTON_CLASS, class.unwrap_or_default());
    let merged_style = format!("{}; {}", DEFAULT_BUTTON_STYLE, style.unwrap_or_default());

    let (waiting_for_options, set_waiting_for_options) = leptos::prelude::signal(false);

    #[cfg(not(all(target_arch = "wasm32", any(feature = "hydrate", feature = "csr"))))]
    {
        let _ = options;
        let _ = on_login_success;
        let _ = on_login_error;
        let _ = waiting_for_options;
        let _ = set_waiting_for_options;
    }

    #[cfg(all(target_arch = "wasm32", any(feature = "hydrate", feature = "csr")))]
    {
        let on_success = on_login_success.clone();
        let on_error = on_login_error.clone();
        Effect::new(move |_| {
            if waiting_for_options.get() {
                if let Some(opt_str) = options.get() {
                    set_waiting_for_options.set(false);
                    let on_success = on_success.clone();
                    let on_error = on_error.clone();
                    leptos::prelude::spawn_local(async move {
                        match run_login_ceremony(opt_str).await {
                            Ok(res) => on_success.run(res),
                            Err(err) => on_error.run(err),
                        }
                    });
                }
            }
        });
    }

    let handle_click = move |_| {
        if pending.get() {
            return;
        }
        if let Some(ref cb) = on_click {
            cb.run(());
        }

        #[cfg(all(target_arch = "wasm32", any(feature = "hydrate", feature = "csr")))]
        {
            if let Some(opt_str) = options.get() {
                let on_success = on_login_success.clone();
                let on_error = on_login_error.clone();
                leptos::prelude::spawn_local(async move {
                    match run_login_ceremony(opt_str).await {
                        Ok(res) => on_success.run(res),
                        Err(err) => on_error.run(err),
                    }
                });
            } else {
                set_waiting_for_options.set(true);
            }
        }
    };

    view! {
        <button
            type="button"
            class=merged_class
            style=merged_style
            on:click=handle_click
            disabled=move || pending.get()
        >
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width: 18px; height: 18px; flex-shrink: 0;" xmlns="http://www.w3.org/2000/svg">
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 009 11a5 5 0 00-10 0c0 1.05.15 2.07.433 3.036l.64 2.222A3.01 3.01 0 003 18.11V21h3v-2.89a3 3 0 01.378-1.468z" />
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 11c0-3.517 1.009-6.799 2.753-9.571m3.44 2.04l-.054.09A13.916 13.916 0 0015 11a5 5 0 0010 0c0-1.05-.15-2.07-.433-3.036l-.64-2.222A3.01 3.01 0 0021 5.89V3h-3v2.89a3 3 0 01-.378 1.468z" />
            </svg>
            {move || if pending.get() { "Starting ceremony..." } else { "Login with Passkey" }}
        </button>
    }
}
