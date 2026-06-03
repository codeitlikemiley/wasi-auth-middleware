# UI Components Guide

[← Getting Started](getting_started.md) · **2 of 4** · [Next: Architecture →](architecture.md)

Complete how-to guide for using the `leptos-wasi-ui` authentication components in your Leptos application. Each section includes the **prop API**, **associated data types**, and a **full working example** taken from [`examples/leptos-auth-demo`](../examples/leptos-auth-demo/src/lib.rs).

> **Quick start:** Add the crate to your `Cargo.toml`:
> ```toml
> [dependencies]
> leptos-wasi-ui = { path = "../leptos-wasi-ui" }
> # For passkey management:
> # leptos-wasi-ui = { path = "../leptos-wasi-ui", features = ["passkey"] }
> ```

---

## Table of Contents

- [LoginForm](#loginform)
- [TotpSetup](#totpsetup)
- [SessionList](#sessionlist)
- [MfaStatus](#mfastatus)
- [PasskeyList](#passkeylist)
- [Composing on a Dashboard](#composing-on-a-dashboard)
- [Styling & Theming](#styling--theming)

---

## `LoginForm`

Tabbed interface supporting **Email OTP**, **Magic Link**, and **TOTP MFA** sign-in methods. Optionally renders Passkey and OAuth buttons.

### Props

| Prop | Type | Required | Description |
|---|---|---|---|
| `class` | `Option<TextProp>` | No | CSS class appended to the container. |
| `style` | `Option<TextProp>` | No | Inline styles merged with defaults. |
| `initial_email` | `Option<String>` | No | Pre-fills the email input. |
| `on_request_otp` | `Option<Callback<String>>` | No | Fired when clicking "Send OTP". Receives the email. |
| `on_submit_otp` | `Option<Callback<OtpVerification>>` | No | Fired when submitting an OTP code. |
| `on_request_magic_link` | `Option<Callback<String>>` | No | Fired when requesting a magic link. |
| `on_verify_totp` | `Option<Callback<TotpVerification>>` | No | Fired when submitting a TOTP code. |
| `request_otp_pending` | `Signal<bool>` | **Yes** | Loading state for "Send OTP" button. |
| `request_otp_result` | `Signal<Option<Result<String, String>>>` | **Yes** | OTP request feedback. |
| `verify_otp_pending` | `Signal<bool>` | **Yes** | Loading state for OTP verification. |
| `verify_otp_result` | `Signal<Option<Result<bool, String>>>` | **Yes** | OTP verification feedback. |
| `request_magic_link_pending` | `Signal<bool>` | **Yes** | Loading state for magic link. |
| `request_magic_link_result` | `Signal<Option<Result<String, String>>>` | **Yes** | Magic link feedback. |
| `verify_totp_pending` | `Signal<bool>` | **Yes** | Loading state for TOTP. |
| `verify_totp_result` | `Signal<Option<Result<bool, String>>>` | **Yes** | TOTP verification feedback. |
| `show_passkey` | `Option<bool>` | No | Show/hide the passkey login button. |
| `on_passkey_login` | `Option<Callback<()>>` | No | Fired on passkey login click. |
| `passkey_login_pending` | `Signal<bool>` | **Yes** | Loading state for passkey login. |
| `show_oauth` | `Option<bool>` | No | Show/hide OAuth provider buttons. |
| `use_default_styles` | `bool` | No | Default `true`. Set `false` for custom styling. |

### Data Types

```rust
use leptos_wasi_ui::components::login_form::{OtpVerification, TotpVerification};

pub struct OtpVerification {
    pub email: String,
    pub code: String,
}

pub struct TotpVerification {
    pub email: String,
    pub code: String,
}
```

### Example

```rust,no_run
use leptos::prelude::*;
use leptos_wasi_ui::LoginForm;
use leptos_wasi_ui::components::login_form::{OtpVerification, TotpVerification};

// Server functions (run on WASI) — implement your auth logic here
#[server(RequestOtp, "/api")]
pub async fn request_otp(email: String) -> Result<String, ServerFnError> { todo!() }

#[server(VerifyOtp, "/api")]
pub async fn verify_otp(email: String, otp: String) -> Result<bool, ServerFnError> { todo!() }

#[server(RequestMagicLink, "/api")]
pub async fn request_magic_link(email: String) -> Result<String, ServerFnError> { todo!() }

#[server(VerifyTotpLogin, "/api")]
pub async fn verify_totp_login_action(email: String, code: String) -> Result<bool, ServerFnError> { todo!() }

#[component]
pub fn Login() -> impl IntoView {
    // 1. Create Actions to dispatch server calls
    let request_otp_action = Action::new(|email: &String| {
        let email = email.clone();
        async move { request_otp(email).await }
    });
    let verify_otp_action = Action::new(|(email, otp): &(String, String)| {
        let email = email.clone(); let otp = otp.clone();
        async move { verify_otp(email, otp).await }
    });
    let request_magic_link_action = Action::new(|email: &String| {
        let email = email.clone();
        async move { request_magic_link(email).await }
    });
    let verify_totp_action = Action::new(|(email, code): &(String, String)| {
        let email = email.clone(); let code = code.clone();
        async move { verify_totp_login_action(email, code).await }
    });

    // 2. Derive reactive signals from actions
    let request_otp_pending = Signal::derive(move || request_otp_action.pending().get());
    let request_otp_result = Signal::derive(move || {
        request_otp_action.value().get().map(|res| res.map_err(|e| e.to_string()))
    });
    let verify_otp_pending = Signal::derive(move || verify_otp_action.pending().get());
    let verify_otp_result = Signal::derive(move || {
        verify_otp_action.value().get().map(|res| res.map_err(|e| e.to_string()))
    });
    let request_magic_link_pending = Signal::derive(move || request_magic_link_action.pending().get());
    let request_magic_link_result = Signal::derive(move || {
        request_magic_link_action.value().get().map(|res| res.map_err(|e| e.to_string()))
    });
    let verify_totp_pending = Signal::derive(move || verify_totp_action.pending().get());
    let verify_totp_result = Signal::derive(move || {
        verify_totp_action.value().get().map(|res| res.map_err(|e| e.to_string()))
    });
    let passkey_login_pending = Signal::derive(move || false);

    // 3. Create callbacks that dispatch the actions
    let on_request_otp = Callback::new(move |email: String| {
        request_otp_action.dispatch(email);
    });
    let on_submit_otp = Callback::new(move |v: OtpVerification| {
        verify_otp_action.dispatch((v.email, v.code));
    });
    let on_request_magic_link = Callback::new(move |email: String| {
        request_magic_link_action.dispatch(email);
    });
    let on_verify_totp = Callback::new(move |v: TotpVerification| {
        verify_totp_action.dispatch((v.email, v.code));
    });

    // 4. Navigate on successful verification
    let navigate = leptos_router::hooks::use_navigate();
    let nav = navigate.clone();
    Effect::new(move |_| {
        if let Some(Ok(true)) = verify_otp_action.value().get() {
            nav("/dashboard", Default::default());
        }
    });
    Effect::new(move |_| {
        if let Some(Ok(true)) = verify_totp_action.value().get() {
            navigate("/dashboard", Default::default());
        }
    });

    // 5. Render
    view! {
        <LoginForm
            show_oauth=false
            show_passkey=false
            request_otp_pending=request_otp_pending
            request_otp_result=request_otp_result
            verify_otp_pending=verify_otp_pending
            verify_otp_result=verify_otp_result
            request_magic_link_pending=request_magic_link_pending
            request_magic_link_result=request_magic_link_result
            verify_totp_pending=verify_totp_pending
            verify_totp_result=verify_totp_result
            passkey_login_pending=passkey_login_pending
            on_submit_otp=on_submit_otp
            on_request_otp=on_request_otp
            on_request_magic_link=on_request_magic_link
            on_verify_totp=on_verify_totp
        />
    }
}
```

---

## `TotpSetup`

Two-step wizard for configuring an authenticator app:

1. Enter email → server generates secret and provisioning URI.
2. Display secret + URI → user enters 6-digit code to activate MFA.

### Props

| Prop | Type | Required | Description |
|---|---|---|---|
| `class` / `style` | `Option<TextProp>` | No | Style overrides. |
| `initial_email` | `Option<String>` | No | Pre-fills the email field. |
| `uri` | `Signal<Option<String>>` | **Yes** | Provisioning URI from the server. |
| `on_setup` | `Option<Callback<String>>` | No | Initiates setup. Receives email. |
| `on_verify` | `Option<Callback<TotpSetupVerification>>` | No | Verifies the first code. |
| `setup_pending` | `Signal<bool>` | **Yes** | Loading state for setup. |
| `setup_result` | `Signal<Option<Result<String, String>>>` | **Yes** | Setup result (secret on success). |
| `verify_pending` | `Signal<bool>` | **Yes** | Loading state for verification. |
| `verify_result` | `Signal<Option<Result<bool, String>>>` | **Yes** | Verification result. |
| `use_default_styles` | `bool` | No | Default `true`. |

### Data Type

```rust
use leptos_wasi_ui::components::totp_setup::TotpSetupVerification;

pub struct TotpSetupVerification {
    pub email: String,
    pub code: String,
}
```

### Example

```rust,no_run
use leptos::prelude::*;
use leptos_wasi_ui::TotpSetup as TotpSetupForm;
use leptos_wasi_ui::components::totp_setup::TotpSetupVerification;

#[server(SetupTotp, "/api")]
pub async fn setup_totp(email: String) -> Result<String, ServerFnError> {
    // Call leptos_wasi_auth::register_totp(...) — returns provisioning URI
    todo!()
}

#[server(VerifyTotpLogin, "/api")]
pub async fn verify_totp_login_action(email: String, code: String) -> Result<bool, ServerFnError> {
    // Call leptos_wasi_auth::verify_totp_login(...) — issue JWT on success
    todo!()
}

#[component]
pub fn TotpSetupPage() -> impl IntoView {
    let setup_action = Action::new(|email: &String| {
        let email = email.clone();
        async move { setup_totp(email).await }
    });
    let verify_action = Action::new(|v: &TotpSetupVerification| {
        let email = v.email.clone(); let code = v.code.clone();
        async move { verify_totp_login_action(email, code).await }
    });

    let on_setup = Callback::new(move |email: String| { setup_action.dispatch(email); });
    let on_verify = Callback::new(move |v: TotpSetupVerification| { verify_action.dispatch(v); });

    let uri = Signal::derive(move || setup_action.value().get().and_then(|r| r.ok()));
    let setup_pending = Signal::derive(move || setup_action.pending().get());
    let setup_result = Signal::derive(move || {
        setup_action.value().get().map(|r| {
            r.map(|uri| {
                uri.split("secret=").nth(1)
                    .and_then(|s| s.split('&').next())
                    .unwrap_or("").to_string()
            }).map_err(|e| e.to_string())
        })
    });
    let verify_pending = Signal::derive(move || verify_action.pending().get());
    let verify_result = Signal::derive(move || {
        verify_action.value().get().map(|r| r.map_err(|e| e.to_string()))
    });

    let navigate = leptos_router::hooks::use_navigate();
    Effect::new(move |_| {
        if let Some(Ok(true)) = verify_action.value().get() {
            navigate("/dashboard", Default::default());
        }
    });

    view! {
        <TotpSetupForm
            uri=uri
            setup_pending=setup_pending
            setup_result=setup_result
            verify_pending=verify_pending
            verify_result=verify_result
            on_setup=on_setup
            on_verify=on_verify
        />
    }
}
```

---

## `SessionList`

Displays active sessions with metadata (truncated ID, roles, expiry). Highlights the current session and supports single or bulk revocation.

### Props

| Prop | Type | Required | Description |
|---|---|---|---|
| `class` / `style` | `Option<TextProp>` | No | Style overrides. |
| `sessions` | `Signal<Vec<wasi_auth_traits::Session>>` | **Yes** | Active sessions to display. |
| `current_session_id` | `Option<Signal<Option<String>>>` | No | Highlights the current session. |
| `on_revoke` | `Callback<String>` | **Yes** | Revoke a single session. Receives `session_id`. |
| `on_revoke_all` | `Option<Callback<()>>` | No | Revoke all other sessions (bulk). |
| `revoke_pending` | `Signal<bool>` | **Yes** | Loading state during revocation. |
| `revoke_result` | `Signal<Option<Result<(), String>>>` | **Yes** | Success/error feedback. |
| `use_default_styles` | `bool` | No | Default `true`. |

### Example

```rust,no_run
use leptos::prelude::*;
use leptos_wasi_ui::SessionList;

#[component]
pub fn DashboardSessions() -> impl IntoView {
    let (sessions, set_sessions) = signal(vec![
        wasi_auth_traits::Session {
            session_id: "session_current_12345".to_string(),
            user_id: "user@example.com".to_string(),
            roles: vec!["user".to_string()],
            expires_at: 1800000000,
        },
        wasi_auth_traits::Session {
            session_id: "session_other_67890".to_string(),
            user_id: "user@example.com".to_string(),
            roles: vec!["user".to_string()],
            expires_at: 1800000000,
        },
    ]);
    let (current_session_id, _) = signal(Some("session_current_12345".to_string()));
    let (revoke_pending, set_revoke_pending) = signal(false);
    let (revoke_result, set_revoke_result) = signal(None::<Result<(), String>>);

    let on_revoke = Callback::new(move |id: String| {
        set_revoke_pending.set(true);
        leptos::task::spawn_local(async move {
            // In production: call a server function to delete the session
            set_sessions.update(|list| { list.retain(|s| s.session_id != id); });
            set_revoke_pending.set(false);
            set_revoke_result.set(Some(Ok(())));
        });
    });

    let on_revoke_all = Callback::new(move |_: ()| {
        set_revoke_pending.set(true);
        leptos::task::spawn_local(async move {
            set_sessions.update(|list| {
                list.retain(|s| s.session_id == "session_current_12345");
            });
            set_revoke_pending.set(false);
            set_revoke_result.set(Some(Ok(())));
        });
    });

    view! {
        <SessionList
            sessions=sessions
            current_session_id=current_session_id
            on_revoke=on_revoke
            on_revoke_all=on_revoke_all
            revoke_pending=revoke_pending
            revoke_result=revoke_result
        />
    }
}
```

---

## `MfaStatus`

Status card showing whether TOTP MFA is enabled or disabled. Displays a shield icon and a "Disable MFA" button when active.

### Props

| Prop | Type | Required | Description |
|---|---|---|---|
| `class` / `style` | `Option<TextProp>` | No | Style overrides. |
| `totp_enabled` | `Signal<bool>` | **Yes** | Whether TOTP MFA is active. |
| `on_disable` | `Option<Callback<()>>` | No | Fired on "Disable MFA" click. |
| `disable_pending` | `Signal<bool>` | **Yes** | Loading state while disabling. |
| `disable_result` | `Signal<Option<Result<(), String>>>` | **Yes** | Success/error feedback. |
| `use_default_styles` | `bool` | No | Default `true`. |

### Example

```rust,no_run
use leptos::prelude::*;
use leptos_wasi_ui::MfaStatus;

#[component]
pub fn DashboardMfa() -> impl IntoView {
    let (totp_enabled, set_totp_enabled) = signal(true);
    let (disable_pending, set_disable_pending) = signal(false);
    let (disable_result, set_disable_result) = signal(None::<Result<(), String>>);

    let on_disable = Callback::new(move |_: ()| {
        set_disable_pending.set(true);
        leptos::task::spawn_local(async move {
            // In production: call server fn to remove TOTP secret
            set_totp_enabled.set(false);
            set_disable_pending.set(false);
            set_disable_result.set(Some(Ok(())));
        });
    });

    view! {
        <MfaStatus
            totp_enabled=totp_enabled
            on_disable=on_disable
            disable_pending=disable_pending
            disable_result=disable_result
        />
    }
}
```

---

## `PasskeyList`

> **Feature gate:** Requires `features = ["passkey"]` in your `Cargo.toml`.

Displays registered WebAuthn passkeys with creation/last-used dates. Supports inline rename and delete with confirmation.

### Props

| Prop | Type | Required | Description |
|---|---|---|---|
| `class` / `style` | `Option<TextProp>` | No | Style overrides. |
| `passkeys` | `Signal<Vec<StoredPasskey>>` | **Yes** | Registered passkeys. |
| `on_delete` | `Callback<String>` | **Yes** | Confirmed delete. Receives `cred_id`. |
| `on_rename` | `Callback<(String, String)>` | **Yes** | Rename save. Receives `(cred_id, new_name)`. |
| `pending` | `Option<Signal<bool>>` | No | Global loading state (dims the list). |
| `rename_result` | `Option<Signal<Option<Result<(), String>>>>` | No | Rename feedback. |
| `delete_result` | `Option<Signal<Option<Result<(), String>>>>` | No | Delete feedback. |
| `use_default_styles` | `bool` | No | Default `true`. |

### Example

```rust,no_run
use leptos::prelude::*;
use leptos_wasi_ui::PasskeyList;

#[component]
pub fn DashboardPasskeys() -> impl IntoView {
    let (passkeys, set_passkeys) = signal(vec![
        wasi_auth_core::passkey::StoredPasskey {
            user_id: "user@example.com".to_string(),
            cred_id: "cred_1".to_string(),
            public_key: "pk_1".to_string(),
            name: "Personal MacBook Pro".to_string(),
            created_at: 1700000000000,
            last_used_at: 1700005000000,
            counter: 0,
        },
    ]);
    let (pending, set_pending) = signal(false);
    let (rename_result, set_rename_result) = signal(None::<Result<(), String>>);
    let (delete_result, set_delete_result) = signal(None::<Result<(), String>>);

    let on_rename = Callback::new(move |(cred_id, new_name): (String, String)| {
        set_pending.set(true);
        leptos::task::spawn_local(async move {
            set_passkeys.update(|list| {
                if let Some(pk) = list.iter_mut().find(|p| p.cred_id == cred_id) {
                    pk.name = new_name;
                }
            });
            set_pending.set(false);
            set_rename_result.set(Some(Ok(())));
        });
    });

    let on_delete = Callback::new(move |cred_id: String| {
        set_pending.set(true);
        leptos::task::spawn_local(async move {
            set_passkeys.update(|list| { list.retain(|p| p.cred_id != cred_id); });
            set_pending.set(false);
            set_delete_result.set(Some(Ok(())));
        });
    });

    view! {
        <PasskeyList
            passkeys=passkeys
            on_delete=on_delete
            on_rename=on_rename
            pending=pending
            rename_result=rename_result
            delete_result=delete_result
        />
    }
}
```

---

## Composing on a Dashboard

Bring `SessionList`, `MfaStatus`, and `PasskeyList` together on a single page:

```rust,no_run
#[component]
pub fn Dashboard() -> impl IntoView {
    // ... set up signals and callbacks for each component (see examples above) ...

    view! {
        <div style="display: flex; flex-direction: column; gap: 24px;">
            <SessionList
                sessions=sessions
                current_session_id=current_session_id
                on_revoke=on_revoke
                on_revoke_all=on_revoke_all
                revoke_pending=revoke_pending
                revoke_result=revoke_result
            />
            <MfaStatus
                totp_enabled=totp_enabled
                on_disable=on_disable
                disable_pending=disable_pending
                disable_result=disable_result
            />
            {move || {
                #[cfg(feature = "passkey")]
                { Some(view! {
                    <PasskeyList
                        passkeys=passkeys
                        on_delete=on_delete
                        on_rename=on_rename
                        pending=passkey_pending
                        rename_result=rename_result
                        delete_result=delete_result
                    />
                }) }
                #[cfg(not(feature = "passkey"))]
                { None::<leptos::prelude::AnyView> }
            }}
        </div>
    }
}
```

---

## Styling & Theming

All components follow a consistent pattern:

| Strategy | How | When to Use |
|---|---|---|
| **Default styles** | Do nothing (or `use_default_styles=true`) | Built-in dark glassmorphism theme. |
| **Additive overrides** | Pass `style="..."` prop | Tweak specific properties. |
| **Class-based** | Pass `class="my-class"` prop | Apply your own CSS rules. |
| **Full custom** | Set `use_default_styles=false` | Complete styling control. |

CSS class targets: `wasi-auth-login-form`, `wasi-auth-session-list`, `wasi-auth-mfa-status`, `wasi-auth-totp-setup`, `wasi-auth-passkey-list`. These classes are always rendered regardless of `use_default_styles`.

---

[← Getting Started](getting_started.md) · **2 of 4** · [Next: Architecture →](architecture.md)
