# leptos-wasi-ui

A premium, highly configurable library of Leptos UI components designed for integrating WASI Authentication Middleware pipelines into Leptos applications.

## Core Components

This crate provides a collection of interactive UI components:

- **`LoginForm`**: A tabbed sign-in component supporting Email OTP, Magic Link request, and MFA TOTP verification. It can also render passkey login and OAuth provider buttons.
- **`OtpForm`**: A workflow form that handles both requesting a One-Time Password (OTP) and verifying it.
- **`MagicLinkForm`**: A passwordless sign-in requester form that accepts an email address and triggers a magic link dispatch.
- **`TotpSetup`**: A wizard component for setting up MFA (TOTP). It displays the base32 secret key, provisioning URI (for QR codes), and a code verification input to confirm successful setup.
- **`MfaStatus`**: Renders the current MFA status (Enabled/Disabled) and allows the user to disable it via a confirmation button.
- **`SessionList`**: Displays active user sessions, allowing single-session revocation or revoking all other sessions in bulk.
- **`PasskeyRegisterButton` & `PasskeyLoginButton`**: Buttons that orchestrate WebAuthn/Passkey ceremonies directly in browser environments (using JS/WASM interop).
- **`PasskeyList`** (under `passkey` feature): Displays registered passkeys, enabling renaming and credential deletion.

## Crate Features

The library utilizes conditional compilation flags to optimize bundle size and support different execution environments:

| Feature | Description |
|---|---|
| `ssr` (default) | Compiles components with server-side rendering support. |
| `hydrate` | Enables browser hydration and links JS-driven credential (WebAuthn/Passkey) APIs. |
| `csr` | Enables client-side rendering (CSR) and browser WebAuthn API bindings. |
| `passkey` | Enables the `PasskeyList` component and integrates passkey structures from `wasi-auth-core`. |

## Premium Default Styling

All components feature beautiful, responsive, and customizable default styles matching dark glassmorphic themes. 
Styling can be toggled using the `use_default_styles` prop (defaults to `true`). When set to `false`, components render unstyled markup, letting you apply custom Tailwind, CSS modules, or utility framework styles easily.

## Usage Guide

To use these components in your Leptos application, add `leptos-wasi-ui` to your dependencies with the desired features.

### 1. Rendering the LoginForm

Below is an example of importing and rendering the `<LoginForm>` component, which automatically handles tabs for Email OTP, Magic Link, and TOTP verification, as well as Passkey triggers and OAuth social buttons:

```rust,ignore
use leptos::*;
use leptos_wasi_ui::LoginForm;

#[component]
pub fn LoginPage() -> impl IntoView {
    view! {
        <div class="login-container">
            <LoginForm
                // Optional styling overrides
                class="custom-login-card"
                style="max-width: 440px;"
                use_default_styles=true
                
                // Show/hide specific login methods
                show_otp=true
                show_magic_link=true
                show_totp=true
                show_passkey=true
                
                // Customize OAuth providers
                oauth_providers=vec![
                    ("Google".to_string(), "http://127.0.0.1:8080/authorize?provider=google".to_string()),
                    ("GitHub".to_string(), "http://127.0.0.1:8080/authorize?provider=github".to_string())
                ]
            />
        </div>
    }
}
```

### 2. User Security Dashboard Integration

Here is a complete example of a user security settings panel that displays registered Passkeys, active browser Sessions, and current Multi-Factor Authentication (MFA) status. This binds the components to reactive Leptos signals and server action handlers:

```rust,ignore
use leptos::*;
use leptos_wasi_ui::{SessionList, PasskeyList, MfaStatus};
use wasi_auth_traits::Session;
use wasi_auth_core::passkey::StoredPasskey;

#[component]
pub fn SecurityDashboard() -> impl IntoView {
    // 1. Reactive state for active sessions
    let (sessions, set_sessions) = signal(vec![
        Session {
            session_id: "current_session".to_string(),
            user_id: "user_123".to_string(),
            roles: vec!["user".to_string()],
            expires_at: 1700000000,
        }
    ]);
    let (current_session_id, _) = signal(Some("current_session".to_string()));
    let (revoke_pending, set_revoke_pending) = signal(false);

    // Callback when revoking a session
    let on_revoke_session = Callback::new(move |session_id: String| {
        set_revoke_pending.set(true);
        // Here you would trigger a server action:
        // revoke_action.dispatch(session_id);
        set_revoke_pending.set(false);
    });

    // 2. Reactive state for registered Passkeys
    let (passkeys, set_passkeys) = signal(vec![
        StoredPasskey {
            user_id: "user_123".to_string(),
            cred_id: "cred_abc".to_string(),
            public_key: "key_data".to_string(),
            name: "My MacBook TouchID".to_string(),
            created_at: 1700000000000,
            last_used_at: 1700005000000,
            counter: 12,
        }
    ]);
    let (passkey_pending, set_passkey_pending) = signal(false);

    // Callbacks for passkey mutations
    let on_delete_passkey = Callback::new(move |cred_id: String| {
        set_passkey_pending.set(true);
        // Trigger server function to delete passkey credential
        set_passkey_pending.set(false);
    });
    
    let on_rename_passkey = Callback::new(move |(cred_id, new_name): (String, String)| {
        // Trigger server function to update passkey label
    });

    // 3. Reactive state for MFA TOTP status
    let (mfa_enabled, set_mfa_enabled) = signal(true);
    let (mfa_pending, set_mfa_pending) = signal(false);

    let on_disable_mfa = Callback::new(move |_| {
        set_mfa_pending.set(true);
        // Trigger server function to disable TOTP
        set_mfa_enabled.set(false);
        set_mfa_pending.set(false);
    });

    view! {
        <div class="dashboard-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 24px; padding: 20px;">
            // Render MFA Status Panel
            <MfaStatus
                enabled=mfa_enabled
                pending=mfa_pending
                on_disable=on_disable_mfa
            />

            // Render Passkey Management Panel
            <PasskeyList
                passkeys=passkeys
                pending=passkey_pending
                on_delete=on_delete_passkey
                on_rename=on_rename_passkey
            />

            // Render Active Sessions Panel
            <SessionList
                sessions=sessions
                current_session_id=current_session_id
                pending=revoke_pending
                on_revoke=on_revoke_session
            />
        </div>
    }
}
```
