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
