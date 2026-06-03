# leptos-wasi-ui

Premium, configurable Leptos UI components for WASI authentication workflows.

## Components

| Component | Description |
|---|---|
| `LoginForm` | Tabbed sign-in: Email OTP, Magic Link, TOTP MFA, Passkey, OAuth |
| `TotpSetup` | Step-by-step MFA setup wizard (secret display + code verification) |
| `SessionList` | Active session list with single/bulk revocation |
| `MfaStatus` | MFA enabled/disabled status card with disable action |
| `PasskeyList`* | Registered passkey management (rename, delete with confirmation) |
| `PasskeyRegisterButton` / `PasskeyLoginButton` | WebAuthn browser ceremony triggers |

*\* Requires `features = ["passkey"]`*

## Features

| Feature | Description |
|---|---|
| `ssr` (default) | Server-side rendering support |
| `hydrate` | Browser hydration + WebAuthn API bindings |
| `csr` | Client-side rendering + WebAuthn API bindings |
| `passkey` | Enables `PasskeyList` component |

## Styling

All components ship with dark glassmorphism defaults. Control via:
- `use_default_styles=true` (default) — built-in theme
- `style="..."` — additive overrides
- `class="..."` — your own CSS rules
- `use_default_styles=false` — fully custom

## Usage & Examples

**→ See the [UI Components Guide](../docs/ui_components.md)** for complete prop tables and full working examples.

The [`examples/leptos-auth-demo`](../examples/leptos-auth-demo/) app demonstrates every component wired to real server functions.
