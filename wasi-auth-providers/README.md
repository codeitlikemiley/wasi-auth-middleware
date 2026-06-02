# wasi-auth-providers

Ready-to-use OAuth2 and OpenID Connect provider configurations for the `wasi-auth-middleware` ecosystem.

This crate provides pre-configured preset modules containing the correct authorization, token, and userinfo endpoints for popular identity providers.

## Purpose

Instead of manually hardcoding URLs and looking up OAuth documentation for various providers, this crate exposes clean, typed constructor functions that return `OAuthConfig` configurations.

## Setup & Dependency Features

Add this to your `Cargo.toml`:

```toml
[dependencies]
wasi-auth-providers = { version = "0.1.0", path = "../wasi-auth-providers", features = ["google", "github"] }
```

### Feature Flags

No features are enabled by default. Choose only the identity providers you need, or enable all:

- **`google`** — Enables the Google provider preset.
- **`github`** — Enables the GitHub provider preset.
- **`apple`** — Enables the Sign in with Apple provider preset.
- **`microsoft`** — Enables the Microsoft Entra ID (Azure AD) provider preset.
- **`facebook`** — Enables the Facebook Login provider preset.
- **`discord`** — Enables the Discord Login provider preset.
- **`x`** — Enables the X (formerly Twitter) provider preset.
- **`keycloak`** — Enables the Keycloak provider preset.
- **`all`** — Helper feature that enables all providers above.

## Key APIs

Each enabled provider module exposes a function to construct the respective configuration:

### Google Preset
```rust
use wasi_auth_providers::google;
let config = google::google("client_id", "client_secret", "https://app.com/callback");
```

### GitHub Preset
```rust
use wasi_auth_providers::github;
let config = github::github("client_id", "client_secret", "https://app.com/callback");
```

### Microsoft Preset (Azure AD / Entra ID)
Allows configuring tenant ID (defaults to `"common"` if `None` is provided):
```rust
use wasi_auth_providers::microsoft;
let config = microsoft::microsoft("client_id", "client_secret", "https://app.com/callback", Some("my-tenant-id"));
```

### Keycloak Preset
Supports self-hosted instances by taking a base server URL and realm name:
```rust
use wasi_auth_providers::keycloak;
let config = keycloak::keycloak(
    "client_id",
    "client_secret",
    "https://app.com/callback",
    "https://keycloak.example.com",
    "myrealm"
);
```

### Other Presets
- `apple::apple(client_id, client_secret, redirect_uri)`
- `facebook::facebook(client_id, client_secret, redirect_uri)`
- `discord::discord(client_id, client_secret, redirect_uri)`
- `x::x(client_id, client_secret, redirect_uri)`
