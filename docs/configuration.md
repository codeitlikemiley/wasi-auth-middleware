# Configuration Reference

This document serves as the single source of truth for runtime configurations, environment variables, file-based options, cookie security levels, and configuration schemas.

---

## Environment Variables

### Standalone Interceptor Configurations

The interceptor reads configuration from environment variables and an optional TOML configuration file.

| Variable | Required | Default | Description |
|---|---|---|---|
| `JWT_PUBLIC_KEY` | No* | None | PEM-encoded RSA public key for cryptographic signature verification. |
| `JWT_AUDIENCE` | No* | None | Expected JWT `aud` claim value. |
| `JWT_ISSUER` | No* | None | Expected JWT `iss` claim value. |
| `WASI_AUTH_CONFIG` | No | `wasi-auth.toml` | File path to load the TOML configuration block. |
| `WASI_AUTH_PUBLIC_PATHS` | No | *(see default)* | Comma-separated list of paths/patterns bypassing authentication. |
| `WASI_AUTH_LOGIN_REDIRECT` | No | `/login` | URL to redirect unauthenticated GET requests to. |

> **\* Silent Unsafe JWT Verification Fallback:** If **any** of the cryptographic verification environment variables (`JWT_PUBLIC_KEY`, `JWT_AUDIENCE`, or `JWT_ISSUER`) are missing or blank, the interceptor silently falls back to **unsafe JWT parsing**. In this mode, the JWT claims payload is decoded without signature validation, but token expiration (`exp`) is still checked (with a 60-second grace window). This is strictly for development and testing. Do not use this fallback in production.

### Leptos Integration Configurations

| Variable | Default | Description |
|---|---|---|
| `TRUST_PROXY_HEADERS` | `false` | Trust `X-User-*` headers from upstream proxy |
| `WASI_AUTH_TRUST_PROXY_HEADERS` | `false` | Alias for `TRUST_PROXY_HEADERS` |

---

## TOML Configuration File Schema

By default, the interceptor searches for `wasi-auth.toml` (which can be overridden by `WASI_AUTH_CONFIG`).

- **`[auth]` Section (Supported)**:
  - `public_paths` (array of strings): Paths matching these patterns bypass verification. Suffix wildcards (e.g. `/static/*`) are supported.
  - `login_redirect` (string): Redirect location for unauthenticated requests.
- **`[jwt]` Section (Ignored)**:
  - Properties under `[jwt]` (e.g. `public_key_path`, `audience`, `issuer`) are parsed into the configuration struct but **ignored** during runtime verification. Cryptographic JWT verification requires the `JWT_PUBLIC_KEY`, `JWT_AUDIENCE`, and `JWT_ISSUER` environment variables to be set.

### Example `wasi-auth.toml`
```toml
[auth]
public_paths = [
    "/",
    "/login",
    "/signup",
    "/static/*",
    "/pkg/*"
]
login_redirect = "/login"

[jwt]
# These keys are parsed but ignored at runtime. Ensure you bind the values as environment variables instead!
audience = "my-application"
issuer = "https://auth.example.com"
```

---

## Default Public Paths

If no custom public paths are provided via environment variables or TOML configuration, the interceptor defaults to bypassing authentication for the following routes:
- `/`
- `/login`
- `/signup`
- `/pkg/*` (static WASM/JS web bundles)
- `/static/*` (assets, CSS, images)
- `/health` (health check endpoints)

---

## Cookie Precedence

When extracting JWT tokens from cookies, the following precedence order is used (highest to lowest priority):

| Priority | Cookie Name | Security Level | Description |
|---|---|---|---|
| 1 | `__Host-jwt` | Highest (host-bound) | Secure, HTTP-only, cookie restricted to the host that set it. |
| 2 | `__Host-session` | Host-bound | Host-bound session cookie fallback. |
| 3 | `__Secure-jwt` | Secure (HTTPS-only) | Requires secure HTTPS connection to be transmitted. |
| 4 | `__Secure-session` | Secure | Secure session cookie fallback. |
| 5 | `jwt` | Standard | Standard cookie prefix. |
| 6 | `session` | Lowest | Standard session cookie fallback. |

---

## Rate-Limiter Configuration Parameters

To protect authentication endpoints, request rate limits can be set using the `RateLimiter` trait. The default `InMemoryRateLimiter` uses a sliding window (default: 900 seconds / 15 minutes) and supports setting custom limits:

- **Sliding Window**: 900 seconds (15 minutes).
- **Default Action Limit**: 100 requests.
- **Action `"send_otp"` Limit**: 5 requests.
- **Action `"verify_otp"` Limit**: 10 requests.

Custom limits can be registered via code using:
```rust
limiter.with_limit("custom_action", 20);
```

---

## Provider Preset Reference

The `wasi-auth-providers` crate provides ready-to-use client presets for external OIDC/OAuth2 integrations. Below is the configuration reference for the presets:

- **Google**: `google::google(client_id, client_secret, redirect_uri)`
  - *Endpoints*:
    - Authorization: `https://accounts.google.com/o/oauth2/v2/auth`
    - Token: `https://oauth2.googleapis.com/token`
    - Userinfo: `https://openidconnect.googleapis.com/v1/userinfo`
- **GitHub**: `github::github(client_id, client_secret, redirect_uri)`
  - *Endpoints*:
    - Authorization: `https://github.com/login/oauth/authorize`
    - Token: `https://github.com/login/oauth/access_token`
    - Userinfo: `https://api.github.com/user`
- **Apple**: `apple::apple(client_id, client_secret, redirect_uri)`
  - *Endpoints*:
    - Authorization: `https://appleid.apple.com/auth/authorize`
    - Token: `https://appleid.apple.com/auth/token`
  - *Note*: Userinfo is not supported by the standard Apple OIDC endpoint.
- **Microsoft**: `microsoft::microsoft(client_id, client_secret, redirect_uri, tenant_id)`
  - *Endpoints*:
    - Authorization: `/oauth2/v2.0/authorize`
    - Token: `/oauth2/v2.0/token`
    - Userinfo: `https://graph.microsoft.com/oidc/userinfo`
  - *Note*: Uses `tenant_id` (defaults to `"common"` if `None` is provided).
- **Facebook**: `facebook::facebook(client_id, client_secret, redirect_uri)`
  - *Endpoints*:
    - Authorization: `/dialog/oauth`
    - Token: `/oauth2/access_token`
    - Userinfo: `/me?fields=id,name,email`
- **Discord**: `discord::discord(client_id, client_secret, redirect_uri)`
  - *Endpoints*:
    - Authorization: `/api/oauth2/authorize`
    - Token: `/api/oauth2/token`
    - Userinfo: `/api/users/@me`
- **X (Twitter)**: `x::x(client_id, client_secret, redirect_uri)`
  - *Endpoints*:
    - Authorization: `/i/oauth2/authorize`
    - Token: `/2/oauth2/token`
    - Userinfo: `/2/users/me`
- **Keycloak**: `keycloak::keycloak(client_id, client_secret, redirect_uri, server_url, realm)`
  - *Endpoints*: Constructs endpoints dynamically based on the Keycloak server URL and realm path prefix: `/realms/{realm}/protocol/openid-connect`.
