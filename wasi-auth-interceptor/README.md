# wasi-auth-interceptor

A standalone WASI HTTP middleware component that acts as an **authentication proxy** in a [WebAssembly Component Model](https://component-model.bytecodealliance.org/) composition pipeline.

## How It Works

The interceptor **imports** `wasi:http/incoming-handler@0.2.9` (the downstream application) and **exports** the same interface, allowing it to sit transparently between the HTTP runtime and your application component.

```text
┌──────────┐      ┌──────────────────────┐      ┌─────────────┐
│  Client  │─────▶│  wasi-auth-interceptor│─────▶│  Your App   │
└──────────┘      └──────────────────────┘      └─────────────┘
```

## Security Behaviour

1. **Header stripping** — All `X-User-*` headers (`X-User-Id`, `X-User-Roles`, `X-User-Email`, `X-User-Name`) are **deleted** from every incoming request before any other processing. This prevents upstream clients from spoofing identity headers.
2. **Public path bypass** — Requests to paths that match the configured public path patterns are forwarded directly to the downstream component **without** authentication.
3. **JWT verification** — For all other paths, a JWT token is extracted from cookies (`jwt`, `session`, `__Host-jwt`, `__Host-session`, `__Secure-jwt`, `__Secure-session`) or the `Authorization: Bearer <token>` header.
4. **Authenticated requests** — On successful verification the interceptor injects the following headers before forwarding to the downstream app:
   - `X-User-Id` — the `sub` claim
   - `X-User-Roles` — comma-separated role list
   - `X-User-Email` — *(if present in claims)*
   - `X-User-Name` — *(if present in claims)*
5. **Unauthenticated requests** — When authentication fails:
   - `POST`, `PUT`, `DELETE`, `PATCH`, or any path starting with `/api/` → **401 Unauthorized** response.
   - All other methods → **302 Redirect** to the login redirect URL.

## Configuration

### Environment Variables

The interceptor can be configured using the following environment variables:

| Variable | Default | Description |
|---|---|---|
| `WASI_AUTH_CONFIG` | `wasi-auth.toml` | Path to the TOML configuration file. |
| `WASI_AUTH_PUBLIC_PATHS` | (See defaults below) | Comma-separated list of paths to bypass authentication. |
| `WASI_AUTH_LOGIN_REDIRECT` | `/login` | URL to redirect unauthenticated browser requests. |
| `JWT_PUBLIC_KEY` | None | PEM-encoded public key for RS256 signature verification. |
| `JWT_AUDIENCE` | None | Expected `aud` claim value. |
| `JWT_ISSUER` | None | Expected `iss` claim value. |

### Default Public Paths

If no configuration overrides are provided, the following paths bypass authentication:
- `/`
- `/login`
- `/signup`
- `/pkg/*`
- `/static/*`
- `/health`

### TOML Configuration File

Under the `[auth]` section, you can configure public paths and redirect targets:

```toml
[auth]
public_paths = ["/", "/login", "/signup", "/pkg/*", "/static/*", "/health"]
login_redirect = "/login"
```

> **Note on `[jwt]` section in TOML**: While the configuration parser contains a `[jwt]` section for fields like `public_key_path`, `audience`, and `issuer`, **the interceptor does not currently support these settings at runtime**. At runtime, cryptographic verification only checks the environment variables (`JWT_PUBLIC_KEY`, `JWT_AUDIENCE`, `JWT_ISSUER`).

### Silent Unsafe Fallback

If any of the verification environment variables (`JWT_PUBLIC_KEY`, `JWT_AUDIENCE`, or `JWT_ISSUER`) is missing, the interceptor silently falls back to **unsafe JWT verification**. Under this fallback:
- Signature verification is bypassed entirely.
- The JWT's payload claims are decoded.
- Token expiration (`exp`) is still validated with a 60-second grace window.

## Setup & Features

### Compilation

This crate is compiled as a WebAssembly Component (`cdylib` crate-type). It generates bindings using `wit-bindgen` for the `wasi:http` world.

### Cargo Features

- `config-file` (enabled by default): Enables loading configurations from a TOML file. Disabling this removes the `toml` dependency and forces configuration to rely solely on environment variables.
