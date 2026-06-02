# wasi-auth-traits

Core trait abstractions and pluggable storage/service interfaces for the `wasi-auth-middleware` ecosystem.

This crate defines the contracts that allow different storage engines, email dispatch systems, and rate limiters to integrate seamlessly with the WASI Authentication Middleware.

## Purpose

The primary purpose of this crate is to provide a clean, pluggable architecture. By coding against these traits, the core authentication middleware remains independent of specific cloud providers, databases, or runtime-specific system calls (like Spin KV or SQLite).

## Setup & Dependency Features

Add the following to your `Cargo.toml`:

```toml
[dependencies]
wasi-auth-traits = { version = "0.1.0", path = "../wasi-auth-traits" }
```

### Feature Flags

- **`hash-otp`** *(default)* — Enables Argon2 password/OTP hashing and verification utilities via the `argon2` and `rand_core` crates.
- **`spin`** — Enables `SpinKeyValueStorage`, using the WebAssembly Spin SDK's key-value store. This is target-gated and only compiles/runs on `wasm32-wasi` targets.
- **`sqlite`** — Enables `SQLiteStorage`, using the WebAssembly Spin SDK's SQLite database interface. This is also target-gated to `wasm32-wasi` targets.
- **`http-email`** — Enables the HTTP-based email client `HttpEmail` using `spin-sdk` on Wasm targets and `ureq` on native platforms.
- **`passkey`** — Enables passkey (WebAuthn) helper wrappers and trait definitions via `passkey-server` and `async-trait`.

## Key APIs

### 1. `AuthStorage` Trait
Defines how sessions and One-Time Passwords (OTPs) are stored, retrieved, and verified.
```rust
pub trait AuthStorage {
    fn store_session(&self, session_id: &str, user_id: &str, roles: &[String], expires_at: u64) -> Result<(), AuthError>;
    fn get_session(&self, session_id: &str) -> Result<Option<Session>, AuthError>;
    fn delete_session(&self, session_id: &str) -> Result<(), AuthError>;
    fn store_otp(&self, email: &str, otp: &str, expires_at: u64) -> Result<(), AuthError>;
    fn verify_otp(&self, email: &str, otp: &str) -> Result<bool, AuthError>;
    // ... and more (TOTP, JTI blacklisting, etc.)
}
```

### 2. `EmailSender` Trait
Defines the interface for sending transactional emails (like OTPs) to users.
```rust
pub trait EmailSender {
    fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), AuthError>;
}
```

### 3. `RateLimiter` Trait
Defines standard checks and tracking for incoming request rate limits (e.g. key/action based).
```rust
pub trait RateLimiter {
    fn check_rate_limit(&self, key: &str, action: &str) -> Result<bool, AuthError>;
    fn record_action(&self, key: &str, action: &str) -> Result<(), AuthError>;
}
```

### 4. `Session` Struct
Represents an active, authenticated user session carrying user ID, roles, and expiry timestamp.

## Provided Implementations

- **`InMemoryStorage`** — A thread-safe, in-memory (`RwLock<HashMap>`) storage implementation, perfect for testing and local development.
- **`InMemoryRateLimiter`** — A thread-safe sliding window rate limiter backed by in-memory history.
- **`StdoutEmail`** — An email sender that writes messages to standard output (useful during development).

## Usage & Implementation Guide

### 1. Initializing and Using Provided Drivers

Here is an example showing how to initialize `InMemoryStorage` and `StdoutEmail`, which are available out of the box:

```rust,ignore
use wasi_auth_traits::{AuthStorage, EmailSender, InMemoryStorage, StdoutEmail};

fn main() -> Result<(), wasi_auth_traits::AuthError> {
    // 1. Initialize thread-safe in-memory storage
    let storage = InMemoryStorage::new();

    // 2. Store a session (expires in 1 hour)
    let expires_at = chrono::Utc::now().timestamp() as u64 + 3600;
    storage.store_session(
        "session_id_123",
        "user_alice",
        &["user".to_string(), "admin".to_string()],
        expires_at
    )?;

    // 3. Retrieve and inspect the session
    if let Some(session) = storage.get_session("session_id_123")? {
        println!("User: {}, Roles: {:?}", session.user_id, session.roles);
    }

    // 4. Initialize StdoutEmail sender
    let email_sender = StdoutEmail::new();
    email_sender.send_email(
        "alice@example.com",
        "Your Verification Code",
        "Welcome! Your code is 556677."
    )?;

    Ok(())
}
```

### 2. Implementing a Custom Storage Driver (e.g. Postgres/Redis)

You can plug in your own database backend by implementing the `AuthStorage` trait. Below is a simplified example implementing the trait for a hypothetical database connection:

```rust,ignore
use wasi_auth_traits::{AuthStorage, AuthError, Session};

pub struct MyDbStorage {
    // db_pool: DbPool,
}

impl AuthStorage for MyDbStorage {
    fn store_session(
        &self,
        session_id: &str,
        user_id: &str,
        roles: &[String],
        expires_at: u64,
    ) -> Result<(), AuthError> {
        // Run SQL query:
        // "INSERT INTO sessions (id, user_id, roles, expires_at) VALUES ($1, $2, $3, $4)"
        Ok(())
    }

    fn get_session(&self, session_id: &str) -> Result<Option<Session>, AuthError> {
        // Run SQL query:
        // "SELECT user_id, roles, expires_at FROM sessions WHERE id = $1"
        // and return Session on match
        Ok(None)
    }

    fn delete_session(&self, session_id: &str) -> Result<(), AuthError> {
        // Run SQL query:
        // "DELETE FROM sessions WHERE id = $1"
        Ok(())
    }

    fn store_otp(&self, email: &str, otp: &str, expires_at: u64) -> Result<(), AuthError> {
        // Run SQL query to insert hashed OTP
        Ok(())
    }

    fn verify_otp(&self, email: &str, otp: &str) -> Result<bool, AuthError> {
        // Fetch and check OTP hash
        Ok(true)
    }

    // Include other optional methods if using TOTP, Passkeys, etc.
}
```
