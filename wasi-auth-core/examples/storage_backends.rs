//! Run this example with:
//! cargo run --example storage_backends -p wasi-auth-core

use wasi_auth_traits::{AuthStorage, SQLiteStorage, SpinKeyValueStorage};

fn main() {
    println!("=======================================================");
    println!("             WASI Storage Backends Example             ");
    println!("=======================================================\n");

    println!("This example demonstrates how to configure and interact with the database drivers");
    println!("used by the WASI Authentication Middleware framework:\n");
    println!("  1. Spin Key-Value Store (SpinKeyValueStorage)");
    println!("  2. Spin SQLite Database (SQLiteStorage)\n");

    // =========================================================
    // 1. Spin Key-Value Storage
    // =========================================================
    println!("-------------------------------------------------------");
    println!("1. Spin Key-Value Storage (SpinKeyValueStorage)");
    println!("-------------------------------------------------------");

    // Instantiating the driver. It connects to the "default" store by default.
    let kv_store = SpinKeyValueStorage::open_default();
    println!("   SpinKeyValueStorage driver initialized.");

    // Attempting storage operations
    let session_id = "test-session-kv-123";
    let user_id = "user@example.com";
    let roles = vec!["admin".to_string(), "editor".to_string()];
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;

    println!("   Attempting to store session in Spin KV...");
    match kv_store.store_session(session_id, user_id, &roles, expires_at) {
        Ok(_) => {
            println!("   ✅ SUCCESS: Session stored in Spin KV store!");
            // Read back
            if let Ok(Some(session)) = kv_store.get_session(session_id) {
                println!(
                    "   ✅ SUCCESS: Retrieved session for user: {}",
                    session.user_id
                );
            }
        }
        Err(e) => {
            println!("   ⚠️  INFO (Expected Native Behavior):");
            println!("      Store operation returned: {}", e);
            println!("      Reason: Spin KV store APIs are only available when running inside the");
            println!(
                "              Spin/Wasmtime WebAssembly runtime environment compiled for wasm32-wasi."
            );
        }
    }
    println!();

    // =========================================================
    // 2. Spin SQLite Storage
    // =========================================================
    println!("-------------------------------------------------------");
    println!("2. Spin SQLite Storage (SQLiteStorage)");
    println!("-------------------------------------------------------");

    // Instantiating the driver. It connects to the "default" database.
    let sqlite_store = SQLiteStorage::open_default();
    println!("   SQLiteStorage driver initialized.");

    println!("   Attempting to store OTP secret in SQLite...");
    let email = "dev@example.com";
    let secret = "JBSWY3DPEHPK3PXP"; // Base32 test secret

    match sqlite_store.store_totp_secret(email, secret) {
        Ok(_) => {
            println!("   ✅ SUCCESS: TOTP secret stored in SQLite database!");
            // Read back
            if let Ok(Some(stored_secret)) = sqlite_store.get_totp_secret(email) {
                println!("   ✅ SUCCESS: Retrieved secret: {}", stored_secret);
            }
        }
        Err(e) => {
            println!("   ⚠️  INFO (Expected Native Behavior):");
            println!("      Store operation returned: {}", e);
            println!("      Reason: Spin SQLite APIs are only available when running inside the");
            println!(
                "              Spin/Wasmtime WebAssembly runtime environment compiled for wasm32-wasi."
            );
        }
    }
    println!("\n=======================================================");
    println!("For a complete end-to-end local integration run:");
    println!("  just check");
    println!("This compiles the codebase target to wasm32-wasip2 and executes");
    println!("the composed component under simulated Wasmtime runtime mock environments.");
    println!("=======================================================");
}
