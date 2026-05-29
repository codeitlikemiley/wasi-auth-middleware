//! Run this example with:
//! cargo run --example totp -p wasi-auth-core

use hmac::{Hmac, Mac};
use sha1::Sha1;
use wasi_auth_core::totp::{base32_decode, generate_totp_secret, generate_totp_uri, verify_totp};
use wasi_auth_traits::{AuthStorage, InMemoryStorage};

type HmacSha1 = Hmac<Sha1>;

/// Helper function to programmatically generate the current 6-digit TOTP code.
fn get_current_totp_code(secret_b32: &str, time_secs: u64) -> String {
    let secret_bytes = base32_decode(secret_b32).expect("Invalid secret format");
    let current_step = time_secs / 30;
    let step_bytes = current_step.to_be_bytes();
    let mut mac = HmacSha1::new_from_slice(&secret_bytes).unwrap();
    mac.update(&step_bytes);
    let result = mac.finalize();
    let code_bytes = result.into_bytes();

    let offset = (code_bytes[19] & 0x0f) as usize;
    let binary: u32 = (((code_bytes[offset] & 0x7f) as u32) << 24)
        | ((code_bytes[offset + 1] as u32) << 16)
        | ((code_bytes[offset + 2] as u32) << 8)
        | (code_bytes[offset + 3] as u32);

    let totp = binary % 1_000_000;
    format!("{:06}", totp)
}

fn main() {
    println!("=======================================================");
    println!("                 WASI TOTP Example                     ");
    println!("=======================================================\n");

    let email = "dev@example.com";
    let storage = InMemoryStorage::new();

    // 1. Generate a new secret and standard QR Code/Authenticator URI
    let secret = generate_totp_secret();
    let uri = generate_totp_uri(email, &secret, "WasiAuthDemo");

    println!("1. Enroll user (generate secret):");
    println!("   Secret (Base32): {}\n", secret);
    println!("2. Provisioning URI for Authenticator apps:");
    println!("   {}\n", uri);

    // Save user's secret to the storage backend
    storage
        .store_totp_secret(email, &secret)
        .expect("Failed to store secret in DB");

    // 3. Simulate client verification flow
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Generate the correct code for this time step to simulate client input
    let correct_code = get_current_totp_code(&secret, now);
    println!("3. Simulated client code generation:");
    println!("   Current active code: {}\n", correct_code);

    // 4. Verify code against stored secret
    println!("4. Verifying code...");
    let stored_secret = storage.get_totp_secret(email).unwrap().unwrap();
    match verify_totp(&stored_secret, &correct_code, now) {
        Ok(Some(step)) => {
            println!(
                "   ✅ SUCCESS: Code '{}' is valid at step {}!",
                correct_code, step
            );

            // 5. Anti-Replay Attack Check (using JTI blacklist)
            let replay_key = format!("totp:{}:{}", email, step);
            if storage.is_jti_blacklisted(&replay_key).unwrap() {
                println!("   ❌ REPLAY ERROR: Code has already been consumed!");
            } else {
                println!("   🔒 Consuming TOTP step (adding to blacklist)...");
                storage.blacklist_jti(&replay_key, now + 90).unwrap();
                println!("   ✅ Success! TOTP code verified and consumed.");
            }

            // Attempting to re-verify the same code
            println!("\n5. Attempting to verify the same code again (replay attack simulation):");
            if storage.is_jti_blacklisted(&replay_key).unwrap() {
                println!("   ✅ BLOCKED: Replay attack successfully blocked by JTI blacklist!");
            } else {
                println!("   ❌ WARNING: Replay check failed!");
            }
        }
        _ => {
            println!("   ❌ ERROR: Verification failed.");
        }
    }
}
