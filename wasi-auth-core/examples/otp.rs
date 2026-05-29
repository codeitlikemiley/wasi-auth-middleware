//! Run this example with:
//! cargo run --example otp -p wasi-auth-core

use wasi_auth_core::otp::{send_and_store_otp, verify_otp};
use wasi_auth_traits::{InMemoryRateLimiter, InMemoryStorage, StdoutEmail};

fn main() {
    println!("=======================================================");
    println!("                 WASI Email OTP Example                ");
    println!("=======================================================\n");

    let email = "user@example.com";
    let storage = InMemoryStorage::new();
    // In this example, we use StdoutEmail which outputs the email content to stdout.
    // In production, you can enable the "http-email" feature and use HttpEmail to post email payloads 
    // to your external email APIs (like SendGrid, Mailgun, AWS SES, or a custom microservice):
    //
    // #[cfg(feature = "http-email")]
    // let sender = wasi_auth_traits::HttpEmail::new("https://your-email-service.com/send".to_string());
    let sender = StdoutEmail::new();
    
    // 10-second window, limit 2 attempts
    let limiter = InMemoryRateLimiter::new(10, 2);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 1. Send OTP
    println!("1. Requesting OTP for {}...", email);
    let otp = send_and_store_otp(email, &storage, &sender, 300, now, Some(&limiter))
        .expect("Failed to send/store OTP");

    println!("   OTP generated: {}", otp);
    println!("   Stored in Database with 5 minute expiration.\n");

    // 2. Rate limit simulation: send a 2nd time
    println!("2. Requesting 2nd OTP (within limit)...");
    let otp2 = send_and_store_otp(email, &storage, &sender, 300, now, Some(&limiter))
        .expect("Failed to send 2nd OTP");
    println!("   ✅ Success: 2nd OTP generated: {}\n", otp2);

    // Requesting a 3rd time should trigger the rate limiter
    println!("3. Requesting 3rd OTP (exceeding limit)...");
    match send_and_store_otp(email, &storage, &sender, 300, now, Some(&limiter)) {
        Ok(_) => println!("   ❌ WARNING: Rate limit was not enforced!"),
        Err(e) => {
            println!("   ✅ BLOCKED: Rate limit enforced successfully!");
            println!("   Error detail: {}", e);
        }
    }
    println!();

    // 3. Verify OTP
    println!("4. Verifying the correct OTP...");
    // Let's verify the most recent one we generated
    match verify_otp(email, &otp2, &storage, None) {
        Ok(true) => {
            println!("   ✅ SUCCESS: OTP verified successfully!");
        }
        Ok(false) => {
            println!("   ❌ ERROR: Verification failed (unexpected invalid code).");
        }
        Err(e) => {
            println!("   ❌ ERROR: Verification failed: {}", e);
        }
    }
    println!();

    // OTP should be consumed now
    println!("5. Attempting to verify the same OTP again (consumption check)...");
    match verify_otp(email, &otp2, &storage, None) {
        Ok(true) => {
            println!("   ❌ WARNING: OTP was not consumed on first verification!");
        }
        Ok(false) => {
            println!("   ✅ BLOCKED: OTP was successfully consumed and cannot be reused.");
        }
        Err(e) => {
            println!("   ❌ ERROR: Verification error: {}", e);
        }
    }
}
