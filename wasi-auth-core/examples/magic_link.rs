//! Run this example with:
//! cargo run --example magic_link -p wasi-auth-core

use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use wasi_auth_core::magic_link::{generate_magic_link, verify_magic_link};
use wasi_auth_traits::InMemoryStorage;

fn main() {
    println!("=======================================================");
    println!("             WASI Magic Link Example                   ");
    println!("=======================================================\n");

    let email = "user@example.com";
    let storage = InMemoryStorage::new();

    // 1. Generate RSA keypair for JWT signing
    println!("1. Generating temporary RSA key pair for JWT signing...");
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate private key");
    let public_key = RsaPublicKey::from(&private_key);

    let private_key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string();
    let public_key_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();
    println!("   Key pair generated successfully.\n");

    // 2. Generate the Magic Link
    println!("2. Generating magic link url...");
    let base_url = "https://my-app.com/login/callback";
    let link = generate_magic_link(
        email,
        base_url,
        &private_key_pem,
        Some("key-1"),
        300, // 5 minute validity
        "my-app-audience",
        "my-app-issuer",
    )
    .expect("Failed to generate magic link");

    println!("   Generated Magic Link:\n   {}\n", link);

    // 3. Extract the token from the link
    let token = link.split("token=").nth(1).unwrap();

    // 4. Verify/consume token (first click)
    println!("3. Verifying the token (simulating first click)...");
    match verify_magic_link(
        token,
        &public_key_pem,
        "my-app-audience",
        "my-app-issuer",
        &storage,
    ) {
        Ok(verified_email) => {
            println!("   ✅ SUCCESS: Authenticated user: {}", verified_email);
            println!("   🔒 Token consumed (JTI added to blacklist).");
        }
        Err(e) => {
            println!("   ❌ ERROR: Verification failed: {:?}", e);
        }
    }

    // 5. Attempt to reuse the token (second click)
    println!("\n4. Re-verifying the same token (simulating second click/replay attack):");
    match verify_magic_link(
        token,
        &public_key_pem,
        "my-app-audience",
        "my-app-issuer",
        &storage,
    ) {
        Ok(verified_email) => {
            println!(
                "   ❌ WARNING: Replay attack succeeded! Verified user: {}",
                verified_email
            );
        }
        Err(e) => {
            println!("   ✅ BLOCKED: Replay attack successfully blocked!");
            println!("   Detail error: {}", e);
        }
    }
}
