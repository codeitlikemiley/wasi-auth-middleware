//! Complete example demonstrating Passkey (WebAuthn) registration and login ceremonies.
//!
//! This example shows how to:
//! 1. Configure the relying party (RP) and initialize an in-memory credential storage.
//! 2. Initiate passkey registration, returning options to the client browser.
//! 3. Complete registration by verifying the client's public key attestation.
//! 4. Initiate login, returning a challenge to the client browser.
//! 5. Complete login by verifying the client's signature assertion.
//!
//! To run this example:
//!   cargo run --example passkey_demo --all-features

use base64::prelude::*;
use coset::{Algorithm, CborSerializable, CoseKey, KeyType, Label, iana};
use p256::SecretKey;
use p256::ecdsa::{SigningKey, VerifyingKey, signature::Signer};
use p256::elliptic_curve::rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use wasi_auth_core::passkey::*;
use wasi_auth_traits::InMemoryStorage;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enable logging
    tracing_subscriber::fmt::init();
    println!("=== Passkey (WebAuthn) Ceremony Demo ===");

    // 1. Initialize our Relying Party (RP) configuration and storage backend
    let config = PasskeyConfig {
        rp_id: "example.com".to_string(),
        rp_name: "My Secure Service".to_string(),
        origin: "https://example.com".to_string(),
        state_ttl: 300, // Ephemeral challenges valid for 5 minutes
    };
    let store = InMemoryStorage::new();

    let user_id = "usr_123456";
    let username = "alice@example.com";
    let display_name = "Alice Liddell";

    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;

    // ==========================================
    // CEREMONY 1: Passkey Registration (Create)
    // ==========================================
    println!("\n--- 1. Starting Passkey Registration ---");
    let reg_options =
        start_passkey_registration(&store, user_id, username, display_name, &config, now_ms)
            .await?;

    println!(
        "Registration Challenge Generated: {}",
        reg_options.challenge
    );
    println!("Credential creation options serialized successfully!");

    // --- Simulating Browser Client Behavior (Create) ---
    // The browser client receives `reg_options` and calls:
    // navigator.credentials.create({ publicKey: reg_options })
    // The client generates a new key pair and returns the attestation.
    println!("\n[Client] Generating P-256 key pair and attestation...");
    let challenge = reg_options.challenge;
    let client_data_json = make_client_data(&challenge, &config.origin, "webauthn.create");

    // Client key pair
    let secret_key = SecretKey::random(&mut OsRng);
    let signing_key = SigningKey::from(secret_key);
    let public_key = VerifyingKey::from(&signing_key);
    let cose_key = make_cose_key(&public_key);

    let cred_id = b"credential_id_abcd";

    // Build authenticator data (flags: User Present + Attested Credential Data)
    let auth_data = make_auth_data(&config.rp_id, 0x41, 0, Some(cred_id), Some(&cose_key));
    let attestation_object = make_attestation_object(&auth_data);

    let reg_response = RegistrationResponse {
        id: BASE64_URL_SAFE_NO_PAD.encode(cred_id),
        raw_id: BASE64_URL_SAFE_NO_PAD.encode(cred_id),
        type_: "public-key".to_string(),
        response: AttestationResponse {
            client_data_json,
            attestation_object,
        },
        client_extension_results: None,
        name: Some("Alice's MacBook Pro".to_string()),
    };
    println!("[Client] Attestation response package generated.");

    // --- Back to Server ---
    println!("\n--- 2. Finishing Passkey Registration ---");
    finish_passkey_registration(&store, user_id, &config, reg_response, now_ms).await?;
    println!("Passkey successfully registered and saved to InMemoryStorage!");

    // ==========================================
    // CEREMONY 2: Passkey Authentication (Login)
    // ==========================================
    println!("\n--- 3. Starting Passkey Login ---");
    let login_options = start_passkey_login(&store, &config, now_ms).await?;
    println!("Login Challenge Generated: {}", login_options.challenge);

    // --- Simulating Browser Client Behavior (Get) ---
    // The browser client receives `login_options` and calls:
    // navigator.credentials.get({ publicKey: login_options })
    println!("\n[Client] Signing login assertion with registered key...");
    let login_challenge = login_options.challenge;
    let login_client_data_json = make_client_data(&login_challenge, &config.origin, "webauthn.get");
    let login_client_data_bytes = BASE64_URL_SAFE_NO_PAD.decode(&login_client_data_json)?;

    let login_auth_data = make_auth_data(&config.rp_id, 0x01, 1, None, None); // User Present, Counter = 1

    let login_client_data_hash = Sha256::digest(&login_client_data_bytes);
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&login_auth_data);
    signed_data.extend_from_slice(&login_client_data_hash);

    // Sign the credential using client private key
    let signature: p256::ecdsa::Signature = signing_key.sign(&signed_data);
    let signature_der = signature.to_der();
    let signature_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature_der.as_bytes());

    let login_response = LoginResponse {
        id: BASE64_URL_SAFE_NO_PAD.encode(cred_id),
        raw_id: BASE64_URL_SAFE_NO_PAD.encode(cred_id),
        type_: "public-key".to_string(),
        response: AssertionResponse {
            client_data_json: login_client_data_json,
            authenticator_data: BASE64_URL_SAFE_NO_PAD.encode(&login_auth_data),
            signature: signature_b64,
            user_handle: Some(BASE64_URL_SAFE_NO_PAD.encode(user_id.as_bytes())),
        },
        client_extension_results: None,
    };
    println!("[Client] Assertion signature response generated.");

    // --- Back to Server ---
    println!("\n--- 4. Finishing Passkey Login ---");
    let authenticated_user_id =
        finish_passkey_login(&store, &config, login_response, now_ms).await?;
    println!("Assertion verified successfully!");
    println!(
        "User successfully authenticated as user ID: {}",
        authenticated_user_id
    );
    assert_eq!(authenticated_user_id, user_id);

    println!("\n=== All Ceremonies Completed and Verified Successfully ===");
    Ok(())
}

// === Helper functions to mock client WebAuthn payload creation ===

fn make_client_data(challenge: &str, origin: &str, type_: &str) -> String {
    let json = serde_json::json!({
        "challenge": challenge,
        "origin": origin,
        "type": type_,
    });
    let bytes = serde_json::to_vec(&json).unwrap();
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

fn make_cose_key(public_key: &VerifyingKey) -> Vec<u8> {
    let encoded = public_key.to_encoded_point(false);
    let x = encoded.x().unwrap().as_slice();
    let y = encoded.y().unwrap().as_slice();

    let key = CoseKey {
        kty: KeyType::Assigned(iana::KeyType::EC2),
        key_id: vec![],
        alg: Some(Algorithm::Assigned(iana::Algorithm::ES256)),
        key_ops: Default::default(),
        base_iv: vec![],
        params: vec![
            (Label::Int(-1), coset::cbor::value::Value::Integer(1.into())), // P-256
            (Label::Int(-2), coset::cbor::value::Value::Bytes(x.to_vec())), // x
            (Label::Int(-3), coset::cbor::value::Value::Bytes(y.to_vec())), // y
        ],
    };
    key.to_vec().unwrap()
}

fn make_auth_data(
    rp_id: &str,
    flags: u8,
    counter: u32,
    cred_id: Option<&[u8]>,
    public_key: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let hash = Sha256::digest(rp_id.as_bytes());
    buf.extend_from_slice(&hash);
    buf.push(flags);
    buf.extend_from_slice(&counter.to_be_bytes());

    if let (Some(cid), Some(pk)) = (cred_id, public_key) {
        buf.extend_from_slice(&[0u8; 16]); // AAGUID
        buf.extend_from_slice(&(cid.len() as u16).to_be_bytes());
        buf.extend_from_slice(cid);
        buf.extend_from_slice(pk);
    }
    buf
}

fn make_attestation_object(auth_data: &[u8]) -> String {
    let map = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("fmt".to_string()),
            ciborium::value::Value::Text("none".to_string()),
        ),
        (
            ciborium::value::Value::Text("attStmt".to_string()),
            ciborium::value::Value::Map(vec![]),
        ),
        (
            ciborium::value::Value::Text("authData".to_string()),
            ciborium::value::Value::Bytes(auth_data.to_vec()),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&map, &mut bytes).unwrap();
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}
