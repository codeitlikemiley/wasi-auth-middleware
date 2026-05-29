//! Run this example with:
//! cargo run --example oauth -p wasi-auth-core

use wasi_auth_core::oauth::{OAuthConfig, Oauth2Client, PkceChallenge};

fn main() {
    println!("=======================================================");
    println!("               WASI OAuth2/PKCE Example                 ");
    println!("=======================================================\n");

    // 1. Define configuration preset for Google
    let config = OAuthConfig {
        client_id: "google-client-id-xyz".to_string(),
        client_secret: "google-client-secret-123".to_string(),
        auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
        token_url: "https://oauth2.googleapis.com/token".to_string(),
        userinfo_url: Some("https://openidconnect.googleapis.com/v1/userinfo".to_string()),
        redirect_uri: "https://my-app.com/login/callback".to_string(),
    };

    println!("1. OAuth2 Client Configuration loaded:");
    println!("   Client ID:    {}", config.client_id);
    println!("   Redirect URI: {}\n", config.redirect_uri);

    // 2. Generate PKCE Challenge
    println!("2. Generating PKCE Challenge (Proof Key for Code Exchange)...");
    let pkce = PkceChallenge::generate();
    println!("   Code Verifier:  {}", pkce.code_verifier);
    println!("   Code Challenge: {}\n", pkce.code_challenge);

    // 3. Generate Authorization Redirect URL
    println!("3. Generating Authorization Redirect URL...");
    let scope = "openid email profile";
    let state = "secure-random-state-string";
    let auth_url = Oauth2Client::generate_auth_url(&config, state, scope, Some(&pkce));

    println!("   Redirect the client's browser to:\n   {}\n", auth_url);
    println!("4. Exchange flow info:");
    println!(
        "   Once the user authorizes and redirects back to your callback with a `code` query parameter,"
    );
    println!(
        "   you perform the token exchange on the server side using the stored `code_verifier`:"
    );
    println!("   `Oauth2Client::exchange_code(&config, code, Some(&verifier), &http_client)`\n");
}
