//! Run this example with:
//! cargo run --example oauth -p wasi-auth-core

use wasi_auth_core::oauth::{Oauth2Client, PkceChallenge};

fn main() {
    println!("=======================================================");
    println!("               WASI OAuth2/PKCE Example                 ");
    println!("=======================================================\n");

    println!("This example demonstrates how to configure OAuth2 parameters and generate");
    println!("secure authentication request flows using pre-defined social presets:\n");

    let client_id = "demo-client-id";
    let client_secret = "demo-client-secret";
    let redirect_uri = "https://my-app.com/login/callback";

    // 1. Google Preset
    println!("1. Loading Google OAuth2 Preset Configuration...");
    let google_config = wasi_auth_providers::google::google(client_id, client_secret, redirect_uri);
    println!("   Google Auth URL:  {}", google_config.auth_url);
    println!("   Google Token URL: {}\n", google_config.token_url);

    // 2. GitHub Preset
    println!("2. Loading GitHub OAuth2 Preset Configuration...");
    let github_config = wasi_auth_providers::github::github(client_id, client_secret, redirect_uri);
    println!("   GitHub Auth URL:  {}", github_config.auth_url);
    println!("   GitHub Token URL: {}\n", github_config.token_url);

    // 3. Keycloak Preset (custom realm)
    println!("3. Loading Keycloak OIDC Preset Configuration...");
    let keycloak_config = wasi_auth_providers::keycloak::keycloak(
        client_id,
        client_secret,
        redirect_uri,
        "https://keycloak.my-org.com",
        "custom-realm",
    );
    println!("   Keycloak Auth URL:  {}", keycloak_config.auth_url);
    println!("   Keycloak Token URL: {}\n", keycloak_config.token_url);

    // 4. Generate PKCE Challenge
    println!("4. Generating PKCE Challenge (Proof Key for Code Exchange)...");
    let pkce = PkceChallenge::generate();
    println!("   Code Verifier:  {}", pkce.code_verifier);
    println!("   Code Challenge: {}\n", pkce.code_challenge);

    // 5. Generate Authorization Redirect URL (using Google preset as example)
    println!("5. Generating Authorization Redirect URL for Google Sign-In...");
    let scope = "openid email profile";
    let state = "secure-random-state-string";
    let auth_url = Oauth2Client::generate_auth_url(&google_config, state, scope, Some(&pkce));

    println!("   Redirect the client's browser to:\n   {}\n", auth_url);
    println!("6. Exchange flow info:");
    println!(
        "   Once the user authorizes and redirects back to your callback with a `code` query parameter,"
    );
    println!(
        "   you perform the token exchange on the server side using the stored `code_verifier`:"
    );
    println!(
        "   `Oauth2Client::exchange_code(&google_config, code, Some(&verifier), &http_client)`\n"
    );
}
