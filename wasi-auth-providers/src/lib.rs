//! Ready-to-use OAuth2 provider presets for the `wasi-auth` middleware framework.

#[cfg(any(
    feature = "google",
    feature = "github",
    feature = "apple",
    feature = "microsoft",
    feature = "facebook",
    feature = "discord",
    feature = "x",
    feature = "keycloak"
))]
use wasi_auth_core::OAuthConfig;

#[cfg(feature = "google")]
pub mod google {
    use super::*;

    /// Constructs the OAuthConfig preset for Google OAuth 2.0.
    pub fn google(client_id: &str, client_secret: &str, redirect_uri: &str) -> OAuthConfig {
        OAuthConfig {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            userinfo_url: Some("https://openidconnect.googleapis.com/v1/userinfo".to_string()),
            redirect_uri: redirect_uri.to_string(),
        }
    }
}

#[cfg(feature = "github")]
pub mod github {
    use super::*;

    /// Constructs the OAuthConfig preset for GitHub OAuth 2.0.
    pub fn github(client_id: &str, client_secret: &str, redirect_uri: &str) -> OAuthConfig {
        OAuthConfig {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            userinfo_url: Some("https://api.github.com/user".to_string()),
            redirect_uri: redirect_uri.to_string(),
        }
    }
}

#[cfg(feature = "apple")]
pub mod apple {
    use super::*;

    /// Constructs the OAuthConfig preset for Sign in with Apple.
    pub fn apple(client_id: &str, client_secret: &str, redirect_uri: &str) -> OAuthConfig {
        OAuthConfig {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://appleid.apple.com/auth/authorize".to_string(),
            token_url: "https://appleid.apple.com/auth/token".to_string(),
            userinfo_url: None,
            redirect_uri: redirect_uri.to_string(),
        }
    }
}

#[cfg(feature = "microsoft")]
pub mod microsoft {
    use super::*;

    /// Constructs the OAuthConfig preset for Microsoft Entra ID (Azure AD).
    ///
    /// If `tenant_id` is `None`, `"common"` is used for multi-tenant apps.
    pub fn microsoft(
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        tenant_id: Option<&str>,
    ) -> OAuthConfig {
        let tenant = tenant_id.unwrap_or("common");
        OAuthConfig {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
                tenant
            ),
            token_url: format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                tenant
            ),
            userinfo_url: Some("https://graph.microsoft.com/oidc/userinfo".to_string()),
            redirect_uri: redirect_uri.to_string(),
        }
    }
}

#[cfg(feature = "facebook")]
pub mod facebook {
    use super::*;

    /// Constructs the OAuthConfig preset for Facebook Login.
    pub fn facebook(client_id: &str, client_secret: &str, redirect_uri: &str) -> OAuthConfig {
        OAuthConfig {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://www.facebook.com/v19.0/dialog/oauth".to_string(),
            token_url: "https://graph.facebook.com/v19.0/oauth/access_token".to_string(),
            userinfo_url: Some("https://graph.facebook.com/me?fields=id,name,email".to_string()),
            redirect_uri: redirect_uri.to_string(),
        }
    }
}

#[cfg(feature = "discord")]
pub mod discord {
    use super::*;

    /// Constructs the OAuthConfig preset for Discord Login.
    pub fn discord(client_id: &str, client_secret: &str, redirect_uri: &str) -> OAuthConfig {
        OAuthConfig {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://discord.com/api/oauth2/authorize".to_string(),
            token_url: "https://discord.com/api/oauth2/token".to_string(),
            userinfo_url: Some("https://discord.com/api/users/@me".to_string()),
            redirect_uri: redirect_uri.to_string(),
        }
    }
}

#[cfg(feature = "x")]
pub mod x {
    use super::*;

    /// Constructs the OAuthConfig preset for X (formerly Twitter) OAuth 2.0.
    pub fn x(client_id: &str, client_secret: &str, redirect_uri: &str) -> OAuthConfig {
        OAuthConfig {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://twitter.com/i/oauth2/authorize".to_string(),
            token_url: "https://api.twitter.com/2/oauth2/token".to_string(),
            userinfo_url: Some("https://api.twitter.com/2/users/me".to_string()),
            redirect_uri: redirect_uri.to_string(),
        }
    }
}

#[cfg(feature = "keycloak")]
pub mod keycloak {
    use super::*;

    /// Constructs the OAuthConfig preset for a custom Keycloak realm.
    pub fn keycloak(
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        server_url: &str,
        realm: &str,
    ) -> OAuthConfig {
        let base = server_url.trim_end_matches('/');
        OAuthConfig {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: format!("{}/realms/{}/protocol/openid-connect/auth", base, realm),
            token_url: format!("{}/realms/{}/protocol/openid-connect/token", base, realm),
            userinfo_url: Some(format!(
                "{}/realms/{}/protocol/openid-connect/userinfo",
                base, realm
            )),
            redirect_uri: redirect_uri.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "google")]
    #[test]
    fn test_google_preset() {
        let conf = super::google::google("client", "secret", "https://redirect");
        assert_eq!(conf.client_id, "client");
        assert_eq!(conf.client_secret, "secret");
        assert_eq!(
            conf.auth_url,
            "https://accounts.google.com/o/oauth2/v2/auth"
        );
    }

    #[cfg(feature = "keycloak")]
    #[test]
    fn test_keycloak_preset() {
        let conf = super::keycloak::keycloak(
            "client",
            "secret",
            "https://redirect",
            "https://keycloak.example.com/",
            "myrealm",
        );
        assert_eq!(
            conf.auth_url,
            "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/auth"
        );
    }
}
