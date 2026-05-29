use serde::Deserialize;

/// Configuration for the authentication interceptor.
#[derive(Debug, Clone, Deserialize)]
pub struct InterceptorConfig {
    /// Authentication route configuration.
    pub auth: AuthSection,
    /// Optional JWT signature verification configuration.
    pub jwt: Option<JwtSection>,
}

/// Authentication route configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthSection {
    /// List of paths/patterns (e.g. `/pkg/*`) that bypass authentication.
    pub public_paths: Vec<String>,
    /// The URL path to redirect unauthenticated requests to.
    pub login_redirect: String,
}

/// JWT verification configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct JwtSection {
    /// Path to the PEM-encoded public key file, or the raw PEM string.
    pub public_key_path: Option<String>,
    /// The expected `aud` claim in incoming JWTs.
    pub audience: Option<String>,
    /// The expected `iss` claim in incoming JWTs.
    pub issuer: Option<String>,
}

impl Default for InterceptorConfig {
    fn default() -> Self {
        Self {
            auth: AuthSection {
                public_paths: vec![
                    "/".to_string(),
                    "/login".to_string(),
                    "/signup".to_string(),
                    "/pkg/*".to_string(),
                    "/static/*".to_string(),
                    "/health".to_string(),
                ],
                login_redirect: "/login".to_string(),
            },
            jwt: None,
        }
    }
}

impl InterceptorConfig {
    /// Loads the configuration, attempting to read from `WASI_AUTH_CONFIG` env var path
    /// (defaulting to `./wasi-auth.toml`), and applies environment variable overrides.
    pub fn load() -> Self {
        let mut config = Self::default();

        // 1. Try to load from TOML config file if the feature is enabled
        #[cfg(feature = "config-file")]
        {
            let path =
                std::env::var("WASI_AUTH_CONFIG").unwrap_or_else(|_| "wasi-auth.toml".to_string());
            if let Ok(content) = std::fs::read_to_string(&path) {
                match toml::from_str::<InterceptorConfig>(&content) {
                    Ok(parsed) => {
                        config = parsed;
                    }
                    Err(e) => {
                        eprintln!(
                            "wasi-auth-interceptor: Failed to parse config TOML at {}: {:?}",
                            path, e
                        );
                    }
                }
            }
        }

        // 2. Override configurations with standard environment variables
        if let Ok(paths) = std::env::var("WASI_AUTH_PUBLIC_PATHS") {
            config.auth.public_paths = paths.split(',').map(|s| s.trim().to_string()).collect();
        }

        if let Ok(redirect) = std::env::var("WASI_AUTH_LOGIN_REDIRECT") {
            config.auth.login_redirect = redirect;
        }

        if let Ok(pk) = std::env::var("JWT_PUBLIC_KEY") {
            let jwt = config.jwt.get_or_insert_with(|| JwtSection {
                public_key_path: None,
                audience: None,
                issuer: None,
            });
            jwt.public_key_path = Some(pk);
        }

        if let Ok(aud) = std::env::var("JWT_AUDIENCE") {
            let jwt = config.jwt.get_or_insert_with(|| JwtSection {
                public_key_path: None,
                audience: None,
                issuer: None,
            });
            jwt.audience = Some(aud);
        }

        if let Ok(iss) = std::env::var("JWT_ISSUER") {
            let jwt = config.jwt.get_or_insert_with(|| JwtSection {
                public_key_path: None,
                audience: None,
                issuer: None,
            });
            jwt.issuer = Some(iss);
        }

        config
    }
}
