use crate::AuthError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub userinfo_url: Option<String>,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub sub: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub roles: Option<Vec<String>>,
}

pub trait HttpClient {
    fn post(&self, url: &str, headers: &[(&str, &str)], body: &str) -> Result<String, AuthError>;
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<String, AuthError>;
}

pub struct Oauth2Client;

impl Oauth2Client {
    pub fn generate_auth_url(config: &OAuthConfig, state: &str, scope: &str) -> String {
        let auth_url = if config.auth_url.contains('?') {
            format!("{}&", config.auth_url)
        } else {
            format!("{}?", config.auth_url)
        };

        format!(
            "{}response_type=code&client_id={}&redirect_uri={}&state={}&scope={}",
            auth_url,
            urlencoding::encode(&config.client_id),
            urlencoding::encode(&config.redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(scope)
        )
    }

    pub fn exchange_code(
        config: &OAuthConfig,
        code: &str,
        client: &impl HttpClient,
    ) -> Result<TokenResponse, AuthError> {
        let body = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}",
            urlencoding::encode(code),
            urlencoding::encode(&config.redirect_uri),
            urlencoding::encode(&config.client_id),
            urlencoding::encode(&config.client_secret)
        );

        let headers = [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Accept", "application/json"),
        ];

        let resp_body = client.post(&config.token_url, &headers, &body)?;
        let token_resp: TokenResponse = serde_json::from_str(&resp_body).map_err(|e| {
            AuthError::Crypto(format!(
                "Failed to parse token response: {}, body: {}",
                e, resp_body
            ))
        })?;
        Ok(token_resp)
    }

    pub fn get_user_info(
        config: &OAuthConfig,
        access_token: &str,
        client: &impl HttpClient,
    ) -> Result<UserInfo, AuthError> {
        let userinfo_url = config
            .userinfo_url
            .as_ref()
            .ok_or_else(|| AuthError::Crypto("Userinfo endpoint not configured".to_string()))?;

        let auth_header = format!("Bearer {}", access_token);
        let headers = [
            ("Authorization", auth_header.as_str()),
            ("Accept", "application/json"),
        ];

        let resp_body = client.get(userinfo_url, &headers)?;
        let user_info: UserInfo = serde_json::from_str(&resp_body).map_err(|e| {
            AuthError::Crypto(format!(
                "Failed to parse userinfo response: {}, body: {}",
                e, resp_body
            ))
        })?;
        Ok(user_info)
    }

    pub fn parse_oidc_discovery(
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        metadata_json: &str,
    ) -> Result<OAuthConfig, AuthError> {
        #[derive(Deserialize)]
        struct DiscoveryMetadata {
            authorization_endpoint: String,
            token_endpoint: String,
            userinfo_endpoint: Option<String>,
        }

        let meta: DiscoveryMetadata = serde_json::from_str(metadata_json)
            .map_err(|e| AuthError::Crypto(format!("Failed to parse OIDC metadata: {}", e)))?;

        Ok(OAuthConfig {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: meta.authorization_endpoint,
            token_url: meta.token_endpoint,
            userinfo_url: meta.userinfo_endpoint,
            redirect_uri: redirect_uri.to_string(),
        })
    }

    pub fn fetch_oidc_config(
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        discovery_url: &str,
        client: &impl HttpClient,
    ) -> Result<OAuthConfig, AuthError> {
        let headers = [("Accept", "application/json")];
        let meta_json = client.get(discovery_url, &headers)?;
        Self::parse_oidc_discovery(client_id, client_secret, redirect_uri, &meta_json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockHttpClient {
        response_body: String,
        last_request: Mutex<Option<(String, String, String)>>, // (method, url, body)
    }

    impl HttpClient for MockHttpClient {
        fn post(
            &self,
            url: &str,
            _headers: &[(&str, &str)],
            body: &str,
        ) -> Result<String, AuthError> {
            let mut req = self.last_request.lock().unwrap();
            *req = Some(("POST".to_string(), url.to_string(), body.to_string()));
            Ok(self.response_body.clone())
        }

        fn get(&self, url: &str, _headers: &[(&str, &str)]) -> Result<String, AuthError> {
            let mut req = self.last_request.lock().unwrap();
            *req = Some(("GET".to_string(), url.to_string(), String::new()));
            Ok(self.response_body.clone())
        }
    }

    #[test]
    fn test_generate_auth_url() {
        let config = OAuthConfig {
            client_id: "id123".to_string(),
            client_secret: "sec123".to_string(),
            auth_url: "https://auth.com".to_string(),
            token_url: "https://token.com".to_string(),
            userinfo_url: None,
            redirect_uri: "https://app.com/callback".to_string(),
        };

        let url = Oauth2Client::generate_auth_url(&config, "mystate", "openid email");
        assert!(url.contains("client_id=id123"));
        assert!(url.contains("state=mystate"));
        assert!(url.contains("scope=openid%20email"));
    }

    #[test]
    fn test_exchange_code() {
        let config = OAuthConfig {
            client_id: "id123".to_string(),
            client_secret: "sec123".to_string(),
            auth_url: "https://auth.com".to_string(),
            token_url: "https://token.com".to_string(),
            userinfo_url: None,
            redirect_uri: "https://app.com/callback".to_string(),
        };

        let mock_resp =
            r#"{"access_token":"t123","token_type":"Bearer","expires_in":3600,"id_token":"id123"}"#;
        let mock_client = MockHttpClient {
            response_body: mock_resp.to_string(),
            last_request: Mutex::new(None),
        };

        let token_resp = Oauth2Client::exchange_code(&config, "mycode", &mock_client).unwrap();
        assert_eq!(token_resp.access_token, "t123");
        assert_eq!(token_resp.id_token, Some("id123".to_string()));

        let req = mock_client.last_request.lock().unwrap().clone().unwrap();
        assert_eq!(req.0, "POST");
        assert_eq!(req.1, "https://token.com");
        assert!(req.2.contains("code=mycode"));
        assert!(req.2.contains("client_secret=sec123"));
    }

    #[test]
    fn test_get_user_info() {
        let config = OAuthConfig {
            client_id: "id123".to_string(),
            client_secret: "sec123".to_string(),
            auth_url: "https://auth.com".to_string(),
            token_url: "https://token.com".to_string(),
            userinfo_url: Some("https://userinfo.com".to_string()),
            redirect_uri: "https://app.com/callback".to_string(),
        };

        let mock_resp =
            r#"{"sub":"user123","name":"John Doe","email":"john@example.com","roles":["user"]}"#;
        let mock_client = MockHttpClient {
            response_body: mock_resp.to_string(),
            last_request: Mutex::new(None),
        };

        let user_info = Oauth2Client::get_user_info(&config, "t123", &mock_client).unwrap();
        assert_eq!(user_info.sub, "user123");
        assert_eq!(user_info.name, Some("John Doe".to_string()));
        assert_eq!(user_info.email, Some("john@example.com".to_string()));
        assert_eq!(user_info.roles, Some(vec!["user".to_string()]));

        let req = mock_client.last_request.lock().unwrap().clone().unwrap();
        assert_eq!(req.0, "GET");
        assert_eq!(req.1, "https://userinfo.com");
    }

    #[test]
    fn test_get_user_info_missing_url() {
        let config = OAuthConfig {
            client_id: "id123".to_string(),
            client_secret: "sec123".to_string(),
            auth_url: "https://auth.com".to_string(),
            token_url: "https://token.com".to_string(),
            userinfo_url: None,
            redirect_uri: "https://app.com/callback".to_string(),
        };

        let mock_client = MockHttpClient {
            response_body: String::new(),
            last_request: Mutex::new(None),
        };

        let err = Oauth2Client::get_user_info(&config, "t123", &mock_client).unwrap_err();
        assert!(matches!(err, AuthError::Crypto(_)));
    }

    #[test]
    fn test_parse_oidc_discovery() {
        let metadata_json = r#"{"authorization_endpoint":"https://auth.com","token_endpoint":"https://token.com","userinfo_endpoint":"https://userinfo.com"}"#;
        let config = Oauth2Client::parse_oidc_discovery(
            "id123",
            "sec123",
            "https://app.com/callback",
            metadata_json,
        )
        .unwrap();
        assert_eq!(config.client_id, "id123");
        assert_eq!(config.client_secret, "sec123");
        assert_eq!(config.auth_url, "https://auth.com");
        assert_eq!(config.token_url, "https://token.com");
        assert_eq!(
            config.userinfo_url,
            Some("https://userinfo.com".to_string())
        );
        assert_eq!(config.redirect_uri, "https://app.com/callback");
    }

    #[test]
    fn test_fetch_oidc_config() {
        let metadata_json = r#"{"authorization_endpoint":"https://auth.com","token_endpoint":"https://token.com","userinfo_endpoint":"https://userinfo.com"}"#;
        let mock_client = MockHttpClient {
            response_body: metadata_json.to_string(),
            last_request: Mutex::new(None),
        };

        let config = Oauth2Client::fetch_oidc_config(
            "id123",
            "sec123",
            "https://app.com/callback",
            "https://discovery.com",
            &mock_client,
        )
        .unwrap();

        assert_eq!(config.client_id, "id123");
        assert_eq!(config.auth_url, "https://auth.com");

        let req = mock_client.last_request.lock().unwrap().clone().unwrap();
        assert_eq!(req.0, "GET");
        assert_eq!(req.1, "https://discovery.com");
    }
}
