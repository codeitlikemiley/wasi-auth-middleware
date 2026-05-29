use crate::AuthError;

#[cfg(feature = "http-email")]
pub struct HttpEmail {
    service_url: String,
}

#[cfg(feature = "http-email")]
impl HttpEmail {
    pub fn new(service_url: String) -> Self {
        Self { service_url }
    }
}

#[cfg(all(feature = "http-email", target_arch = "wasm32", target_os = "wasi"))]
impl crate::EmailSender for HttpEmail {
    fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), AuthError> {
        #[derive(serde::Serialize)]
        struct EmailPayload<'a> {
            to: &'a str,
            subject: &'a str,
            body: &'a str,
        }
        let payload = EmailPayload { to, subject, body };
        let body_bytes = serde_json::to_vec(&payload)
            .map_err(|e| AuthError::Email(format!("Payload serialization failed: {}", e)))?;

        let request = http::Request::builder()
            .method("POST")
            .uri(&self.service_url)
            .header("Content-Type", "application/json")
            .body(Some(bytes::Bytes::from(body_bytes)))
            .map_err(|e| AuthError::Email(format!("Request building failed: {}", e)))?;

        let response = futures::executor::block_on(spin_sdk::http::send::<
            _,
            http::Response<bytes::Bytes>,
        >(request))
        .map_err(|e| AuthError::Email(format!("Outbound HTTP send failed: {:?}", e)))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(AuthError::Email(format!(
                "HttpEmail failed with status: {}",
                response.status()
            )))
        }
    }
}

#[cfg(all(
    feature = "http-email",
    not(all(target_arch = "wasm32", target_os = "wasi"))
))]
impl crate::EmailSender for HttpEmail {
    fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), AuthError> {
        #[derive(serde::Serialize)]
        struct EmailPayload<'a> {
            to: &'a str,
            subject: &'a str,
            body: &'a str,
        }
        let payload = EmailPayload { to, subject, body };

        let response = ureq::post(&self.service_url)
            .timeout(std::time::Duration::from_secs(10))
            .send_json(payload)
            .map_err(|e| AuthError::Email(format!("Outbound HTTP send failed: {}", e)))?;

        if response.status() >= 200 && response.status() < 300 {
            Ok(())
        } else {
            Err(AuthError::Email(format!(
                "HttpEmail failed with status: {}",
                response.status()
            )))
        }
    }
}

#[cfg(all(
    test,
    feature = "http-email",
    not(all(target_arch = "wasm32", target_os = "wasi"))
))]
mod tests {
    use super::*;
    use crate::EmailSender;

    #[test]
    fn test_http_email_native_invalid_url() {
        let sender = HttpEmail::new("http://invalid-url-12345.local".to_string());
        let res = sender.send_email("test@example.com", "Subject", "Body");
        assert!(res.is_err());
        if let Err(AuthError::Email(msg)) = res {
            assert!(msg.contains("Outbound HTTP send failed"));
        } else {
            panic!("Expected Email error");
        }
    }
}
