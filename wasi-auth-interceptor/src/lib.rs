#![allow(clippy::missing_safety_doc)]

wit_bindgen::generate!({
    path: "wit",
    world: "interceptor",
});

struct Interceptor;

impl exports::wasi::http0_2_2::incoming_handler::Guest for Interceptor {
    fn handle(
        request: exports::wasi::http0_2_2::incoming_handler::IncomingRequest,
        response_outparam: exports::wasi::http0_2_2::incoming_handler::ResponseOutparam,
    ) {
        use crate::wasi::http0_2_9::types::{Fields, OutgoingBody, OutgoingResponse};

        let headers = request.headers();
        let _ = headers.delete(&"x-user-id".to_string());
        let _ = headers.delete(&"X-User-Id".to_string());
        let _ = headers.delete(&"x-user-roles".to_string());
        let _ = headers.delete(&"X-User-Roles".to_string());
        let _ = headers.delete(&"x-user-email".to_string());
        let _ = headers.delete(&"X-User-Email".to_string());
        let _ = headers.delete(&"x-user-name".to_string());
        let _ = headers.delete(&"X-User-Name".to_string());

        let path_with_query = request.path_with_query().unwrap_or_else(|| "/".to_string());
        let path = path_with_query.split('?').next().unwrap_or("/");

        // 1. Check if it's a public path
        let is_public =
            path == "/" || path == "/login" || path.starts_with("/pkg/") || path.starts_with("/static/");

        if is_public {
            // Forward request directly
            wasi::http0_2_2::incoming_handler::handle(request, response_outparam);
            return;
        }

        // 2. Perform authentication check
        let mut token = None;

        // Try to get token from Cookie (jwt or session)
        if let Some(cookies) = get_header_value(&headers, "cookie").or_else(|| get_header_value(&headers, "Cookie")) {
            if let Some(t) =
                extract_cookie(&cookies, "jwt").or_else(|| extract_cookie(&cookies, "session"))
            {
                token = Some(t);
            }
        }

        // Try to get token from Authorization: Bearer <token>
        if token.is_none() {
            if let Some(auth_val) = get_header_value(&headers, "authorization").or_else(|| get_header_value(&headers, "Authorization")) {
                if let Some(t) = auth_val.strip_prefix("Bearer ") {
                    token = Some(t.to_string());
                }
            }
        }

        let mut authenticated_session = None;

        if let Some(jwt_token) = token {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::ZERO)
                .as_secs();

            let pub_key = std::env::var("JWT_PUBLIC_KEY").ok();
            let aud = std::env::var("JWT_AUDIENCE").ok();
            let iss = std::env::var("JWT_ISSUER").ok();

            if let (Some(pub_key), Some(aud), Some(iss)) = (pub_key, aud, iss) {
                // Securely verify JWT
                if let Ok(claims) = wasi_auth_core::jwt::verify_jwt(&jwt_token, &pub_key, &aud, &iss, now) {
                    authenticated_session = Some(claims);
                }
            } else {
                // Fallback to unsafe parsing but STILL validate token expiration manually
                if let Ok(claims) = parse_claims_unsafe(&jwt_token) {
                    let is_expired = if let Some(exp_limit) = claims.exp.checked_add(60) {
                        exp_limit <= now
                    } else {
                        claims.exp <= now
                    };
                    if !is_expired {
                        authenticated_session = Some(claims);
                    }
                }
            }
        }

        if let Some(session) = authenticated_session {
            // Inject identity headers into request
            let _ = headers.set(&"x-user-id".to_string(), &[session.sub.as_bytes().to_vec()]);

            let roles_str = session.roles.join(",");
            let _ = headers.set(
                &"x-user-roles".to_string(),
                &[roles_str.as_bytes().to_vec()],
            );

            if let Some(email) = session.email {
                let _ = headers.set(&"x-user-email".to_string(), &[email.as_bytes().to_vec()]);
            }
            if let Some(name) = session.name {
                let _ = headers.set(&"x-user-name".to_string(), &[name.as_bytes().to_vec()]);
            }

            // Forward authenticated request to downstream application
            wasi::http0_2_2::incoming_handler::handle(request, response_outparam);
        } else {
            // Unauthenticated! Block request.
            // If it's a POST/PUT/DELETE/PATCH/API request, return 401. Otherwise redirect to /login.
            let method = request.method();
            let is_api_or_action = matches!(
                method,
                crate::wasi::http0_2_9::types::Method::Post
                    | crate::wasi::http0_2_9::types::Method::Put
                    | crate::wasi::http0_2_9::types::Method::Delete
                    | crate::wasi::http0_2_9::types::Method::Patch
            ) || path.starts_with("/api/");

            if is_api_or_action {
                // Return 401 Unauthorized
                let resp_headers = Fields::new();
                let response = OutgoingResponse::new(resp_headers);
                let _ = response.set_status_code(401);

                let body = response.body().unwrap();
                let stream = body.write().unwrap();
                let _ = stream.blocking_write_and_flush(b"Unauthorized");
                drop(stream);
                let _ = OutgoingBody::finish(body, None);

                exports::wasi::http0_2_2::incoming_handler::ResponseOutparam::set(
                    response_outparam,
                    Ok(response),
                );
            } else {
                // Return 302 Redirect to /login
                let resp_headers = Fields::new();
                let _ = resp_headers.set(&"location".to_string(), &[b"/login".to_vec()]);
                let response = OutgoingResponse::new(resp_headers);
                let _ = response.set_status_code(302);

                let body = response.body().unwrap();
                let stream = body.write().unwrap();
                let _ = stream.blocking_write_and_flush(b"Redirecting to /login...");
                drop(stream);
                let _ = OutgoingBody::finish(body, None);

                exports::wasi::http0_2_2::incoming_handler::ResponseOutparam::set(
                    response_outparam,
                    Ok(response),
                );
            }
        }
    }
}

fn get_header_value(fields: &crate::wasi::http0_2_9::types::Fields, name: &str) -> Option<String> {
    fields
        .get(&name.to_string())
        .first()
        .and_then(|bytes| std::str::from_utf8(bytes).ok().map(|s| s.to_string()))
}

fn extract_cookie(cookie_header: &str, name: &str) -> Option<String> {
    for cookie in cookie_header.split(';') {
        let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
        if parts.len() == 2 && parts[0] == name {
            return Some(parts[1].to_string());
        }
    }
    None
}

fn parse_claims_unsafe(token: &str) -> Result<wasi_auth_core::jwt::Claims, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return Err("Invalid JWT format".to_string());
    }
    // Decode header or claims
    let claims_json =
        wasi_auth_core::jwt::base64_url_decode(parts[1]).map_err(|e| e.to_string())?;

    let claims: wasi_auth_core::jwt::Claims = serde_json::from_slice(&claims_json).map_err(|e| e.to_string())?;
    Ok(claims)
}

export!(Interceptor);
