use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EmailMessage {
    pub to: String,
    pub subject: String,
    pub body: String,
    pub otp: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct MockBehavior {
    #[serde(default)]
    pub jwks_key_rotation: bool,
    #[serde(default)]
    pub signature_key_invalid: bool,
    #[serde(default)]
    pub oidc_error: Option<String>,
    #[serde(default)]
    pub latency_ms: Option<u64>,
    #[serde(default)]
    pub network_dropout: bool,
}

pub struct ServerState {
    pub emails: Vec<EmailMessage>,
    pub behavior: MockBehavior,
    pub current_kid: String,
    pub private_key_pem: String,
    pub jwks_json: String,
}

static STATE: OnceLock<Mutex<ServerState>> = OnceLock::new();

pub fn get_state() -> &'static Mutex<ServerState> {
    STATE.get_or_init(|| {
        let (priv_pem, jwks) = generate_keypair("mock-key-id-1");
        Mutex::new(ServerState {
            emails: Vec::new(),
            behavior: MockBehavior::default(),
            current_kid: "mock-key-id-1".to_string(),
            private_key_pem: priv_pem,
            jwks_json: jwks,
        })
    })
}

pub fn generate_keypair(kid: &str) -> (String, String) {
    match kid {
        "mock-key-id-1" => {
            let pem = r###"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDZvEQra638L9Ab
B0LZD3E3EQp4INNxg9uZXrSDR8VhDhpf7k+Tetj47epWO0IFpK1hiWTfCM83rnwP
lV1C/SD9C8fWc5XpsY/gzmtP5/F27y1cQkBuUqOy+LRINilGQPbrXEW80N1xGY/m
UrzGmOypwXgrRDvmsF/OdYeOjYvID+6eY31+ZQr9iQkloHVrfWRbBM70a+wnz7Lm
RA1M/7i1nq5NBF3FqIvxFPTacm/UwbLMdY2nGlLgTMmD0QYhEm5LDyJ9ft3c4Jaw
cqsVD8HCTmb3pJiqQeQMYZpvpZCE4qzys0lkbqSXwM7crAnEr6rsI+nsRs512k8M
Iuyia6ABAgMBAAECggEAMb4jU8kkpS/WKwqYYMb4njQ4MFQNgko1td7vPeu8Yc0r
RN3Ik8CVx57w8ZTVozzpOFZ/cz3Lu2STJqtAtHBoZC8YDzv2VH6SiHEYDpgGb925
/vEKz7l0+Qr9At9OxCRM1N3Od9G+uVs15xBhXLysmqaeucG7rpr+NEhg+PYI6GIh
TUs4zuFgaHhJrKPCx+ExC9sacQQKvXi8Rssjmg241vvvfvLuxJnMq4V7Im00SV3Z
MzMEV9/LL1dCCYfE96QoR1hEDaoxMtd1OWVSW53ldVoii93kPLGGjuRyldzwrCJy
/ey29cjPHXYTJDtjomer9ZKveTVfa6Ho94coB1U2jQKBgQD8LJkBmJczEJh4OsGp
kO5dAdxkgdDIkG04rZrtSnU6kZhMXv+rrOk+PiyBI4tdggSQkWMgUiYKnex9evJ8
3f6rpk2xEF/9VuVIhVmqlgnvSjrtEBI2y/9DiAgd/AaET8t7j5kYlaefRsxyHSuy
0k/U7zbij35FBUd5t84xtVScRQKBgQDdCeoC8UuVbKF3hgEXswuFznVMKQhF6WN3
AriijnE5KIwIH3fEjtgVNqKPX17iXqvNruEbNwEUTt4QzRwZQKoIzEB/fIwxbXs8
6y3dtwuVPo0xMawwvkt2aNjKugO4y9x/H1aVdPWxOfifTnWtRnv01EJnb3CySZi8
HEjwn582jQKBgQCjb5ge47GjA+99hL89UdRa7TjU3xnc01YmdMXDYw2FTxWA8dUM
g/2LPKqFa+8IRJsGw2OWcAd9vAqo7MU6Tnqe7yLNTkqYG/hwPxT1LVb1AowcVt0n
LKGdOA3iuRPULw83XsMfnubLoQwiLWvD8vCQlhVhUxTIUPqZFZqKtvZGbQKBgQCc
w7tD+v4wK6sYqeF8fW9ept5p9W/4pV31uehY4c1LTIaD/E1lCioWYXlJVcplod8X
MUBVnN0XGhhEsjOLdWEifDoCMML9CzisK9+Lr5Z3crWQfjoxF8VNZW7b2LFrDqqD
PiaaOSlHWGYMFgk/qw2exiuSUGcNC0VXpHfWsF6qwQKBgQDdhGLVPGbVq+Bi2jFs
2oQ+qhTGbn1ntsvUHBohy1tgsHkwjwmWcyYmTselII7UZaKdpEHpdae8pZiNUJI7
3O5z7M7WJLVZo4Re+VT7QDRorIPK3j5mox/gXAodgRVFvBWPqB+iv8S4LczQ5Bhg
o0vxmPhL+yY1ST0AkFHlMi9HuA==
-----END PRIVATE KEY-----"###.to_string();
            let jwks = r###"{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"mock-key-id-1","n":"2bxEK2ut_C_QGwdC2Q9xNxEKeCDTcYPbmV60g0fFYQ4aX-5Pk3rY-O3qVjtCBaStYYlk3wjPN658D5VdQv0g_QvH1nOV6bGP4M5rT-fxdu8tXEJAblKjsvi0SDYpRkD261xFvNDdcRmP5lK8xpjsqcF4K0Q75rBfznWHjo2LyA_unmN9fmUK_YkJJaB1a31kWwTO9GvsJ8-y5kQNTP-4tZ6uTQRdxaiL8RT02nJv1MGyzHWNpxpS4EzJg9EGIRJuSw8ifX7d3OCWsHKrFQ_Bwk5m96SYqkHkDGGab6WQhOKs8rNJZG6kl8DO3KwJxK-q7CPp7EbOddpPDCLsomugAQ","e":"AQAB"}]}"###.to_string();
            (pem, jwks)
        }
        "mock-key-id-2" => {
            let pem = r###"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCbMSSL2jiDGkqZ
pXoW2McNQMikgZz9h0cq30UDslIcOGUDSgjgacBk4ODiK37m4aM0OgUVfcWzyOLT
HousAaKRebVKW3DyMCiT59hKZQv/8BMeanb19qFQSzo2TaKPPTU6UNa4iC8S/r4b
yZOWZUbY1cFGZkNWf2HmplGXOaBwlSIc6e5U0JZVEcfErY+pSE1kOhWzx9USGbz4
TMarH4FMcdW9ffPCBzTHTsc2Jk9auSr4m5E+HNAx0vfXew8Qgvjc9OMgCO5UHIf9
0xDOPIwS/VncR0EsGcRGYq06EiHvZ29vOk89nH+mqXLaLKgJfIOkOfaHgKi+qHlP
IWsYjlJnAgMBAAECggEADVlne2AvXEJMCHYOJR5LK6isRE+h4W0G13k9G9mgQS0u
AzUVw7f/r1hoqmEeGV4aBnQMhpIQX4FNgZDZvYH71JJTiyyHxU1p2s8mm7+gDfPo
sRpsq9ulz0epSjfYs9mKqpQpjtX9YUo9sBuMG8kPvwx5WO+S+0MZzhf1t2cNlfbG
crzf+9EjWtpasPte1oR/NFvUSnSnAyIAWedvJ14kk10lqvJ97xY7nTlsg5ME/rrM
DaB31abg5saUChkWctVoXQhke0fijZyq0KWGqcRatqi4eleZb96zsrk/1kAR4JUB
mRQqlef9Z4b0phFl6oOx7KXap6wfxCM6Mm8BvWPtAQKBgQDJk7b85pOBmhsL+2Kn
SY67eOeA0O4vxMXgadQ3lL+CuUs1F6daHU2UzHd9lscJClNP5I9EN8JvaHM11w47
9+aC16cOVBdDM5IUtbbSdzXV5xH/kK/LLRYXC88QomkdnfKjQ1xz/ZbtKFJKbfL0
bK3qcHzMhMFJPgQ1eTqXAVKRbwKBgQDFF3VsUCfOMQRJcJ2/HXRI284xTQKCjo2W
gYXz5RcJKbfGygoGzTmAlGfri4iLBJmuIcTY+k0+gGA8R4TG7e5Mfpv9zY/riyRY
hSDBZkTAkfg6bbzUWuvHkDXEF8kaFgxQAyiHPEWaggSAO4MG3vli71Q0S5Uisx/c
KUh8Vm5iiQKBgHJls165WJMfqyPUqbs4oplAV1miuNpBOO9QABD/COSeVdEuuFoK
8UF1/IY4sIIv6vIXSzsyzdS+GUw/3SMpYBd3XaZjEMShmtDIA5ZT8yiOt4crTKjo
0HWJzRyqny8guVfwXaKyExpKXNFCrrQKjXTUG+9RlAQF/wt93kNei8ZfAoGAI4dV
DY9tfYfsg+ifJyKCIdgt1UlSmIJmF6mFoi+79VTl4hntsMgyA3G9QgLHPHg50+AW
gh6s6gVuU694yft+J5/zMs9pkEZm6OYmv3ZWEni9zJqXnZg+RJ1Ec/Ltt5wd4BaR
qb89tNqXQR55QjXTsvf9r+eoHLc5mRCAFpnmEDECgYB+Hkr9vpr8Ii1TmIpzSsTo
vxx6lQ4uKL7miL0wUkf8zC3L9iVEaVAkzeq3hFOV5fenyrlKi5/dmP/PCp3uG6kb
nRvsma9VRtUgMzklxMebJD2IJm6Dqi2mfLMYUO3QCbH5pMts+TfZnj2ZLShc7C+Y
4ejysSyVbFF7GfsIZa6sfg==
-----END PRIVATE KEY-----"###.to_string();
            let jwks = r###"{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"mock-key-id-2","n":"mzEki9o4gxpKmaV6FtjHDUDIpIGc_YdHKt9FA7JSHDhlA0oI4GnAZODg4it-5uGjNDoFFX3Fs8ji0x6LrAGikXm1Sltw8jAok-fYSmUL__ATHmp29fahUEs6Nk2ijz01OlDWuIgvEv6-G8mTlmVG2NXBRmZDVn9h5qZRlzmgcJUiHOnuVNCWVRHHxK2PqUhNZDoVs8fVEhm8-EzGqx-BTHHVvX3zwgc0x07HNiZPWrkq-JuRPhzQMdL313sPEIL43PTjIAjuVByH_dMQzjyMEv1Z3EdBLBnERmKtOhIh72dvbzpPPZx_pqly2iyoCXyDpDn2h4Covqh5TyFrGI5SZw","e":"AQAB"}]}"###.to_string();
            (pem, jwks)
        }
        _ => {
            let pem = r###"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2W7dGcExXljXr
9VSlNdEpEzWYA0Mav0/SAlZ5YeIYMrU3E7vsLd4X8GQ6B3lOaHYrQNvZztANFaFx
nhg5vGCeVAYyfjr8Ahy/MeylaRdTS/3UOG5/KtTHFf3tmN7ZwChusHPp7III2OGZ
9W69DZ/Omy/t34DchTsDltLqPyjM+G5mQJ6tP50yzkmQiRZLVjFPAowsztFoGjKW
NrdiRVw8XL0DHYXMc7Z/SXwQetwj135LHOLCyLTvCeoGXKzg91+f/hrHxWPMLazo
qVjAa37imOnjcbw5nxzdj221I+7Fly1gnz7NN0XhMevuPiDiwmw7Aq+Q0wMyFJpm
iwPVVXFzAgMBAAECggEAQJzsqmud0SbrAikSDdusuaYRxkPZof+JU7r6UtXo23QU
G2jFnCCAYfEOQjVluO9wd1Dq1RjfRNOWOYCvyr1BargQ3hE16xcAgoo49D7xQdVa
IbjBBhPyAnx7VZVl2LeqW9XvrEHdrS7TeM6qpxfNuNHpwJoBuaEHUPU+1Dr+xOjk
GjP0ldEz1QrvtYWgYmUce85SRGl9iCaymAzjfjykkmRepass3W5ndP31oX2enSAS
PCQ37YhwH+k3WVL4ds+iNfB9NDBC0WAJF17SVJkPvTRsIUqCsQOGvbWzxS1BeYYV
va7QEzH4LI6b2ARYWP0XG13kLEeUw2ElJULDoGvQAQKBgQDm2BOif4kPK1GXi7K8
WDp+79sKCW+ItbHWw6EMCXyhUVLaxeKkNmk0r2MWFqql8oEc6uEjmv1GAlOeNYpP
0XMeNuAncT9VEXdhfF3B8r79CxS1a19arU7WxgsKSm+k+N9gLrzUbm76RPDTjkGT
94RTaQx0n/LgXYLTUWHWaLAIAQKBgQDKOwRqz90k+Vsx1Pnq3dNPq5QOB/InLOMp
1xxC8YFLIRenJb0eaaGh2E6d/IL2OzrZJM5qep4jK+PHx8GNsS3KQzItzfJtp4JP
FvdxPQGJFP+QwiCaVFyfusCIYiB8keg33tpQrt0pIYVX73JBTFSedEO80Zc4Mj7j
wL9Jz3nZcwKBgQDbgIkjEhxUpT8/V+HMACUXQKHKKHC60PJaociINpkgl8CuME4z
EV32b/NLNKBtjWtCAQG1ppHAuUOjg4uSHDpXd5yrRJ8RF7upoeVRH66F1LyLSZ7x
DSyTQtuKnH8Oomtc/PQnFx9FsLpCn9kxhsF3wsLKPrFmsOROZesfQopoAQKBgQC8
4BwDCnq3orDavNhh1KYcXdqctC0lC5ZqqH67w0WHfrPRp7yXH/8W4qiig4lpIe6X
ifnDlxwFK2PFXjrW9GkY5GOERjoq0e0xovid6WV6u4Lpl3XNzgboJArYFhXTYo6p
R9lMy9TBKo6Yj4l9lSXfDCWLv5Dlqn/0RTwjWsSqIwKBgBuWHw0XCtBRUBwZE2ik
1jKhkIV+96Q3OIbN4Z8R22j/9BvHJVzPOTz8HBSf//vmpbx8pgM7lppwOJl/eWv3
b31+HLsfP/ogUFY8ZORBbdVQlSkZ/ibGzNbX/Pzog1C7q2O5XsRvco8Vx03aNqr5
gTUJMNT0fxsZk5bsUVPagTLj
-----END PRIVATE KEY-----"###.to_string();
            let jwks = r###"{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"invalid-kid","n":"tlu3RnBMV5Y16_VUpTXRKRM1mANDGr9P0gJWeWHiGDK1NxO77C3eF_BkOgd5Tmh2K0Db2c7QDRWhcZ4YObxgnlQGMn46_AIcvzHspWkXU0v91DhufyrUxxX97Zje2cAobrBz6eyCCNjhmfVuvQ2fzpsv7d-A3IU7A5bS6j8ozPhuZkCerT-dMs5JkIkWS1YxTwKMLM7RaBoylja3YkVcPFy9Ax2FzHO2f0l8EHrcI9d-Sxziwsi07wnqBlys4Pdfn_4ax8VjzC2s6KlYwGt-4pjp43G8OZ8c3Y9ttSPuxZctYJ8-zTdF4THr7j4g4sJsOwKvkNMDMhSaZosD1VVxcw","e":"AQAB"}]}"###.to_string();
            (pem, jwks)
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn generate_mock_jwt(
    private_key_pem: &str,
    kid: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    #[derive(serde::Serialize)]
    struct Claims {
        sub: String,
        iss: String,
        aud: String,
        exp: usize,
        roles: Vec<String>,
        name: String,
        email: String,
    }

    let header = Header {
        alg: Algorithm::RS256,
        kid: Some(kid.to_string()),
        ..Default::default()
    };

    let exp = chrono::Utc::now().timestamp() as usize + 3600;
    let claims = Claims {
        sub: "user_id_12345".to_string(),
        iss: "mock-auth-server".to_string(),
        aud: "client-id-123".to_string(),
        exp,
        roles: vec!["user".to_string(), "admin".to_string()],
        name: "Alice Smith".to_string(),
        email: "alice@example.com".to_string(),
    };

    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())?;
    encode(&header, &claims, &key)
}

#[cfg(target_arch = "wasm32")]
fn generate_mock_jwt(_private_key_pem: &str, _kid: &str) -> Result<String, String> {
    Ok("dummy_jwt".to_string())
}

pub fn extract_otp(body: &str) -> Option<String> {
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let mut j = i;
            while j < chars.len() && chars[j].is_ascii_digit() {
                j += 1;
            }
            let len = j - i;
            if (4..=8).contains(&len) {
                let otp: String = chars[i..j].iter().collect();
                return Some(otp);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    None
}

fn handle_connection(mut stream: TcpStream) -> std::io::Result<()> {
    // 1. Get latency & dropout configurations
    let (latency, dropout) = {
        let state = get_state().lock().unwrap();
        (state.behavior.latency_ms, state.behavior.network_dropout)
    };

    if dropout {
        // Connection dropout: close connection immediately
        return Ok(());
    }

    if let Some(ms) = latency {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }

    let mut buffer = [0; 8192];
    let bytes_read = stream.read(&mut buffer)?;
    if bytes_read == 0 {
        return Ok(());
    }

    let request_str = String::from_utf8_lossy(&buffer[..bytes_read]);
    let parts: Vec<&str> = request_str.splitn(2, "\r\n\r\n").collect();
    let header_part = parts[0];
    let body_part = if parts.len() > 1 { parts[1] } else { "" };

    let mut lines = header_part.lines();
    let request_line = match lines.next() {
        Some(line) => line,
        None => {
            send_response(
                &mut stream,
                400,
                "Bad Request",
                "text/plain",
                "Missing request line",
            )?;
            return Ok(());
        }
    };

    let req_parts: Vec<&str> = request_line.split_whitespace().collect();
    if req_parts.len() < 2 {
        send_response(
            &mut stream,
            400,
            "Bad Request",
            "text/plain",
            "Malformed request line",
        )?;
        return Ok(());
    }

    let method = req_parts[0];
    let full_path = req_parts[1];

    let (path, query_str) = match full_path.find('?') {
        Some(idx) => (&full_path[..idx], &full_path[idx + 1..]),
        None => (full_path, ""),
    };

    let query_params = parse_query(query_str);

    match (method, path) {
        ("GET", "/authorize") => {
            let redirect_uri = query_params
                .get("redirect_uri")
                .map(|s| s.as_str())
                .unwrap_or("http://localhost:3000/callback");
            let state_param = query_params.get("state").map(|s| s.as_str()).unwrap_or("");

            let oidc_error = {
                let state = get_state().lock().unwrap();
                state.behavior.oidc_error.clone()
            };

            if let Some(err) = oidc_error {
                let redirect_url = format!("{}?error={}&state={}", redirect_uri, err, state_param);
                send_redirect(&mut stream, &redirect_url)?;
            } else {
                let redirect_url =
                    format!("{}?code=mock_code_123&state={}", redirect_uri, state_param);
                send_redirect(&mut stream, &redirect_url)?;
            }
        }
        ("POST", "/token") => {
            let (priv_key, kid, oidc_error) = {
                let state = get_state().lock().unwrap();
                let priv_key = if state.behavior.signature_key_invalid {
                    let (invalid_priv, _) = generate_keypair("invalid-kid");
                    invalid_priv
                } else {
                    state.private_key_pem.clone()
                };
                (
                    priv_key,
                    state.current_kid.clone(),
                    state.behavior.oidc_error.clone(),
                )
            };

            if let Some(err) = oidc_error {
                let json_body = format!(r#"{{"error": "{}"}}"#, err);
                send_response(
                    &mut stream,
                    400,
                    "Bad Request",
                    "application/json",
                    &json_body,
                )?;
                return Ok(());
            }

            let mock_jwt = match generate_mock_jwt(&priv_key, &kid) {
                Ok(t) => t,
                Err(e) => {
                    send_response(
                        &mut stream,
                        500,
                        "Internal Server Error",
                        "text/plain",
                        &e.to_string(),
                    )?;
                    return Ok(());
                }
            };
            let json_body = format!(
                r#"{{"access_token": "{}", "token_type": "Bearer", "expires_in": 3600, "id_token": "{}", "refresh_token": "mock_refresh_token"}}"#,
                mock_jwt, mock_jwt
            );
            send_response(&mut stream, 200, "OK", "application/json", &json_body)?;
        }
        ("GET", "/userinfo") => {
            let json_body = r#"{"sub": "user_id_12345", "name": "Alice Smith", "email": "alice@example.com", "roles": ["user", "admin"]}"#;
            send_response(&mut stream, 200, "OK", "application/json", json_body)?;
        }
        ("GET", "/jwks") | ("GET", "/.well-known/jwks.json") => {
            let jwks_json = {
                let state = get_state().lock().unwrap();
                state.jwks_json.clone()
            };
            send_response(&mut stream, 200, "OK", "application/json", &jwks_json)?;
        }
        ("POST", "/email/send") => {
            let body_json = body_part.trim();
            #[derive(Deserialize)]
            struct EmailPayload {
                to: String,
                subject: String,
                body: String,
            }
            match serde_json::from_str::<EmailPayload>(body_json) {
                Ok(payload) => {
                    let otp = extract_otp(&payload.body);
                    let msg = EmailMessage {
                        to: payload.to,
                        subject: payload.subject,
                        body: payload.body,
                        otp,
                    };
                    let mut state = get_state().lock().unwrap();
                    state.emails.push(msg);
                    send_response(
                        &mut stream,
                        200,
                        "OK",
                        "application/json",
                        r#"{"status":"sent"}"#,
                    )?;
                }
                Err(e) => {
                    send_response(
                        &mut stream,
                        400,
                        "Bad Request",
                        "text/plain",
                        &format!("Invalid JSON: {}", e),
                    )?;
                }
            }
        }
        ("GET", "/email/inbox") => {
            let to_email = query_params.get("to").cloned().unwrap_or_default();
            let state = get_state().lock().unwrap();
            let filtered_emails: Vec<EmailMessage> = state
                .emails
                .iter()
                .filter(|m| m.to == to_email)
                .cloned()
                .collect();
            let resp_body = serde_json::to_string(&filtered_emails).unwrap();
            send_response(&mut stream, 200, "OK", "application/json", &resp_body)?;
        }
        ("DELETE", "/email/inbox") => {
            let mut state = get_state().lock().unwrap();
            state.emails.clear();
            send_response(
                &mut stream,
                200,
                "OK",
                "application/json",
                r#"{"status":"cleared"}"#,
            )?;
        }
        ("POST", "/mock/configure-behavior") => {
            let body_json = body_part.trim();
            match serde_json::from_str::<MockBehavior>(body_json) {
                Ok(new_behavior) => {
                    let mut state = get_state().lock().unwrap();
                    if new_behavior.jwks_key_rotation {
                        let (new_priv, new_jwks) = generate_keypair("mock-key-id-2");
                        state.current_kid = "mock-key-id-2".to_string();
                        state.private_key_pem = new_priv;
                        state.jwks_json = new_jwks;
                    }
                    state.behavior = new_behavior;
                    send_response(
                        &mut stream,
                        200,
                        "OK",
                        "application/json",
                        r#"{"status":"configured"}"#,
                    )?;
                }
                Err(e) => {
                    send_response(
                        &mut stream,
                        400,
                        "Bad Request",
                        "text/plain",
                        &format!("Invalid JSON: {}", e),
                    )?;
                }
            }
        }
        _ => {
            send_response(&mut stream, 404, "Not Found", "text/plain", "Not Found")?;
        }
    }

    Ok(())
}

fn send_response(
    stream: &mut TcpStream,
    status_code: u16,
    status_text: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
        status_code,
        status_text,
        content_type,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn send_redirect(stream: &mut TcpStream, location: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        location
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    if query.is_empty() {
        return params;
    }
    for pair in query.split('&') {
        let mut parts = pair.split('=');
        if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
            params.insert(key.to_string(), value.to_string());
        }
    }
    params
}

pub fn main_impl() -> Result<(), Box<dyn std::error::Error>> {
    let mut port = 8080;
    if let Some(arg) = std::env::args().nth(1) {
        if let Ok(p) = arg.parse::<u16>() {
            port = p;
        }
    } else if let Ok(p_str) = std::env::var("PORT") {
        if let Ok(p) = p_str.parse::<u16>() {
            port = p;
        }
    } else if let Ok(p_str) = std::env::var("MOCK_AUTH_PORT") {
        if let Ok(p) = p_str.parse::<u16>() {
            port = p;
        }
    }

    // Initialize state
    let _ = get_state();

    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)?;
    println!("Mock OAuth2 Server listening on http://{}", addr);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_connection(stream) {
                    eprintln!("Error handling connection: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::mpsc::channel;
    use std::thread;

    #[test]
    fn test_mock_auth_server_endpoints() {
        let (port_tx, port_rx) = channel();

        thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind");
            let bound_port = listener.local_addr().unwrap().port();
            port_tx.send(bound_port).unwrap();

            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let _ = handle_connection(stream);
                    }
                    Err(_) => break,
                }
            }
        });

        let port = port_rx.recv().unwrap();

        // 1. Test GET /jwks
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        stream
            .write_all(b"GET /jwks HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("keys"));
        assert!(response.contains("mock-key-id-1"));

        // Extract JWKS to get n and e
        let jwks_body_start = response.find("\r\n\r\n").unwrap() + 4;
        let jwks_val: serde_json::Value =
            serde_json::from_str(&response[jwks_body_start..]).unwrap();
        let key_obj = &jwks_val["keys"][0];
        let n_str = key_obj["n"].as_str().unwrap();
        let e_str = key_obj["e"].as_str().unwrap();

        // 2. Test GET /authorize
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        stream.write_all(b"GET /authorize?redirect_uri=http://test/callback&state=mystate HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.contains("HTTP/1.1 302 Found"));
        assert!(
            response.contains("Location: http://test/callback?code=mock_code_123&state=mystate")
        );

        // 3. Test POST /token
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        stream
            .write_all(b"POST /token HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("access_token"));

        let body_start = response.find("\r\n\r\n").unwrap() + 4;
        let body: serde_json::Value = serde_json::from_str(&response[body_start..]).unwrap();
        let token_str = body["access_token"].as_str().unwrap();

        // Decode and cryptographically validate the JWT!
        let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(n_str, e_str).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&["client-id-123"]);
        validation.validate_exp = true;

        #[derive(serde::Deserialize)]
        struct TestClaims {
            sub: String,
            iss: String,
            aud: String,
            exp: usize,
            roles: Vec<String>,
            name: String,
            email: String,
        }

        let token_data =
            jsonwebtoken::decode::<TestClaims>(token_str, &decoding_key, &validation).unwrap();
        assert_eq!(token_data.claims.sub, "user_id_12345");
        assert_eq!(token_data.claims.iss, "mock-auth-server");
        assert_eq!(token_data.claims.aud, "client-id-123");
        assert_eq!(token_data.claims.name, "Alice Smith");
        assert_eq!(token_data.claims.email, "alice@example.com");
        assert!(token_data.claims.exp > 0);
        assert!(token_data.claims.roles.contains(&"admin".to_string()));

        // 4. Test GET /userinfo
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        stream
            .write_all(b"GET /userinfo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("user_id_12345"));
        assert!(response.contains("Alice Smith"));

        // 5. Test POST /email/send
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let email_req = r#"{"to":"bob@example.com","subject":"Your OTP","body":"Hello! Your code is 556677. Thank you!"}"#;
        let req_headers = format!("POST /email/send HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", email_req.len(), email_req);
        stream.write_all(req_headers.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("sent"));

        // 6. Test GET /email/inbox?to=bob@example.com
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        stream.write_all(b"GET /email/inbox?to=bob@example.com HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("bob@example.com"));
        assert!(response.contains("556677"));

        // 7. Test DELETE /email/inbox
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        stream
            .write_all(
                b"DELETE /email/inbox HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("cleared"));

        // Verify inbox is indeed clear
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        stream.write_all(b"GET /email/inbox?to=bob@example.com HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.contains("[]"));
    }
}
