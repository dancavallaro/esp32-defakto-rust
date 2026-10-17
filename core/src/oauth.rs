//! OAuth messages: the device authorization grant (RFC 8628) against Auth0, and
//! token exchange (RFC 8693) against the Trust Domain Server.

use serde::Deserialize;

use crate::http::HttpResponse;

pub const GRANT_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
pub const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const CLIENT_ASSERTION_JWT_SPIFFE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe";
pub const TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
pub const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PollOutcome {
    Pending,
    SlowDown,
    IdToken(String),
    Expired,
    Denied,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum OAuthError {
    #[error("{error}: {description}")]
    Server { status: u16, error: String, description: String },
    #[error("unexpected response: {0}")]
    Malformed(String),
    #[error("login succeeded but no ID token")]
    NoIdToken,
}

pub fn device_code_form(client_id: &str, scope: &str) -> String {
    form(&[("client_id", client_id), ("scope", scope)])
}

pub fn device_token_form(client_id: &str, device_code: &str) -> String {
    form(&[("grant_type", GRANT_DEVICE_CODE), ("device_code", device_code), ("client_id", client_id)])
}

pub fn token_exchange_form(subject_token: &str, subject_token_type: &str, client_assertion: &str) -> String {
    form(&[
        ("grant_type", GRANT_TOKEN_EXCHANGE),
        ("subject_token", subject_token),
        ("subject_token_type", subject_token_type),
        ("client_assertion_type", CLIENT_ASSERTION_JWT_SPIFFE),
        ("client_assertion", client_assertion),
    ])
}

pub fn parse_device_authorization(resp: &HttpResponse) -> Result<DeviceAuthorization, OAuthError> {
    success_body(resp)
}

pub fn parse_poll(resp: &HttpResponse) -> Result<PollOutcome, OAuthError> {
    #[derive(Deserialize)]
    struct Tokens {
        id_token: Option<String>,
    }
    match success_body::<Tokens>(resp) {
        Ok(Tokens { id_token: Some(t) }) => Ok(PollOutcome::IdToken(t)),
        Ok(Tokens { id_token: None }) => Err(OAuthError::NoIdToken),
        Err(OAuthError::Server { error, status, description }) => match error.as_str() {
            "authorization_pending" => Ok(PollOutcome::Pending),
            "slow_down" => Ok(PollOutcome::SlowDown),
            "expired_token" => Ok(PollOutcome::Expired),
            "access_denied" => Ok(PollOutcome::Denied),
            _ => Err(OAuthError::Server { status, error, description }),
        },
        Err(e) => Err(e),
    }
}

/// Returns the issued token (`access_token`).
pub fn parse_token_exchange(resp: &HttpResponse) -> Result<String, OAuthError> {
    #[derive(Deserialize)]
    struct Issued {
        access_token: String,
    }
    success_body::<Issued>(resp).map(|i| i.access_token)
}

fn form(pairs: &[(&str, &str)]) -> String {
    form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish()
}

/// Decodes a 2xx body as `T`, or a non-2xx body as an OAuth error response.
fn success_body<T: serde::de::DeserializeOwned>(resp: &HttpResponse) -> Result<T, OAuthError> {
    #[derive(Deserialize)]
    struct ErrorBody {
        error: String,
        #[serde(default)]
        error_description: String,
    }
    let malformed = || {
        OAuthError::Malformed(format!("HTTP {}: {}", resp.status, String::from_utf8_lossy(&resp.body)))
    };
    if (200..300).contains(&resp.status) {
        return serde_json::from_slice(&resp.body).map_err(|_| malformed());
    }
    let e: ErrorBody = serde_json::from_slice(&resp.body).map_err(|_| malformed())?;
    Err(OAuthError::Server { status: resp.status, error: e.error, description: e.error_description })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, body: &str) -> HttpResponse {
        HttpResponse { status, headers: vec![], body: body.as_bytes().to_vec() }
    }

    #[test]
    fn exchange_form_exact() {
        assert_eq!(
            token_exchange_form("a b", TOKEN_TYPE_ID_TOKEN, "x.y.z"),
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
             &subject_token=a+b\
             &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-spiffe\
             &client_assertion=x.y.z"
        );
    }

    #[test]
    fn device_code_form_has_scope() {
        assert_eq!(
            device_code_form("cid", "openid profile email"),
            "client_id=cid&scope=openid+profile+email"
        );
    }

    #[test]
    fn device_token_form_exact() {
        assert_eq!(
            device_token_form("cid", "dc"),
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=dc&client_id=cid"
        );
    }

    #[test]
    fn parses_device_authorization() {
        let body = r#"{"device_code":"dc","user_code":"WDJB-MJHT","verification_uri":"https://t/activate",
            "verification_uri_complete":"https://t/activate?user_code=WDJB-MJHT","expires_in":900,"interval":5}"#;
        let auth = parse_device_authorization(&resp(200, body)).unwrap();
        assert_eq!(auth.user_code, "WDJB-MJHT");
        assert_eq!(auth.expires_in, 900);
        assert_eq!(auth.interval, Some(5));
        assert!(matches!(
            parse_device_authorization(&resp(401, r#"{"error":"unauthorized_client","error_description":"no"}"#)),
            Err(OAuthError::Server { status: 401, .. })
        ));
    }

    #[test]
    fn poll_outcomes() {
        assert_eq!(parse_poll(&resp(403, r#"{"error":"authorization_pending"}"#)), Ok(PollOutcome::Pending));
        assert_eq!(parse_poll(&resp(429, r#"{"error":"slow_down"}"#)), Ok(PollOutcome::SlowDown));
        assert_eq!(parse_poll(&resp(403, r#"{"error":"expired_token"}"#)), Ok(PollOutcome::Expired));
        assert_eq!(parse_poll(&resp(403, r#"{"error":"access_denied"}"#)), Ok(PollOutcome::Denied));
        assert_eq!(
            parse_poll(&resp(200, r#"{"access_token":"a","id_token":"i.d.t"}"#)),
            Ok(PollOutcome::IdToken("i.d.t".into()))
        );
        assert_eq!(parse_poll(&resp(200, r#"{"access_token":"a"}"#)), Err(OAuthError::NoIdToken));
        assert_eq!(
            parse_poll(&resp(400, r#"{"error":"invalid_grant","error_description":"x"}"#)),
            Err(OAuthError::Server { status: 400, error: "invalid_grant".into(), description: "x".into() })
        );
        assert!(matches!(parse_poll(&resp(502, "<html>")), Err(OAuthError::Malformed(_))));
    }

    #[test]
    fn exchange_error_surfaces_description() {
        assert_eq!(
            parse_token_exchange(&resp(
                400,
                r#"{"error":"invalid_request","error_description":"subject_token is required"}"#
            )),
            Err(OAuthError::Server {
                status: 400,
                error: "invalid_request".into(),
                description: "subject_token is required".into()
            })
        );
    }

    #[test]
    fn exchange_ok() {
        let body = r#"{"access_token":"o.b.o","issued_token_type":"urn:ietf:params:oauth:token-type:jwt","token_type":"N_A"}"#;
        assert_eq!(parse_token_exchange(&resp(200, body)), Ok("o.b.o".into()));
    }
}
