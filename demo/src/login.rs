//! Signing the user in with the OAuth device authorization grant (RFC 8628),
//! which suits a device that can show a QR code but has no keyboard.

use defakto::http::HttpResponse;
use defakto::oauth::{form, parse_json, OAuthError};
use serde::Deserialize;

pub const GRANT_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";

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

pub fn device_code_form(client_id: &str, scope: &str) -> String {
    form(&[("client_id", client_id), ("scope", scope)])
}

pub fn device_token_form(client_id: &str, device_code: &str) -> String {
    form(&[("grant_type", GRANT_DEVICE_CODE), ("device_code", device_code), ("client_id", client_id)])
}

pub fn parse_device_authorization(resp: &HttpResponse) -> Result<DeviceAuthorization, OAuthError> {
    parse_json(resp)
}

pub fn parse_poll(resp: &HttpResponse) -> Result<PollOutcome, OAuthError> {
    #[derive(Deserialize)]
    struct Tokens {
        id_token: Option<String>,
    }
    match parse_json::<Tokens>(resp) {
        Ok(Tokens { id_token: Some(t) }) => Ok(PollOutcome::IdToken(t)),
        Ok(Tokens { id_token: None }) => Err(OAuthError::Missing("id_token")),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, body: &str) -> HttpResponse {
        HttpResponse { status, headers: vec![], body: body.as_bytes().to_vec() }
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
        assert_eq!(parse_poll(&resp(200, r#"{"access_token":"a"}"#)), Err(OAuthError::Missing("id_token")));
        assert_eq!(
            parse_poll(&resp(400, r#"{"error":"invalid_grant","error_description":"x"}"#)),
            Err(OAuthError::Server { status: 400, error: "invalid_grant".into(), description: "x".into() })
        );
        assert!(matches!(parse_poll(&resp(502, "<html>")), Err(OAuthError::Malformed(_))));
    }
}
