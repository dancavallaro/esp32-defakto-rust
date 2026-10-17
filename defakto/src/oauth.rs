//! OAuth 2.0 plumbing shared by every token endpoint: form bodies and the
//! RFC 6749 error response.

use serde::Deserialize;

use crate::http::HttpResponse;

pub const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum OAuthError {
    #[error("{error}: {description}")]
    Server { status: u16, error: String, description: String },
    #[error("unexpected response: {0}")]
    Malformed(String),
    #[error("no {0} in response")]
    Missing(&'static str),
}

pub fn form(pairs: &[(&str, &str)]) -> String {
    form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish()
}

/// Decodes a 2xx body as `T`, or a non-2xx body as an OAuth error response.
pub fn parse_json<T: serde::de::DeserializeOwned>(resp: &HttpResponse) -> Result<T, OAuthError> {
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

    #[derive(Debug, PartialEq, Deserialize)]
    struct Tokens {
        access_token: String,
    }

    #[test]
    fn form_encodes_pairs() {
        assert_eq!(form(&[("scope", "openid email"), ("x", "a:b")]), "scope=openid+email&x=a%3Ab");
    }

    #[test]
    fn success_body_decodes() {
        assert_eq!(parse_json(&resp(200, r#"{"access_token":"t"}"#)), Ok(Tokens { access_token: "t".into() }));
    }

    #[test]
    fn error_body_is_server_error() {
        assert_eq!(
            parse_json::<Tokens>(&resp(400, r#"{"error":"invalid_grant","error_description":"x"}"#)),
            Err(OAuthError::Server { status: 400, error: "invalid_grant".into(), description: "x".into() })
        );
    }

    #[test]
    fn non_json_is_malformed() {
        assert_eq!(
            parse_json::<Tokens>(&resp(502, "<html>")),
            Err(OAuthError::Malformed("HTTP 502: <html>".into()))
        );
    }
}
