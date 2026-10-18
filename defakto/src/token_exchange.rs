//! RFC 8693 token exchange at the Trust Domain Server, authenticated with a
//! JWT-SVID. Exchanging a user's ID token yields an OBO token that names this
//! workload as the actor.

use serde::Deserialize;

use crate::http::{HttpClient, HttpResponse};
use crate::oauth::{form, parse_json, OAuthError, FORM_CONTENT_TYPE};
use crate::serverless::SvidToken;
use crate::Error;

pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const CLIENT_ASSERTION_JWT_SPIFFE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe";
pub const TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
/// The delegated JWT-SVID Defakto issues; also the subject type for re-exchanging one.
pub const TOKEN_TYPE_JWT_SVID_OBO: &str = "urn:defakto:security:token-type:jwt-svid-obo";

/// RFC 8693 leaves `requested_token_type` and `audience` optional, but the
/// Trust Domain Server rejects requests without them.
#[derive(Debug, Clone, PartialEq)]
pub struct Request<'a> {
    pub subject_token: &'a str,
    pub subject_token_type: &'a str,
    pub requested_token_type: &'a str,
    /// Who the issued token is for.
    pub audience: &'a str,
}

pub fn request_form(req: &Request, client_assertion: &str) -> String {
    form(&[
        ("grant_type", GRANT_TYPE),
        ("subject_token", req.subject_token),
        ("subject_token_type", req.subject_token_type),
        ("requested_token_type", req.requested_token_type),
        ("audience", req.audience),
        ("client_assertion_type", CLIENT_ASSERTION_JWT_SPIFFE),
        ("client_assertion", client_assertion),
    ])
}

/// Returns the issued token (`access_token`).
pub fn parse_response(resp: &HttpResponse) -> Result<String, OAuthError> {
    #[derive(Deserialize)]
    struct Issued {
        access_token: String,
    }
    parse_json::<Issued>(resp).map(|i| i.access_token)
}

/// Exchanges `req.subject_token` for a token issued to `svid`'s workload.
pub fn exchange(http: &mut impl HttpClient, token_url: &str, req: &Request, svid: &SvidToken) -> Result<String, Error> {
    let body = request_form(req, &svid.token);
    let resp = http.post(token_url, FORM_CONTENT_TYPE, &[], body.as_bytes(), &[])?;
    Ok(parse_response(&resp)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeHttp;

    fn resp(status: u16, body: &str) -> HttpResponse {
        HttpResponse { status, headers: vec![], body: body.as_bytes().to_vec() }
    }

    fn request(subject_token: &str) -> Request<'_> {
        Request {
            subject_token,
            subject_token_type: TOKEN_TYPE_ID_TOKEN,
            requested_token_type: TOKEN_TYPE_JWT_SVID_OBO,
            audience: "aud",
        }
    }

    #[test]
    fn request_form_exact() {
        assert_eq!(
            request_form(&request("a b"), "x.y.z"),
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
             &subject_token=a+b\
             &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token\
             &requested_token_type=urn%3Adefakto%3Asecurity%3Atoken-type%3Ajwt-svid-obo\
             &audience=aud\
             &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-spiffe\
             &client_assertion=x.y.z"
        );
    }

    #[test]
    fn error_surfaces_description() {
        assert_eq!(
            parse_response(&resp(
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
    fn parses_issued_token() {
        let body = r#"{"access_token":"o.b.o","issued_token_type":"urn:ietf:params:oauth:token-type:jwt","token_type":"N_A"}"#;
        assert_eq!(parse_response(&resp(200, body)), Ok("o.b.o".into()));
    }

    #[test]
    fn exchange_posts_form() {
        let mut http = FakeHttp::default().reply(200, r#"{"access_token":"o.b.o"}"#);
        let svid = SvidToken { spiffe_id: "spiffe://p/iot/defakto-demo".into(), token: "svid.jwt.sig".into() };

        let token = exchange(&mut http, "https://tds/oauth/token", &request("id.tok.en"), &svid);

        assert_eq!(token, Ok("o.b.o".into()));
        let req = &http.requests[0];
        assert_eq!(req.url, "https://tds/oauth/token");
        assert_eq!(req.content_type, FORM_CONTENT_TYPE);
        assert_eq!(req.body, request_form(&request("id.tok.en"), "svid.jwt.sig").into_bytes());
    }

    #[test]
    fn network_failure_is_http_error() {
        let mut http = FakeHttp::default().fail("timeout");
        let svid = SvidToken { spiffe_id: "s".into(), token: "t".into() };
        let err = exchange(&mut http, "https://tds/oauth/token", &request("i"), &svid).unwrap_err();
        assert_eq!(err.to_string(), "network: timeout");
    }
}
