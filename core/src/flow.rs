//! The demo's network steps, in order: attest for a JWT-SVID, log the user in
//! with the device flow, then exchange their ID token for an OBO token.

use std::time::Duration;

use crate::attest::{AttestError, Attestor};
use crate::grpcweb::{self, GrpcError};
use crate::http::{HttpClient, HttpError};
use crate::jwt::{DisplayClaims, JwtError};
use crate::oauth::{self, DeviceAuthorization, OAuthError, PollOutcome};
use crate::serverless::{self, ServerlessError, SvidToken};

pub const SERVERLESS_URL: &str = "https://defakto.o.cavnet.cloud";
pub const TOKEN_URL: &str = "https://defakto.o.cavnet.cloud/oauth/token";
pub const LOGIN_SCOPE: &str = "openid profile email";

/// Evidence timestamps before this (2024-01-01) mean the clock was never set.
const EARLIEST_VALID_TIME: i64 = 1_704_067_200;
const DEFAULT_POLL_INTERVAL: u64 = 5;
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct Config {
    pub serverless_url: String,
    pub token_url: String,
    pub svid_audience: String,
    pub auth0_domain: String,
    pub auth0_client_id: String,
    pub subject_token_type: String,
}

pub trait Clock {
    fn unix_now(&self) -> i64;
    fn sleep(&mut self, d: Duration);
}

/// `Display` is what the error screen shows, so messages stay short.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum FlowError {
    #[error("clock not set")]
    ClockNotSet,
    #[error("network: {0}")]
    Http(#[from] HttpError),
    #[error(transparent)]
    Grpc(#[from] GrpcError),
    #[error(transparent)]
    Attest(#[from] AttestError),
    #[error(transparent)]
    Serverless(#[from] ServerlessError),
    #[error(transparent)]
    OAuth(#[from] OAuthError),
    #[error(transparent)]
    Jwt(#[from] JwtError),
    #[error("code expired")]
    Expired,
    #[error("sign-in declined")]
    Denied,
    #[error("cancelled")]
    Cancelled,
}

pub fn fetch_svid(
    http: &mut impl HttpClient,
    cfg: &Config,
    attestor: &dyn Attestor,
    now: i64,
    nonce: &str,
) -> Result<SvidToken, FlowError> {
    if now < EARLIEST_VALID_TIME {
        return Err(FlowError::ClockNotSet);
    }
    let evidence = attestor.evidence(now, nonce)?;
    let body = serverless::fetch_jwt_svid_body(&evidence, &cfg.svid_audience);
    let url = format!("{}{}", cfg.serverless_url, serverless::FETCH_JWT_SVID_PATH);
    let resp = http.post(&url, grpcweb::CONTENT_TYPE, &body, grpcweb::READ_HEADERS)?;
    Ok(serverless::parse_fetch_jwt_svid(&grpcweb::parse_response(&resp)?)?)
}

pub fn start_login(http: &mut impl HttpClient, cfg: &Config) -> Result<DeviceAuthorization, FlowError> {
    let url = format!("https://{}/oauth/device/code", cfg.auth0_domain);
    let body = oauth::device_code_form(&cfg.auth0_client_id, LOGIN_SCOPE);
    let resp = http.post(&url, oauth::FORM_CONTENT_TYPE, body.as_bytes(), &[])?;
    Ok(oauth::parse_device_authorization(&resp)?)
}

/// Polls until the user finishes signing in, the code expires, or `cancelled`
/// returns true. Never sleeps past the code's expiry.
pub fn wait_for_id_token(
    http: &mut impl HttpClient,
    cfg: &Config,
    auth: &DeviceAuthorization,
    clock: &mut dyn Clock,
    cancelled: &dyn Fn() -> bool,
) -> Result<String, FlowError> {
    let url = format!("https://{}/oauth/token", cfg.auth0_domain);
    let body = oauth::device_token_form(&cfg.auth0_client_id, &auth.device_code);
    let deadline = clock.unix_now() + auth.expires_in as i64;
    let mut interval = Duration::from_secs(auth.interval.unwrap_or(DEFAULT_POLL_INTERVAL));

    loop {
        let remaining = deadline - clock.unix_now();
        if remaining <= 0 {
            return Err(FlowError::Expired);
        }
        if cancelled() {
            return Err(FlowError::Cancelled);
        }
        clock.sleep(interval.min(Duration::from_secs(remaining as u64)));
        if cancelled() {
            return Err(FlowError::Cancelled);
        }
        let resp = http.post(&url, oauth::FORM_CONTENT_TYPE, body.as_bytes(), &[])?;
        match oauth::parse_poll(&resp)? {
            PollOutcome::Pending => {}
            PollOutcome::SlowDown => interval += SLOW_DOWN_STEP,
            PollOutcome::IdToken(token) => return Ok(token),
            PollOutcome::Expired => return Err(FlowError::Expired),
            PollOutcome::Denied => return Err(FlowError::Denied),
        }
    }
}

pub fn exchange(
    http: &mut impl HttpClient,
    cfg: &Config,
    id_token: &str,
    svid: &SvidToken,
) -> Result<DisplayClaims, FlowError> {
    let body = oauth::token_exchange_form(id_token, &cfg.subject_token_type, &svid.token);
    let resp = http.post(&cfg.token_url, oauth::FORM_CONTENT_TYPE, body.as_bytes(), &[])?;
    let token = oauth::parse_token_exchange(&resp)?;
    Ok(DisplayClaims::from_obo_jwt(&token)?)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use super::*;
    use crate::attest::{HmacAttestor, SoftwareHmacKey};
    use crate::http::HttpResponse;
    use crate::jwt::fixtures::{alice_obo, make_jwt};

    #[derive(Debug, Clone, PartialEq)]
    struct Request {
        url: String,
        content_type: String,
        body: Vec<u8>,
        read_headers: Vec<String>,
    }

    #[derive(Default)]
    struct FakeHttp {
        replies: VecDeque<Result<HttpResponse, HttpError>>,
        requests: Vec<Request>,
        posts: Rc<Cell<usize>>,
    }

    impl FakeHttp {
        fn reply(mut self, status: u16, body: impl Into<Vec<u8>>) -> Self {
            self.replies.push_back(Ok(HttpResponse { status, headers: vec![], body: body.into() }));
            self
        }
    }

    impl HttpClient for FakeHttp {
        fn post(&mut self, url: &str, content_type: &str, body: &[u8], read_headers: &[&str]) -> Result<HttpResponse, HttpError> {
            self.posts.set(self.posts.get() + 1);
            self.requests.push(Request {
                url: url.into(),
                content_type: content_type.into(),
                body: body.to_vec(),
                read_headers: read_headers.iter().map(|h| h.to_string()).collect(),
            });
            self.replies.pop_front().expect("unexpected request")
        }
    }

    struct FakeClock {
        now: i64,
        slept: Vec<Duration>,
    }

    impl Clock for FakeClock {
        fn unix_now(&self) -> i64 {
            self.now
        }
        fn sleep(&mut self, d: Duration) {
            self.now += d.as_secs() as i64;
            self.slept.push(d);
        }
    }

    fn cfg() -> Config {
        Config {
            serverless_url: SERVERLESS_URL.into(),
            token_url: TOKEN_URL.into(),
            svid_audience: "https://issuer.example".into(),
            auth0_domain: "t.us.auth0.com".into(),
            auth0_client_id: "cid".into(),
            subject_token_type: oauth::TOKEN_TYPE_ID_TOKEN.into(),
        }
    }

    fn attestor() -> HmacAttestor<SoftwareHmacKey> {
        HmacAttestor::new("c6-demo".into(), SoftwareHmacKey((0u8..32).collect()), "software HMAC")
    }

    fn auth(expires_in: u64, interval: Option<u64>) -> DeviceAuthorization {
        DeviceAuthorization {
            device_code: "dc".into(),
            user_code: "WDJB-MJHT".into(),
            verification_uri: "https://t/activate".into(),
            verification_uri_complete: None,
            expires_in,
            interval,
        }
    }

    fn pending() -> &'static str {
        r#"{"error":"authorization_pending"}"#
    }

    const NOW: i64 = 1_792_200_000;

    #[test]
    fn fetch_svid_posts_grpc_web() {
        let mut body = grpcweb::frame(&serverless::encode_response(&[("spiffe://p/iot/c6-demo", "jwt")]));
        body.extend([0x80, 0, 0, 0, 15]);
        body.extend(b"grpc-status:0\r\n");
        let mut http = FakeHttp::default().reply(200, body);

        let svid = fetch_svid(&mut http, &cfg(), &attestor(), NOW, "0011223344556677").unwrap();

        assert_eq!(svid, SvidToken { spiffe_id: "spiffe://p/iot/c6-demo".into(), token: "jwt".into() });
        let req = &http.requests[0];
        assert_eq!(req.url, format!("{SERVERLESS_URL}{}", serverless::FETCH_JWT_SVID_PATH));
        assert_eq!(req.content_type, grpcweb::CONTENT_TYPE);
        assert_eq!(req.read_headers, grpcweb::READ_HEADERS);
        let ev = attestor().evidence(NOW, "0011223344556677").unwrap();
        assert_eq!(req.body, serverless::fetch_jwt_svid_body(&ev, "https://issuer.example"));
    }

    #[test]
    fn fetch_svid_rejects_unset_clock() {
        let mut http = FakeHttp::default();
        assert_eq!(fetch_svid(&mut http, &cfg(), &attestor(), 1_000, "00"), Err(FlowError::ClockNotSet));
        assert!(http.requests.is_empty());
    }

    #[test]
    fn start_login_posts_device_code() {
        let body = r#"{"device_code":"dc","user_code":"U","verification_uri":"https://t/a","expires_in":900}"#;
        let mut http = FakeHttp::default().reply(200, body);
        assert_eq!(start_login(&mut http, &cfg()).unwrap().device_code, "dc");
        assert_eq!(http.requests[0].url, "https://t.us.auth0.com/oauth/device/code");
        assert_eq!(http.requests[0].body, oauth::device_code_form("cid", LOGIN_SCOPE).into_bytes());
    }

    #[test]
    fn wait_polls_until_token() {
        let mut http = FakeHttp::default()
            .reply(403, pending())
            .reply(429, r#"{"error":"slow_down"}"#)
            .reply(200, r#"{"id_token":"t"}"#);
        let mut clock = FakeClock { now: NOW, slept: vec![] };

        let token = wait_for_id_token(&mut http, &cfg(), &auth(900, None), &mut clock, &|| false);

        assert_eq!(token, Ok("t".into()));
        let secs: Vec<u64> = clock.slept.iter().map(Duration::as_secs).collect();
        assert_eq!(secs, [5, 5, 10]);
        for req in &http.requests {
            assert_eq!(req.url, "https://t.us.auth0.com/oauth/token");
            assert_eq!(req.body, oauth::device_token_form("cid", "dc").into_bytes());
        }
    }

    #[test]
    fn wait_expires_after_deadline() {
        let mut http = FakeHttp::default().reply(403, pending()).reply(403, pending()).reply(403, pending());
        let mut clock = FakeClock { now: NOW, slept: vec![] };

        let result = wait_for_id_token(&mut http, &cfg(), &auth(12, Some(5)), &mut clock, &|| false);

        assert_eq!(result, Err(FlowError::Expired));
        assert!(http.requests.len() <= 3);
        assert!(clock.now <= NOW + 12, "slept past the deadline");
    }

    #[test]
    fn wait_honours_cancel() {
        let mut http = FakeHttp::default().reply(403, pending()).reply(403, pending());
        let posts = http.posts.clone();
        let mut clock = FakeClock { now: NOW, slept: vec![] };

        let result = wait_for_id_token(&mut http, &cfg(), &auth(900, None), &mut clock, &|| posts.get() >= 1);

        assert_eq!(result, Err(FlowError::Cancelled));
        assert_eq!(http.requests.len(), 1);
    }

    #[test]
    fn denied_maps_to_denied() {
        let mut http = FakeHttp::default().reply(403, r#"{"error":"access_denied"}"#);
        let mut clock = FakeClock { now: NOW, slept: vec![] };
        assert_eq!(
            wait_for_id_token(&mut http, &cfg(), &auth(900, None), &mut clock, &|| false),
            Err(FlowError::Denied)
        );
    }

    #[test]
    fn http_error_maps_to_flow_error() {
        let mut http = FakeHttp::default();
        http.replies.push_back(Err(HttpError("timeout".into())));
        let err = start_login(&mut http, &cfg()).unwrap_err();
        assert_eq!(err, FlowError::Http(HttpError("timeout".into())));
        assert_eq!(err.to_string(), "network: timeout");
    }

    #[test]
    fn exchange_posts_form_and_decodes() {
        let obo = make_jwt(&alice_obo());
        let mut http = FakeHttp::default().reply(200, format!(r#"{{"access_token":"{obo}"}}"#));
        let svid = SvidToken { spiffe_id: "spiffe://p/iot/c6-demo".into(), token: "svid.jwt.sig".into() };

        let claims = exchange(&mut http, &cfg(), "id.tok.en", &svid).unwrap();

        assert_eq!(claims.greeting, "Hi, Alice!");
        assert_eq!(http.requests[0].url, TOKEN_URL);
        assert_eq!(http.requests[0].content_type, oauth::FORM_CONTENT_TYPE);
        assert_eq!(
            http.requests[0].body,
            oauth::token_exchange_form("id.tok.en", oauth::TOKEN_TYPE_ID_TOKEN, "svid.jwt.sig").into_bytes()
        );
    }
}
