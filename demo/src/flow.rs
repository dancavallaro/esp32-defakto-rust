//! The demo's network steps, in order: attest for a JWT-SVID, log the user in
//! with the device flow, then exchange their ID token for an OBO token.

use std::time::Duration;

use defakto::attest::Attestor;
use defakto::http::{HttpClient, HttpError};
use defakto::jwt::JwtError;
use defakto::oauth::{OAuthError, FORM_CONTENT_TYPE};
use defakto::serverless::{self, SvidToken};
use defakto::token_exchange;

use crate::claims::DisplayClaims;
use crate::login::{self, DeviceAuthorization, PollOutcome};

pub const SERVERLESS_URL: &str = "https://defakto.o.cavnet.cloud";
pub const TOKEN_URL: &str = "https://defakto.o.cavnet.cloud/oauth/token";
pub const LOGIN_SCOPE: &str = "openid profile email";

const DEFAULT_POLL_INTERVAL: u64 = 5;
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct Config {
    pub serverless_url: String,
    pub token_url: String,
    pub svid_audience: String,
    /// The IdP's device authorization and token endpoints, from its OIDC
    /// discovery document. They differ per IdP, so neither is derived.
    pub login_device_url: String,
    pub login_token_url: String,
    pub login_client_id: String,
    pub subject_token_type: String,
    pub requested_token_type: String,
    /// Who the OBO token is for; nothing downstream consumes it in this demo.
    pub obo_audience: String,
}

pub trait Clock {
    fn unix_now(&self) -> i64;
    fn sleep(&mut self, d: Duration);
}

/// `Display` is what the error screen shows, so messages stay short.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum FlowError {
    #[error(transparent)]
    Defakto(#[from] defakto::Error),
    #[error("network: {0}")]
    Http(#[from] HttpError),
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
    Ok(serverless::fetch_jwt_svid(http, &cfg.serverless_url, &cfg.svid_audience, attestor, now, nonce)?)
}

pub fn start_login(http: &mut impl HttpClient, cfg: &Config) -> Result<DeviceAuthorization, FlowError> {
    let body = login::device_code_form(&cfg.login_client_id, LOGIN_SCOPE);
    let resp = http.post(&cfg.login_device_url, FORM_CONTENT_TYPE, body.as_bytes(), &[])?;
    Ok(login::parse_device_authorization(&resp)?)
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
    let body = login::device_token_form(&cfg.login_client_id, &auth.device_code);
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
        let resp = http.post(&cfg.login_token_url, FORM_CONTENT_TYPE, body.as_bytes(), &[])?;
        match login::parse_poll(&resp)? {
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
    let token = exchange_token(http, cfg, id_token, svid)?;
    Ok(DisplayClaims::from_obo_jwt(&token)?)
}

/// Like `exchange`, but returns the raw OBO token.
pub fn exchange_token(
    http: &mut impl HttpClient,
    cfg: &Config,
    id_token: &str,
    svid: &SvidToken,
) -> Result<String, FlowError> {
    let req = token_exchange::Request {
        subject_token: id_token,
        subject_token_type: &cfg.subject_token_type,
        requested_token_type: &cfg.requested_token_type,
        audience: &cfg.obo_audience,
    };
    Ok(token_exchange::exchange(http, &cfg.token_url, &req, svid)?)
}

#[cfg(test)]
mod tests {
    use defakto::testing::{make_jwt, FakeHttp};

    use super::*;
    use crate::claims::fixtures::alice_obo;

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
            login_device_url: "https://idp.example/device".into(),
            login_token_url: "https://idp.example/token".into(),
            login_client_id: "cid".into(),
            subject_token_type: token_exchange::TOKEN_TYPE_ID_TOKEN.into(),
            requested_token_type: token_exchange::TOKEN_TYPE_JWT_SVID_OBO.into(),
            obo_audience: "https://api.example".into(),
        }
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
    fn start_login_posts_device_code() {
        let body = r#"{"device_code":"dc","user_code":"U","verification_uri":"https://t/a","expires_in":900}"#;
        let mut http = FakeHttp::default().reply(200, body);
        assert_eq!(start_login(&mut http, &cfg()).unwrap().device_code, "dc");
        assert_eq!(http.requests[0].url, "https://idp.example/device");
        assert_eq!(http.requests[0].body, login::device_code_form("cid", LOGIN_SCOPE).into_bytes());
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
            assert_eq!(req.url, "https://idp.example/token");
            assert_eq!(req.body, login::device_token_form("cid", "dc").into_bytes());
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
        let mut http = FakeHttp::default().fail("timeout");
        let err = start_login(&mut http, &cfg()).unwrap_err();
        assert_eq!(err, FlowError::Http(HttpError("timeout".into())));
        assert_eq!(err.to_string(), "network: timeout");
    }

    #[test]
    fn fetch_svid_uses_config() {
        let mut http = FakeHttp::default().fail("timeout");
        let attestor = defakto::attest::HmacAttestor::new(
            "defakto-demo".into(),
            defakto::attest::SoftwareHmacKey(vec![0; 32]),
            "software HMAC",
        );
        let err = fetch_svid(&mut http, &cfg(), &attestor, NOW, "00").unwrap_err();
        assert_eq!(http.requests[0].url, format!("{SERVERLESS_URL}{}", serverless::FETCH_JWT_SVID_PATH));
        assert_eq!(err.to_string(), "network: timeout");
    }

    #[test]
    fn exchange_posts_form_and_decodes() {
        let obo = make_jwt(&alice_obo());
        let mut http = FakeHttp::default().reply(200, format!(r#"{{"access_token":"{obo}"}}"#));
        let svid = SvidToken { spiffe_id: "spiffe://p/iot/defakto-demo".into(), token: "svid.jwt.sig".into() };

        let claims = exchange(&mut http, &cfg(), "id.tok.en", &svid).unwrap();

        assert_eq!(claims.greeting, "Hi, Alice!");
        assert_eq!(http.requests[0].url, TOKEN_URL);
        assert_eq!(
            http.requests[0].body,
            token_exchange::request_form(
                &token_exchange::Request {
                    subject_token: "id.tok.en",
                    subject_token_type: token_exchange::TOKEN_TYPE_ID_TOKEN,
                    requested_token_type: token_exchange::TOKEN_TYPE_JWT_SVID_OBO,
                    audience: "https://api.example",
                },
                "svid.jwt.sig"
            )
            .into_bytes()
        );
    }
}
