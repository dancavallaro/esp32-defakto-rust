//! The demo's network steps, in order: attest for a JWT-SVID, log the user in
//! with the device flow, exchange their ID token for an OBO token, then check
//! them in with it.

use std::time::Duration;

use defakto::attest::Attestor;
use defakto::http::{HttpClient, HttpError};
use defakto::jwt::JwtError;
use defakto::oauth::{OAuthError, FORM_CONTENT_TYPE};
use defakto::serverless::{self, SvidToken};
use defakto::token_exchange;

use crate::app::Event;
use crate::claims::DisplayClaims;
use crate::login::{self, DeviceAuthorization, PollOutcome};

pub const SERVERLESS_URL: &str = "https://defakto.o.cavnet.cloud";
pub const TOKEN_URL: &str = "https://defakto.o.cavnet.cloud/oauth/token";
pub const LOGIN_SCOPE: &str = "openid profile email";
const JSON_CONTENT_TYPE: &str = "application/json";

const DEFAULT_POLL_INTERVAL: u64 = 5;
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);
/// Polls run for minutes over flaky WiFi, so one dropped request shouldn't end the sign-in.
const MAX_POLL_FAILURES: u32 = 3;
/// How often a wait between polls checks for cancellation, so a re-tap isn't held up.
const CANCEL_CHECK: Duration = Duration::from_millis(250);

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
    /// Who the OBO token is for: the check-in service, when there is one.
    pub obo_audience: String,
    /// The check-in service the OBO token is presented to. Without one, a
    /// sign-in ends at the token exchange.
    pub checkin_url: Option<String>,
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
    #[error("check-in refused: HTTP {0}")]
    CheckIn(u16),
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
    let resp = http.post(&cfg.login_device_url, FORM_CONTENT_TYPE, &[], body.as_bytes(), &[])?;
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
    let mut failures = 0;

    loop {
        let remaining = deadline - clock.unix_now();
        if remaining <= 0 {
            return Err(FlowError::Expired);
        }
        if sleep_unless_cancelled(clock, interval.min(Duration::from_secs(remaining as u64)), cancelled) {
            return Err(FlowError::Cancelled);
        }
        let resp = match http.post(&cfg.login_token_url, FORM_CONTENT_TYPE, &[], body.as_bytes(), &[]) {
            Ok(resp) if resp.status < 500 => resp,
            failed => {
                failures += 1;
                if failures < MAX_POLL_FAILURES {
                    continue;
                }
                return Err(match failed {
                    Err(e) => e.into(),
                    Ok(resp) => OAuthError::Malformed(format!("HTTP {}", resp.status)).into(),
                });
            }
        };
        failures = 0;
        match login::parse_poll(&resp)? {
            PollOutcome::Pending => {}
            PollOutcome::SlowDown => interval += SLOW_DOWN_STEP,
            PollOutcome::IdToken(token) => return Ok(token),
            PollOutcome::Expired => return Err(FlowError::Expired),
            PollOutcome::Denied => return Err(FlowError::Denied),
        }
    }
}

/// Runs a whole sign-in, reporting its progress through `report`. Once
/// `cancelled` turns true nothing more is reported, so a late failure from a
/// cancelled run can't land on the next one.
pub fn run_login(
    http: &mut impl HttpClient,
    cfg: &Config,
    attestor: &dyn Attestor,
    clock: &mut dyn Clock,
    nonce: &str,
    cancelled: &dyn Fn() -> bool,
    report: &mut dyn FnMut(Event),
) {
    let mut report = |ev| {
        if !cancelled() {
            report(ev)
        }
    };
    match login(http, cfg, attestor, clock, nonce, cancelled, &mut report) {
        Ok(()) | Err(FlowError::Cancelled) => {}
        Err(FlowError::Expired) => report(Event::Expired),
        Err(e) => report(Event::Failed(e.to_string())),
    }
}

fn login(
    http: &mut impl HttpClient,
    cfg: &Config,
    attestor: &dyn Attestor,
    clock: &mut dyn Clock,
    nonce: &str,
    cancelled: &dyn Fn() -> bool,
    report: &mut dyn FnMut(Event),
) -> Result<(), FlowError> {
    let auth = start_login(http, cfg)?;
    report(Event::LoginStarted { auth: auth.clone(), now: clock.unix_now() });
    let id_token = wait_for_id_token(http, cfg, &auth, clock, cancelled)?;
    report(Event::SignedIn);
    let svid = fetch_svid(http, cfg, attestor, clock.unix_now(), nonce)?;
    report(Event::SvidReady);
    let obo = exchange_token(http, cfg, &id_token, &svid)?;
    let claims = DisplayClaims::from_obo_jwt(&obo)?;
    report(Event::Exchanged(claims.clone()));
    if let Some(url) = &cfg.checkin_url {
        check_in(http, url, &obo)?;
        report(Event::CheckedIn(claims));
    }
    Ok(())
}

/// Returns true, having slept less than `d`, if `cancelled` turns true.
fn sleep_unless_cancelled(clock: &mut dyn Clock, d: Duration, cancelled: &dyn Fn() -> bool) -> bool {
    let mut left = d;
    while !left.is_zero() {
        if cancelled() {
            return true;
        }
        let nap = left.min(CANCEL_CHECK);
        clock.sleep(nap);
        left -= nap;
    }
    cancelled()
}

/// Exchanges the user's ID token for an OBO token naming this device as actor.
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

/// Presents the OBO token to the check-in service, which learns from it both
/// who checked in and through which device.
pub fn check_in(http: &mut impl HttpClient, url: &str, obo: &str) -> Result<(), FlowError> {
    let bearer = format!("Bearer {obo}");
    let resp = http.post(url, JSON_CONTENT_TYPE, &[("authorization", &bearer)], b"{}", &[])?;
    match resp.status {
        200..=299 => Ok(()),
        status => Err(FlowError::CheckIn(status)),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use defakto::testing::{make_jwt, svid_response, FakeHttp};

    use super::*;
    use crate::claims::fixtures::alice_obo;

    /// Sums the sleeps between consecutive posts, so tests see one wait per poll.
    struct FakeClock {
        elapsed: Duration,
        waits: Vec<(usize, Duration)>,
        posts: Rc<Cell<usize>>,
    }

    impl FakeClock {
        fn new(http: &FakeHttp) -> Self {
            Self { elapsed: Duration::ZERO, waits: vec![], posts: http.posts.clone() }
        }

        fn waits(&self) -> Vec<u64> {
            self.waits.iter().map(|(_, d)| d.as_secs()).collect()
        }
    }

    impl Clock for FakeClock {
        fn unix_now(&self) -> i64 {
            NOW + self.elapsed.as_secs() as i64
        }
        fn sleep(&mut self, d: Duration) {
            self.elapsed += d;
            match self.waits.last_mut() {
                Some((posts, total)) if *posts == self.posts.get() => *total += d,
                _ => self.waits.push((self.posts.get(), d)),
            }
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
            checkin_url: None,
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
        let mut clock = FakeClock::new(&http);

        let token = wait_for_id_token(&mut http, &cfg(), &auth(900, None), &mut clock, &|| false);

        assert_eq!(token, Ok("t".into()));
        assert_eq!(clock.waits(), [5, 5, 10]);
        for req in &http.requests {
            assert_eq!(req.url, "https://idp.example/token");
            assert_eq!(req.body, login::device_token_form("cid", "dc").into_bytes());
        }
    }

    #[test]
    fn wait_expires_after_deadline() {
        let mut http = FakeHttp::default().reply(403, pending()).reply(403, pending()).reply(403, pending());
        let mut clock = FakeClock::new(&http);

        let result = wait_for_id_token(&mut http, &cfg(), &auth(12, Some(5)), &mut clock, &|| false);

        assert_eq!(result, Err(FlowError::Expired));
        assert!(http.requests.len() <= 3);
        assert!(clock.unix_now() <= NOW + 12, "slept past the deadline");
    }

    #[test]
    fn wait_honours_cancel() {
        let mut http = FakeHttp::default().reply(403, pending()).reply(403, pending());
        let posts = http.posts.clone();
        let mut clock = FakeClock::new(&http);

        let result = wait_for_id_token(&mut http, &cfg(), &auth(900, None), &mut clock, &|| posts.get() >= 1);

        assert_eq!(result, Err(FlowError::Cancelled));
        assert_eq!(http.requests.len(), 1);
    }

    #[test]
    fn cancel_cuts_the_wait_between_polls_short() {
        let mut http = FakeHttp::default();
        let mut clock = FakeClock::new(&http);
        let checks = Cell::new(0);
        let cancel_on_third_check = || {
            checks.set(checks.get() + 1);
            checks.get() >= 3
        };

        let result = wait_for_id_token(&mut http, &cfg(), &auth(900, None), &mut clock, &cancel_on_third_check);

        assert_eq!(result, Err(FlowError::Cancelled));
        assert!(http.requests.is_empty());
        assert!(clock.elapsed < Duration::from_secs(1), "waited {:?} after the cancel", clock.elapsed);
    }

    #[test]
    fn wait_rides_out_transient_poll_failures() {
        let mut http = FakeHttp::default()
            .fail("timeout")
            .reply(502, "<html>Bad Gateway</html>")
            .reply(200, r#"{"id_token":"t"}"#);
        let mut clock = FakeClock::new(&http);

        let token = wait_for_id_token(&mut http, &cfg(), &auth(900, None), &mut clock, &|| false);

        assert_eq!(token, Ok("t".into()));
    }

    #[test]
    fn wait_gives_up_after_repeated_poll_failures() {
        let mut http = FakeHttp::default().fail("timeout").fail("timeout").fail("timeout");
        let mut clock = FakeClock::new(&http);

        let result = wait_for_id_token(&mut http, &cfg(), &auth(900, None), &mut clock, &|| false);

        assert_eq!(result, Err(FlowError::Http(HttpError("timeout".into()))));
        assert_eq!(http.requests.len(), 3);
    }

    #[test]
    fn a_good_poll_resets_the_failure_count() {
        let mut http = FakeHttp::default()
            .fail("timeout")
            .fail("timeout")
            .reply(403, pending())
            .fail("timeout")
            .fail("timeout")
            .reply(200, r#"{"id_token":"t"}"#);
        let mut clock = FakeClock::new(&http);

        let token = wait_for_id_token(&mut http, &cfg(), &auth(900, None), &mut clock, &|| false);

        assert_eq!(token, Ok("t".into()));
    }

    fn device_code(expires_in: u64) -> String {
        format!(r#"{{"device_code":"dc","user_code":"U","verification_uri":"https://t/a","expires_in":{expires_in},"interval":5}}"#)
    }

    fn attestor() -> impl Attestor {
        defakto::attest::HmacAttestor::new(
            "defakto-demo".into(),
            defakto::attest::SoftwareHmacKey(vec![0; 32]),
            "software HMAC",
        )
    }

    fn run(http: &mut FakeHttp, cancelled: &dyn Fn() -> bool) -> Vec<Event> {
        run_with(http, &cfg(), cancelled)
    }

    fn run_with(http: &mut FakeHttp, cfg: &Config, cancelled: &dyn Fn() -> bool) -> Vec<Event> {
        let mut clock = FakeClock::new(http);
        let mut events = vec![];
        run_login(http, cfg, &attestor(), &mut clock, "00", cancelled, &mut |ev| events.push(ev));
        events
    }

    /// Replies for a sign-in that gets as far as the OBO token.
    fn signed_in_and_exchanged(obo: &str) -> FakeHttp {
        FakeHttp::default()
            .reply(200, device_code(900))
            .reply(200, r#"{"id_token":"id.tok.en"}"#)
            .reply(200, svid_response("spiffe://p/iot/defakto-demo", "svid.jwt.sig"))
            .reply(200, format!(r#"{{"access_token":"{obo}"}}"#))
    }

    #[test]
    fn run_login_ends_at_the_exchange_without_a_checkin_url() {
        let mut http = signed_in_and_exchanged(&make_jwt(&alice_obo()));
        let events = run(&mut http, &|| false);
        assert!(
            matches!(&events[..], [Event::LoginStarted { .. }, Event::SignedIn, Event::SvidReady, Event::Exchanged(c)] if c.greeting == "Hi, Alice!"),
            "{events:?}"
        );
    }

    #[test]
    fn run_login_checks_in_with_the_obo_token() {
        let obo = make_jwt(&alice_obo());
        let mut http = signed_in_and_exchanged(&obo).reply(201, "");
        let cfg = Config { checkin_url: Some("https://checkin.example/checkins".into()), ..cfg() };

        let events = run_with(&mut http, &cfg, &|| false);

        let claims = DisplayClaims::from_obo_jwt(&obo).unwrap();
        assert_eq!(events[3..], [Event::Exchanged(claims.clone()), Event::CheckedIn(claims)]);
        assert_eq!(http.requests[4].url, "https://checkin.example/checkins");
    }

    #[test]
    fn check_in_presents_the_obo_token() {
        let mut http = FakeHttp::default().reply(204, "");
        assert_eq!(check_in(&mut http, "https://checkin.example/checkins", "o.b.o"), Ok(()));
        let req = &http.requests[0];
        assert_eq!(req.headers, [("authorization".to_string(), "Bearer o.b.o".to_string())]);
        assert_eq!((req.content_type.as_str(), req.body.as_slice()), (JSON_CONTENT_TYPE, b"{}".as_slice()));
    }

    #[test]
    fn check_in_refusal_is_an_error() {
        let mut http = FakeHttp::default().reply(403, r#"{"error":"unknown device"}"#);
        let err = check_in(&mut http, "https://checkin.example/checkins", "o.b.o").unwrap_err();
        assert_eq!(err.to_string(), "check-in refused: HTTP 403");
    }

    #[test]
    fn run_login_reports_a_failure() {
        let mut http = FakeHttp::default().fail("timeout");
        assert_eq!(run(&mut http, &|| false), [Event::Failed("network: timeout".into())]);
    }

    #[test]
    fn run_login_reports_expiry() {
        let mut http = FakeHttp::default().reply(200, device_code(6)).reply(403, pending()).reply(403, pending());
        let events = run(&mut http, &|| false);
        assert!(matches!(events[..], [Event::LoginStarted { .. }, Event::Expired]), "{events:?}");
    }

    #[test]
    fn run_login_reports_nothing_once_cancelled() {
        let mut http = FakeHttp::default().reply(200, device_code(900)).reply(400, r#"{"error":"invalid_grant"}"#);
        let posts = http.posts.clone();
        let events = run(&mut http, &|| posts.get() >= 2);
        assert!(matches!(events[..], [Event::LoginStarted { .. }]), "{events:?}");
    }

    #[test]
    fn denied_maps_to_denied() {
        let mut http = FakeHttp::default().reply(403, r#"{"error":"access_denied"}"#);
        let mut clock = FakeClock::new(&http);
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
    fn exchange_posts_form() {
        let obo = make_jwt(&alice_obo());
        let mut http = FakeHttp::default().reply(200, format!(r#"{{"access_token":"{obo}"}}"#));
        let svid = SvidToken { spiffe_id: "spiffe://p/iot/defakto-demo".into(), token: "svid.jwt.sig".into() };

        assert_eq!(exchange_token(&mut http, &cfg(), "id.tok.en", &svid), Ok(obo));
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
