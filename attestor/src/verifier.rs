//! The webhook's verification, without HTTP: decode the payload, check its signature, then its
//! freshness, then the replay cache, following the Go `esp32-attestor`'s `webhook.go`.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine};
use esp_attest::evidence::{parse_evidence, Evidence};
use esp_attest::hmac::HmacEvidence;
use esp_attest::tee_verify::{TeeClaims, TeeEnvelope};
use serde::de::IgnoredAny;

use crate::enrollment::Devices;

/// Unknown devices and bad signatures share one message so the response can't be used to
/// enumerate which device IDs are enrolled; the real reason is logged.
pub const REJECT_INVALID: &str = "invalid evidence";
pub const REJECT_STALE: &str = "stale evidence";

/// The webhook's answer: attributes on success, or only `error`. Sorted, as Go encodes maps.
pub type Response = BTreeMap<String, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    Hmac,
    Tee,
}

impl Anchor {
    /// The `anchor` attribute, which Defakto policies match on.
    fn attribute(self) -> &'static str {
        match self {
            Anchor::Hmac => "nvs_secret",
            Anchor::Tee => "tee",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Accepted,
    Replayed,
    Rejected,
}

/// What happened to one attestation attempt. Its `Display` is the attempt's log line.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    /// As presented, whether or not it's enrolled.
    pub device_id: Option<String>,
    pub anchor: Option<Anchor>,
    pub outcome: Outcome,
    /// Why it was rejected, which the response deliberately doesn't say.
    pub reason: Option<String>,
    pub tee: Option<TeeClaims>,
}

pub struct Verifier {
    devices: RwLock<Devices>,
    skew: Duration,
    seen: Mutex<HashMap<String, ReplayEntry>>,
}

struct ReplayEntry {
    at: SystemTime,
    response: Response,
}

impl Verifier {
    pub fn new(devices: Devices, skew: Duration) -> Self {
        Verifier { devices: RwLock::new(devices), skew, seen: Mutex::new(HashMap::new()) }
    }

    /// Replaces the enrolled devices. The replay cache is kept: its entries expire on their own.
    pub fn set_devices(&self, devices: Devices) {
        *self.devices.write().unwrap_or_else(PoisonError::into_inner) = devices;
    }

    /// Verifies the evidence in a request's `payload` as of `now`.
    pub fn attest(&self, payload: &str, now: SystemTime) -> (Response, Decision) {
        let evidence = decode_payload(payload).and_then(|raw| parse_evidence(&raw).map_err(|e| e.0));
        let attempt = match evidence {
            Ok(Evidence::Hmac(e)) => self.verify_hmac(&e, now),
            Ok(Evidence::Tee(e)) => self.verify_tee(&e, now),
            Err(reason) => {
                Attempt { device_id: None, anchor: None, tee: None, result: Err(Rejection::invalid(reason)) }
            }
        };
        attempt.finish()
    }

    fn verify_hmac(&self, e: &HmacEvidence, now: SystemTime) -> Attempt {
        let result = self.check_hmac(e).and_then(|()| {
            let attrs = Response::from([
                ("device_id".to_owned(), e.device_id.clone()),
                ("anchor".to_owned(), Anchor::Hmac.attribute().to_owned()),
            ]);
            self.accept(Anchor::Hmac, &e.device_id, e.ts, &e.nonce, attrs, now)
        });
        Attempt { device_id: Some(e.device_id.clone()), anchor: Some(Anchor::Hmac), tee: None, result }
    }

    fn check_hmac(&self, e: &HmacEvidence) -> Result<(), Rejection> {
        let devices = self.devices.read().unwrap_or_else(PoisonError::into_inner);
        let device = devices.get(&e.device_id).ok_or_else(|| Rejection::invalid("not enrolled"))?;
        // An empty secret is still a valid HMAC key, so a TEE-only device must never reach verify.
        let secret = device.secret.as_ref().ok_or_else(|| Rejection::invalid("no secret enrolled"))?;
        // Checked before the replay cache, so a cached success can never be reached without a
        // valid signature.
        if !e.verify(secret) {
            return Err(Rejection::invalid("signature mismatch"));
        }
        Ok(())
    }

    fn verify_tee(&self, env: &TeeEnvelope, now: SystemTime) -> Attempt {
        let (result, tee) = match self.check_tee(env) {
            Ok(claims) => {
                let attrs = tee_attributes(&env.device_id, &claims);
                (self.accept(Anchor::Tee, &env.device_id, env.ts, &env.nonce, attrs, now), Some(claims))
            }
            Err(rejection) => (Err(rejection), None),
        };
        Attempt { device_id: Some(env.device_id.clone()), anchor: Some(Anchor::Tee), tee, result }
    }

    fn check_tee(&self, env: &TeeEnvelope) -> Result<TeeClaims, Rejection> {
        let devices = self.devices.read().unwrap_or_else(PoisonError::into_inner);
        let device = devices.get(&env.device_id).ok_or_else(|| Rejection::invalid("not enrolled"))?;
        let key = device.tee_key.as_ref().ok_or_else(|| Rejection::invalid("no TEE key enrolled"))?;
        // As for HMAC, the signature is checked before the replay cache.
        env.verify(key).map_err(|e| Rejection::invalid(e.0))
    }

    /// The freshness and replay checks shared by every anchor, for evidence whose signature has
    /// already been verified.
    fn accept(
        &self,
        anchor: Anchor,
        device_id: &str,
        ts: i64,
        nonce: &str,
        attrs: Response,
        now: SystemTime,
    ) -> Result<Accepted, Rejection> {
        if !self.fresh(ts, now) {
            return Err(Rejection {
                error: REJECT_STALE,
                reason: format!("ts {ts} is more than {}s from now", self.skew.as_secs()),
            });
        }
        Ok(self.result_for(anchor, device_id, nonce, attrs, now))
    }

    /// `|now - ts| <= skew`, at `now`'s full precision as Go compares. A `ts` outside what
    /// `SystemTime` can hold is never fresh.
    fn fresh(&self, ts: i64, now: SystemTime) -> bool {
        let secs = Duration::from_secs(ts.unsigned_abs());
        let at = if ts >= 0 { UNIX_EPOCH.checked_add(secs) } else { UNIX_EPOCH.checked_sub(secs) };
        let Some(at) = at else { return false };
        let diff = now.duration_since(at).unwrap_or_else(|e| e.duration());
        diff <= self.skew
    }

    /// Replays the stored result for a repeated nonce. The trust domain server retries 5xx, so
    /// a repeat must succeed identically rather than be rejected.
    fn result_for(&self, anchor: Anchor, device_id: &str, nonce: &str, attrs: Response, now: SystemTime) -> Accepted {
        // Keyed by anchor too, so evidence from a weaker anchor can never be served a stronger
        // one's cached attributes.
        let key = format!("{}|{device_id}|{nonce}", anchor.attribute());
        let mut seen = self.seen();
        if let Some(entry) = seen.get(&key) {
            return Accepted { response: entry.response.clone(), replayed: true };
        }
        let max_age = 2 * self.skew;
        seen.retain(|_, entry| now.duration_since(entry.at).map_or(true, |age| age <= max_age));
        seen.insert(key, ReplayEntry { at: now, response: attrs.clone() });
        Accepted { response: attrs, replayed: false }
    }

    fn seen(&self) -> MutexGuard<'_, HashMap<String, ReplayEntry>> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    fn cached(&self) -> usize {
        self.seen().len()
    }
}

/// Defakto documents the payload as base64 but sends the evidence verbatim, so accept both.
fn decode_payload(payload: &str) -> Result<Vec<u8>, String> {
    if serde_json::from_str::<IgnoredAny>(payload).is_ok() {
        return Ok(payload.as_bytes().to_vec());
    }
    let stripped: String = payload.chars().filter(|c| !matches!(c, '\r' | '\n')).collect();
    STANDARD.decode(stripped).map_err(|e| format!("payload is neither JSON nor base64: {e}"))
}

fn tee_attributes(device_id: &str, claims: &TeeClaims) -> Response {
    [
        ("device_id", device_id.to_owned()),
        ("anchor", Anchor::Tee.attribute().to_owned()),
        ("app_version", claims.app.ver.clone()),
        ("app_digest", claims.app.calc_digest.clone()),
        ("app_secure_version", claims.app.secure_ver.to_string()),
        ("tee_version", claims.tee.ver.clone()),
        ("tee_digest", claims.tee.calc_digest.clone()),
        ("bootloader_digest", claims.bootloader.calc_digest.clone()),
        ("idf_version", claims.app.idf_ver.clone()),
        ("secure_boot", secure_boot(claims).to_string()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect()
}

fn secure_boot(claims: &TeeClaims) -> bool {
    claims.tee.sign_verified && claims.app.sign_verified && claims.bootloader.sign_verified
}

/// One attempt on its way to a `Decision`.
struct Attempt {
    device_id: Option<String>,
    anchor: Option<Anchor>,
    tee: Option<TeeClaims>,
    result: Result<Accepted, Rejection>,
}

struct Accepted {
    response: Response,
    replayed: bool,
}

struct Rejection {
    error: &'static str,
    reason: String,
}

impl Rejection {
    fn invalid(reason: impl Into<String>) -> Self {
        Rejection { error: REJECT_INVALID, reason: reason.into() }
    }
}

impl Attempt {
    fn finish(self) -> (Response, Decision) {
        let (response, outcome, reason, tee) = match self.result {
            Ok(a) => {
                let outcome = if a.replayed { Outcome::Replayed } else { Outcome::Accepted };
                (a.response, outcome, None, self.tee)
            }
            Err(r) => {
                let response = Response::from([("error".to_owned(), r.error.to_owned())]);
                (response, Outcome::Rejected, Some(r.reason), None)
            }
        };
        (response, Decision { device_id: self.device_id, anchor: self.anchor, outcome, reason, tee })
    }
}

impl fmt::Display for Anchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Anchor::Hmac => "hmac",
            Anchor::Tee => "tee",
        })
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Outcome::Accepted => "accepted",
            Outcome::Replayed => "replayed",
            Outcome::Rejected => "rejected",
        })
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("attest")?;
        if let Some(device_id) = &self.device_id {
            write!(f, " device_id={device_id:?}")?;
        }
        if let Some(anchor) = self.anchor {
            write!(f, " anchor={anchor}")?;
        }
        write!(f, " outcome={}", self.outcome)?;
        if let Some(reason) = &self.reason {
            write!(f, " reason={reason:?}")?;
        }
        if let Some(c) = &self.tee {
            write!(
                f,
                " app_version={:?} secure_boot={} app_digest={} tee_digest={}",
                c.app.ver,
                secure_boot(c),
                short(&c.app.calc_digest),
                short(&c.tee.calc_digest)
            )?;
        }
        Ok(())
    }
}

/// A digest's first 8 characters, escaped: the device, not this server, wrote it.
fn short(digest: &str) -> String {
    digest.chars().take(8).collect::<String>().escape_debug().to_string()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::{engine::general_purpose::STANDARD, Engine};
    use esp_attest::hmac::{evidence_json, sign};
    use esp_attest::tee_verify::TeePublicKey;
    use esp_attest::testing::{public_key_hex, TestToken};

    use super::*;
    use crate::enrollment::{Device, Devices};

    const SKEW: Duration = Duration::from_secs(60);

    const DEVICE_ID: &str = "a1b2c3d4e5f6";
    const NOW: i64 = 1789200000;
    const SECRET: [u8; 32] = *b"0123456789abcdef0123456789abcdef";
    const NONCE: &str = "deadbeefcafe0001";

    const GOLDEN: &str = include_str!("../../esp-attest/testdata/tee_envelope_golden.json");
    const GOLDEN_DEVICE_ID: &str = "defakto-demo";
    const GOLDEN_NOW: i64 = 1792200000;
    const GOLDEN_NONCE: &str = "0011223344556677";
    /// The XIAO's attestation key, which signed the golden envelope.
    const XIAO_KEY: &str = "02cded7398be59dd931161ccf6ecc7482894f7411e6b5c768f5941e838ce12cdba";

    fn at(secs: i64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    }

    fn secret_only() -> Device {
        Device { secret: Some(SECRET), tee_key: None }
    }

    fn tee_only(key: &str) -> Device {
        Device { secret: None, tee_key: Some(TeePublicKey::parse(key).unwrap()) }
    }

    fn verifier(devices: impl IntoIterator<Item = (&'static str, Device)>) -> Verifier {
        let devices: Devices = devices.into_iter().map(|(id, d)| (id.to_owned(), d)).collect();
        Verifier::new(devices, SKEW)
    }

    fn hmac_verifier() -> Verifier {
        verifier([(DEVICE_ID, secret_only())])
    }

    fn tee_verifier() -> Verifier {
        verifier([(GOLDEN_DEVICE_ID, tee_only(XIAO_KEY))])
    }

    fn hmac_evidence(device_id: &str, ts: i64, secret: &[u8]) -> String {
        signed_with_nonce(device_id, ts, NONCE, secret)
    }

    fn signed_with_nonce(device_id: &str, ts: i64, nonce: &str, secret: &[u8]) -> String {
        evidence_json(device_id, ts, nonce, &sign(device_id, ts, nonce, secret))
    }

    fn genuine() -> String {
        hmac_evidence(DEVICE_ID, NOW, &SECRET)
    }

    fn response(pairs: &[(&str, &str)]) -> Response {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn rejection(reason: &str) -> Response {
        response(&[("error", reason)])
    }

    #[test]
    fn accepts_genuine_evidence() {
        let (got, decision) = hmac_verifier().attest(&genuine(), at(NOW));

        assert_eq!(got, response(&[("anchor", "nvs_secret"), ("device_id", DEVICE_ID)]));
        assert_eq!(decision.outcome, Outcome::Accepted);
        assert_eq!(decision.anchor, Some(Anchor::Hmac));
        assert_eq!(decision.device_id.as_deref(), Some(DEVICE_ID));
    }

    // Defakto documents payload as base64 but sends it verbatim; accept both so a fix on their
    // side does not break us.
    #[test]
    fn accepts_base64_payload() {
        let (got, _) = hmac_verifier().attest(&STANDARD.encode(genuine()), at(NOW));

        assert_eq!(got.get("device_id").map(String::as_str), Some(DEVICE_ID));
    }

    #[test]
    fn accepts_base64_payload_with_newlines() {
        let encoded = STANDARD.encode(genuine());
        let wrapped: Vec<&str> = encoded.as_bytes().chunks(20).map(|c| std::str::from_utf8(c).unwrap()).collect();

        let (got, _) = hmac_verifier().attest(&wrapped.join("\r\n"), at(NOW));

        assert_eq!(got.get("device_id").map(String::as_str), Some(DEVICE_ID));
    }

    #[test]
    fn rejects_unknown_device() {
        let (got, decision) = hmac_verifier().attest(&hmac_evidence("ffffffffffff", NOW, &SECRET), at(NOW));

        assert_eq!(got, rejection(REJECT_INVALID));
        assert_eq!(decision.outcome, Outcome::Rejected);
        assert_eq!(decision.device_id.as_deref(), Some("ffffffffffff"));
    }

    #[test]
    fn rejects_bad_mac() {
        let evidence = hmac_evidence(DEVICE_ID, NOW, b"wrong-secret-wrong-secret-wrong!");

        let (got, decision) = hmac_verifier().attest(&evidence, at(NOW));

        assert_eq!(got, rejection(REJECT_INVALID));
        assert_eq!(decision.reason.as_deref(), Some("signature mismatch"));
    }

    // Enumeration oracle: an unknown device and a bad signature must be indistinguishable to an
    // unauthenticated caller.
    #[test]
    fn rejection_does_not_reveal_enrollment() {
        let (unknown, _) = hmac_verifier().attest(&hmac_evidence("ffffffffffff", NOW, &SECRET), at(NOW));
        let (bad_mac, _) =
            hmac_verifier().attest(&hmac_evidence(DEVICE_ID, NOW, b"wrong-secret-wrong-secret-wrong!"), at(NOW));

        assert_eq!(unknown, bad_mac);
    }

    #[test]
    fn rejects_timestamp_outside_skew() {
        for ts in [NOW - 61, NOW + 61] {
            let (got, decision) = hmac_verifier().attest(&hmac_evidence(DEVICE_ID, ts, &SECRET), at(NOW));

            assert_eq!(got, rejection(REJECT_STALE), "ts {ts}");
            assert_eq!(decision.outcome, Outcome::Rejected);
        }
    }

    #[test]
    fn accepts_timestamp_inside_skew() {
        let (got, _) = hmac_verifier().attest(&hmac_evidence(DEVICE_ID, NOW - 59, &SECRET), at(NOW));

        assert!(!got.contains_key("error"), "{got:?}");
    }

    #[test]
    fn accepts_timestamp_at_skew() {
        let (got, _) = hmac_verifier().attest(&hmac_evidence(DEVICE_ID, NOW - 60, &SECRET), at(NOW));

        assert!(!got.contains_key("error"), "{got:?}");
    }

    #[test]
    fn skew_compares_at_full_precision() {
        let now = at(NOW) + Duration::from_millis(500);

        let (inside, _) = hmac_verifier().attest(&hmac_evidence(DEVICE_ID, NOW - 59, &SECRET), now);
        let (outside, _) = hmac_verifier().attest(&hmac_evidence(DEVICE_ID, NOW - 60, &SECRET), now);

        assert!(!inside.contains_key("error"), "{inside:?}");
        assert_eq!(outside, rejection(REJECT_STALE));
    }

    // The server retries 5xx, so a repeat of the same nonce must replay the original result
    // rather than reject it as a replay.
    #[test]
    fn repeated_nonce_replays_original_result() {
        let v = hmac_verifier();

        let (first, first_decision) = v.attest(&genuine(), at(NOW));
        let (second, second_decision) = v.attest(&genuine(), at(NOW));

        assert_eq!(first, second);
        assert!(!second.contains_key("error"));
        assert_eq!(first_decision.outcome, Outcome::Accepted);
        assert_eq!(second_decision.outcome, Outcome::Replayed);
    }

    #[test]
    fn rejects_malformed_payload() {
        let (got, decision) = hmac_verifier().attest("not json at all", at(NOW));

        assert_eq!(got, rejection(REJECT_INVALID));
        assert_eq!(decision.outcome, Outcome::Rejected);
        assert_eq!(decision.device_id, None);
    }

    #[test]
    fn golden_tee_envelope_verifies() {
        let (got, decision) = tee_verifier().attest(GOLDEN, at(GOLDEN_NOW));

        assert_eq!(
            got,
            response(&[
                ("device_id", GOLDEN_DEVICE_ID),
                ("anchor", "tee"),
                ("app_version", "0.1.0"),
                ("app_digest", "d97d0bc6391637f6097a89294b4a7a0908a9f0036cd5d423e160862953c1df9d"),
                ("app_secure_version", "0"),
                ("tee_version", "1.0.0"),
                ("tee_digest", "ac91a50042bd5df20c229d5f2cdf95c80a1ad59296fb2c777896a2e615235d66"),
                ("bootloader_digest", "8415ba134050d3a0aaf53f457579a3052edf886945dbe685bd7261006a145501"),
                ("idf_version", "5.5.5"),
                ("secure_boot", "false"),
            ])
        );
        assert_eq!(decision.outcome, Outcome::Accepted);
        assert_eq!(decision.anchor, Some(Anchor::Tee));
        assert_eq!(decision.tee.map(|c| c.app.ver), Some("0.1.0".to_owned()));
    }

    #[test]
    fn tee_rejects_tampered_eat_byte() {
        let tampered = GOLDEN.replacen(r#""ver":"0.1.0""#, r#""ver":"0.2.0""#, 1);
        assert_ne!(tampered, GOLDEN);

        let (got, _) = tee_verifier().attest(&tampered, at(GOLDEN_NOW));

        assert_eq!(got, rejection(REJECT_INVALID));
    }

    #[test]
    fn tee_rejects_key_other_than_enrolled() {
        let waveshare = "036d2a12ffea1b016cb7a230e821bdecd29d8bc4efad92fcc0e335df5e215bb350";
        let v = verifier([(GOLDEN_DEVICE_ID, tee_only(waveshare))]);

        let (got, _) = v.attest(GOLDEN, at(GOLDEN_NOW));

        assert_eq!(got, rejection(REJECT_INVALID));
    }

    #[test]
    fn tee_rejects_stale() {
        for now in [GOLDEN_NOW + 61, GOLDEN_NOW - 61] {
            let (got, _) = tee_verifier().attest(GOLDEN, at(now));

            assert_eq!(got, rejection(REJECT_STALE), "now {now}");
        }
    }

    // ts and nonce sit outside the signed token, bound to it only through eat.nonce.
    #[test]
    fn tee_rejects_envelope_fields_not_bound_to_token() {
        for (from, to) in [
            (r#""nonce":"0011223344556677""#, r#""nonce":"0011223344556678""#),
            (r#""ts":1792200000"#, r#""ts":1792200001"#),
            (r#""device_id":"defakto-demo""#, r#""device_id":"defakto-demo2""#),
        ] {
            let v = verifier([(GOLDEN_DEVICE_ID, tee_only(XIAO_KEY)), ("defakto-demo2", tee_only(XIAO_KEY))]);
            let swapped = GOLDEN.replacen(from, to, 1);
            assert_ne!(swapped, GOLDEN);

            let (got, _) = v.attest(&swapped, at(GOLDEN_NOW));

            assert_eq!(got, rejection(REJECT_INVALID), "swapped {from}");
        }
    }

    #[test]
    fn tee_repeated_envelope_replays() {
        let v = tee_verifier();

        let (first, _) = v.attest(GOLDEN, at(GOLDEN_NOW));
        let (second, decision) = v.attest(GOLDEN, at(GOLDEN_NOW));

        assert!(!first.contains_key("error"), "{first:?}");
        assert_eq!(first, second);
        assert_eq!(decision.outcome, Outcome::Replayed);
    }

    // A cached nonce must not let a forged token through on its coattails.
    #[test]
    fn tee_replay_with_tampered_token_is_rejected() {
        let v = tee_verifier();
        assert!(!v.attest(GOLDEN, at(GOLDEN_NOW)).0.contains_key("error"));

        let tampered = GOLDEN.replacen(r#""ver":"0.1.0""#, r#""ver":"0.2.0""#, 1);
        let (got, _) = v.attest(&tampered, at(GOLDEN_NOW));

        assert_eq!(got, rejection(REJECT_INVALID));
    }

    #[test]
    fn tee_rejects_unenrolled_and_secret_only_device() {
        let unenrolled = verifier([("someone-else", tee_only(XIAO_KEY))]);
        let secret_only = verifier([(GOLDEN_DEVICE_ID, secret_only())]);
        for v in [unenrolled, secret_only] {
            let (got, decision) = v.attest(GOLDEN, at(GOLDEN_NOW));

            assert_eq!(got, rejection(REJECT_INVALID));
            assert_eq!(decision.anchor, Some(Anchor::Tee));
        }
    }

    #[test]
    fn tee_rejects_unknown_format() {
        let envelope = GOLDEN.replacen(r#""format":"esp-tee-eat/1""#, r#""format":"esp-tee-eat/2""#, 1);
        assert_ne!(envelope, GOLDEN);

        let (got, _) = tee_verifier().attest(&envelope, at(GOLDEN_NOW));

        assert_eq!(got, rejection(REJECT_INVALID));
    }

    #[test]
    fn tee_accepts_self_signed_token() {
        let v = verifier([(GOLDEN_DEVICE_ID, tee_only(&public_key_hex(1)))]);

        let (got, _) = v.attest(&TestToken::new(1).envelope(), at(GOLDEN_NOW));

        assert_eq!(got.get("anchor").map(String::as_str), Some("tee"));
        assert_eq!(got.get("secure_boot").map(String::as_str), Some("false"));
    }

    #[test]
    fn secure_boot_requires_all_three_images_verified() {
        let v = verifier([(GOLDEN_DEVICE_ID, tee_only(&public_key_hex(1)))]);
        let image = |verified: bool| format!(r#"{{"part_digest":{{"sign_verified":{verified}}}}}"#);
        let claims =
            |app: bool| format!(r#"{{"tee":{},"app":{},"bootloader":{}}}"#, image(true), image(app), image(true));

        let mut tok = TestToken::new(1);
        tok.sw_claims = Some(claims(true));
        let (all, _) = v.attest(&tok.envelope(), at(GOLDEN_NOW));
        tok.sw_claims = Some(claims(false));
        tok.nonce = "0011223344556678".into();
        let (one_missing, _) = v.attest(&tok.envelope(), at(GOLDEN_NOW));

        assert_eq!(all.get("secure_boot").map(String::as_str), Some("true"));
        assert_eq!(one_missing.get("secure_boot").map(String::as_str), Some("false"));
    }

    // An empty secret is a valid HMAC key, so a TEE-only device must not fall through to HMAC
    // verification with one.
    #[test]
    fn hmac_rejected_for_device_without_secret() {
        let v = verifier([(DEVICE_ID, tee_only(XIAO_KEY))]);

        let (got, _) = v.attest(&hmac_evidence(DEVICE_ID, NOW, &[]), at(NOW));

        assert_eq!(got, rejection(REJECT_INVALID));
    }

    // HMAC and TEE share the replay cache, so an HMAC request reusing a TEE envelope's nonce must
    // not be served the TEE's attributes.
    #[test]
    fn hmac_reusing_tee_nonce_does_not_get_tee_attributes() {
        let both = Device { secret: Some(SECRET), tee_key: Some(TeePublicKey::parse(XIAO_KEY).unwrap()) };
        let v = verifier([(GOLDEN_DEVICE_ID, both)]);
        assert_eq!(v.attest(GOLDEN, at(GOLDEN_NOW)).0.get("anchor").map(String::as_str), Some("tee"));

        let evidence = signed_with_nonce(GOLDEN_DEVICE_ID, GOLDEN_NOW, GOLDEN_NONCE, &SECRET);
        let (got, decision) = v.attest(&evidence, at(GOLDEN_NOW));

        assert_eq!(got, response(&[("device_id", GOLDEN_DEVICE_ID), ("anchor", "nvs_secret")]));
        assert_eq!(decision.outcome, Outcome::Accepted);
    }

    #[test]
    fn extreme_timestamps_are_stale() {
        for ts in [i64::MIN, i64::MAX] {
            let (got, _) = hmac_verifier().attest(&hmac_evidence(DEVICE_ID, ts, &SECRET), at(NOW));
            assert_eq!(got, rejection(REJECT_STALE), "HMAC ts {ts}");

            let mut tok = TestToken::new(1);
            tok.ts = ts;
            let v = verifier([(GOLDEN_DEVICE_ID, tee_only(&public_key_hex(1)))]);
            let (got, _) = v.attest(&tok.envelope(), at(GOLDEN_NOW));
            assert_eq!(got, rejection(REJECT_STALE), "TEE ts {ts}");
        }
    }

    #[test]
    fn set_devices_takes_effect() {
        let v = hmac_verifier();
        let newcomer = hmac_evidence("0a0b0c0d0e0f", NOW, &SECRET);
        assert_eq!(v.attest(&newcomer, at(NOW)).0, rejection(REJECT_INVALID));
        assert_eq!(v.attest(&genuine(), at(NOW)).1.outcome, Outcome::Accepted);

        v.set_devices([(DEVICE_ID.to_owned(), secret_only()), ("0a0b0c0d0e0f".to_owned(), secret_only())].into());

        let (got, _) = v.attest(&newcomer, at(NOW));
        assert_eq!(got.get("device_id").map(String::as_str), Some("0a0b0c0d0e0f"));
        assert_eq!(v.attest(&genuine(), at(NOW)).1.outcome, Outcome::Replayed);
    }

    // Pruning can't be seen through attest: an entry older than 2 x skew is for evidence that
    // is stale anyway.
    #[test]
    fn replay_cache_prunes_entries_older_than_twice_skew_on_insert() {
        let v = hmac_verifier();
        v.attest(&genuine(), at(NOW));
        v.attest(&signed_with_nonce(DEVICE_ID, NOW + 1, "0000000000000001", &SECRET), at(NOW + 1));
        assert_eq!(v.cached(), 2);

        let later = NOW + 121;
        v.attest(&signed_with_nonce(DEVICE_ID, later, "0000000000000002", &SECRET), at(later));

        assert_eq!(v.cached(), 2, "only the first entry is over 2 x skew old");
        v.attest(&hmac_evidence(DEVICE_ID, NOW, b"wrong-secret-wrong-secret-wrong!"), at(NOW + 500));
        assert_eq!(v.cached(), 2, "rejections neither insert nor prune");
    }

    #[test]
    fn decision_log_escapes_caller_strings() {
        let device_id = "x\ny\"";
        let evidence = serde_json::json!({"device_id": device_id, "ts": NOW, "nonce": NONCE, "mac": "00"}).to_string();

        let (_, decision) = hmac_verifier().attest(&evidence, at(NOW));
        let line = decision.to_string();

        assert!(!line.contains('\n'), "{line}");
        assert!(line.contains(r#"device_id="x\ny\"""#), "{line}");
    }

    #[test]
    fn decision_log_for_rejected_hmac() {
        let evidence = hmac_evidence(DEVICE_ID, NOW, b"wrong-secret-wrong-secret-wrong!");

        let (_, decision) = hmac_verifier().attest(&evidence, at(NOW));

        assert_eq!(
            decision.to_string(),
            r#"attest device_id="a1b2c3d4e5f6" anchor=hmac outcome=rejected reason="signature mismatch""#
        );
    }

    #[test]
    fn decision_log_for_accepted_tee() {
        let (_, decision) = tee_verifier().attest(GOLDEN, at(GOLDEN_NOW));
        let line = decision.to_string();

        assert_eq!(
            line,
            r#"attest device_id="defakto-demo" anchor=tee outcome=accepted app_version="0.1.0" secure_boot=false app_digest=d97d0bc6 tee_digest=ac91a500"#
        );
    }

    #[test]
    fn decision_log_never_includes_macs_or_signatures() {
        let evidence = genuine();
        let mac: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        let (_, hmac) = hmac_verifier().attest(&evidence, at(NOW));
        let (_, tee) = tee_verifier().attest(GOLDEN, at(GOLDEN_NOW));
        let sign: serde_json::Value = serde_json::from_str(GOLDEN).unwrap();

        assert!(!hmac.to_string().contains(mac["mac"].as_str().unwrap()));
        assert!(!tee.to_string().contains(sign["token"]["sign"]["r"].as_str().unwrap()));
    }
}
