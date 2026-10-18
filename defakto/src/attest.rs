//! Device attestation. Everything downstream sees only `Attestor`, so the HMAC
//! backends here and the TEE token backend can be swapped at runtime.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use esp_attest::hmac::{evidence_json, signing_string};
use esp_attest::tee::{tee_envelope, tee_nonce, without_terminators, TEE_CLIENT_ID};

/// What goes into one `MethodAttestation` of a serverless request.
#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    pub method_type: &'static str,
    pub method_version: &'static str,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("attestation failed: {0}")]
pub struct AttestError(pub String);

impl From<esp_attest::Error> for AttestError {
    fn from(e: esp_attest::Error) -> Self {
        Self(e.0)
    }
}

pub trait Attestor: Send {
    /// Shown on screen, e.g. "eFuse HMAC".
    fn label(&self) -> &str;
    fn evidence(&self, ts: i64, nonce: &str) -> Result<Evidence, AttestError>;
}

/// A 32-byte HMAC-SHA256 key, wherever it lives.
pub trait HmacKey: Send {
    fn hmac_sha256(&self, msg: &[u8]) -> Result<[u8; 32], AttestError>;
}

pub struct HmacAttestor<K: HmacKey> {
    device_id: String,
    key: K,
    label: String,
}

impl<K: HmacKey> HmacAttestor<K> {
    pub fn new(device_id: String, key: K, label: impl Into<String>) -> Self {
        Self { device_id, key, label: label.into() }
    }
}

impl<K: HmacKey> Attestor for HmacAttestor<K> {
    fn label(&self) -> &str {
        &self.label
    }

    fn evidence(&self, ts: i64, nonce: &str) -> Result<Evidence, AttestError> {
        let mac = self.key.hmac_sha256(signing_string(&self.device_id, ts, nonce).as_bytes())?;
        Ok(Evidence {
            method_type: "extension",
            method_version: "1.0",
            payload: evidence_json(&self.device_id, ts, nonce, &mac).into_bytes(),
        })
    }
}

/// A key held in ordinary memory, for the host CLI.
pub struct SoftwareHmacKey(pub Vec<u8>);

impl HmacKey for SoftwareHmacKey {
    fn hmac_sha256(&self, msg: &[u8]) -> Result<[u8; 32], AttestError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0)
            .map_err(|e| AttestError(e.to_string()))?;
        mac.update(msg);
        Ok(mac.finalize().into_bytes().into())
    }
}

/// Produces ESP-TEE attestation tokens; the firmware's implementation calls into the TEE.
pub trait TeeTokenSource: Send {
    fn token(&self, nonce: u32, client_id: u32) -> Result<Vec<u8>, AttestError>;
}

pub struct TeeAttestor<T: TeeTokenSource> {
    device_id: String,
    source: T,
}

impl<T: TeeTokenSource> TeeAttestor<T> {
    pub fn new(device_id: String, source: T) -> Self {
        Self { device_id, source }
    }
}

impl<T: TeeTokenSource> Attestor for TeeAttestor<T> {
    fn label(&self) -> &str {
        "ESP-TEE"
    }

    fn evidence(&self, ts: i64, nonce: &str) -> Result<Evidence, AttestError> {
        let token = self.source.token(tee_nonce(&self.device_id, ts, nonce), TEE_CLIENT_ID)?;
        Ok(Evidence {
            method_type: "extension",
            method_version: "1.0",
            payload: tee_envelope(&self.device_id, ts, nonce, without_terminators(&token))?.into_bytes(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    // From `esp32-enroll golden defakto-demo AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8= 1792200000 0011223344556677`.
    const GOLDEN_EVIDENCE: &str = r#"{"device_id":"defakto-demo","ts":1792200000,"nonce":"0011223344556677","mac":"b8eead1bcca6bc6368900c976dab032c0a7f8b8ac1427667e337904cf7a6c033"}"#;

    #[test]
    fn hmac_attestor_matches_golden() {
        let attestor = HmacAttestor::new(
            "defakto-demo".into(),
            SoftwareHmacKey((0u8..32).collect()),
            "software HMAC",
        );
        let ev = attestor.evidence(1792200000, "0011223344556677").unwrap();
        assert_eq!(ev.method_type, "extension");
        assert_eq!(ev.method_version, "1.0");
        assert_eq!(String::from_utf8(ev.payload).unwrap(), GOLDEN_EVIDENCE);
        assert_eq!(attestor.label(), "software HMAC");
    }

    const SAMPLE_TOKEN: &[u8] = include_bytes!("../../esp-attest/testdata/tee_token_sample.json");

    struct FakeTee {
        calls: Arc<Mutex<Option<(u32, u32)>>>,
        reply: Result<Vec<u8>, AttestError>,
    }

    impl TeeTokenSource for FakeTee {
        fn token(&self, nonce: u32, client_id: u32) -> Result<Vec<u8>, AttestError> {
            *self.calls.lock().unwrap() = Some((nonce, client_id));
            self.reply.clone()
        }
    }

    #[test]
    fn tee_attestor_sends_envelope_with_bound_nonce() {
        let calls = Arc::new(Mutex::new(None));
        let reply = Ok([SAMPLE_TOKEN, b"\0"].concat());
        let attestor = TeeAttestor::new("defakto-demo".into(), FakeTee { calls: calls.clone(), reply });

        let ev = attestor.evidence(1792200000, "0011223344556677").unwrap();

        let want = tee_envelope("defakto-demo", 1792200000, "0011223344556677", SAMPLE_TOKEN).unwrap();
        assert_eq!(String::from_utf8(ev.payload).unwrap(), want);
        assert_eq!(*calls.lock().unwrap(), Some((0x78a5dd58, 0x0DEFA470)));
        assert_eq!(ev.method_type, "extension");
        assert_eq!(ev.method_version, "1.0");
        assert_eq!(attestor.label(), "ESP-TEE");
    }

    #[test]
    fn tee_attestor_propagates_source_error() {
        let err = AttestError("esp_tee_att_generate_token: 259".into());
        let source = FakeTee { calls: Arc::default(), reply: Err(err.clone()) };
        let attestor = TeeAttestor::new("defakto-demo".into(), source);
        assert_eq!(attestor.evidence(1792200000, "0011223344556677"), Err(err));
    }
}
