//! Device attestation. Everything downstream sees only `Attestor`, so the HMAC
//! backends here and the TEE token backend can be swapped at runtime.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::evidence::{evidence_json, signing_string};

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

/// A key held in ordinary memory: the host CLI's, and the firmware's NVS fallback.
pub struct SoftwareHmacKey(pub Vec<u8>);

impl HmacKey for SoftwareHmacKey {
    fn hmac_sha256(&self, msg: &[u8]) -> Result<[u8; 32], AttestError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0)
            .map_err(|e| AttestError(e.to_string()))?;
        mac.update(msg);
        Ok(mac.finalize().into_bytes().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // From `esp32-enroll golden c6-demo AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8= 1792200000 0011223344556677`.
    const GOLDEN_EVIDENCE: &str = r#"{"device_id":"c6-demo","ts":1792200000,"nonce":"0011223344556677","mac":"1f5172bf354800a61aacb56fb0e389de1d3db309fb469d350453b2f96e4993f6"}"#;

    #[test]
    fn hmac_attestor_matches_golden() {
        let attestor = HmacAttestor::new(
            "c6-demo".into(),
            SoftwareHmacKey((0u8..32).collect()),
            "software HMAC",
        );
        let ev = attestor.evidence(1792200000, "0011223344556677").unwrap();
        assert_eq!(ev.method_type, "extension");
        assert_eq!(ev.method_version, "1.0");
        assert_eq!(String::from_utf8(ev.payload).unwrap(), GOLDEN_EVIDENCE);
        assert_eq!(attestor.label(), "software HMAC");
    }
}
