//! ESP-TEE evidence for the `esp32-attestor` webhook: the TEE's attestation token,
//! wrapped in an envelope that binds it to the same `device_id|ts|nonce` as HMAC.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::attest::AttestError;
use crate::evidence::signing_string;

pub const TEE_FORMAT: &str = "esp-tee-eat/1";

/// Passed to the TEE as the token's `client_id`; the webhook checks it.
pub const TEE_CLIENT_ID: u32 = 0x0DEFA470;

/// The TEE only takes a 32-bit nonce, so it gets a digest of the HMAC signing string.
pub fn tee_nonce(device_id: &str, ts: i64, nonce: &str) -> u32 {
    let digest = Sha256::digest(signing_string(device_id, ts, nonce));
    u32::from_be_bytes(digest[..4].try_into().unwrap())
}

/// The token goes in verbatim: the TEE's signature covers its exact bytes. Field order
/// matters for the same reason as `evidence_json`.
pub fn tee_envelope(device_id: &str, ts: i64, nonce: &str, token: &[u8]) -> Result<String, AttestError> {
    // The trust domain server mangles anything that isn't 7-bit ASCII on its way to the webhook.
    if !token.is_ascii() {
        return Err(AttestError("TEE token is not ASCII".into()));
    }
    serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(token)
        .map_err(|e| AttestError(format!("TEE token is not a JSON object: {e}")))?;
    let token = std::str::from_utf8(token).expect("ASCII is UTF-8");
    Ok(format!(
        r#"{{"format":"{TEE_FORMAT}","device_id":"{device_id}","ts":{ts},"nonce":"{nonce}","token":{token}}}"#
    ))
}

/// The compressed SEC1 public key the token was signed with, as enrolled with the webhook.
pub fn tee_public_key(token: &[u8]) -> Result<String, AttestError> {
    #[derive(Deserialize)]
    struct Token {
        public_key: PublicKey,
    }
    #[derive(Deserialize)]
    struct PublicKey {
        compressed: String,
    }
    let token: Token =
        serde_json::from_slice(token).map_err(|e| AttestError(format!("TEE token has no public key: {e}")))?;
    Ok(token.public_key.compressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tee_nonce_is_sha256_prefix_of_signing_string() {
        assert_eq!(tee_nonce("defakto-demo", 1792200000, "0011223344556677"), 0x78a5dd58);
    }

    #[test]
    fn envelope_wraps_token_verbatim() {
        let env = tee_envelope("defakto-demo", 1792200000, "0011223344556677", br#"{"a":1}"#).unwrap();
        assert_eq!(
            env,
            r#"{"format":"esp-tee-eat/1","device_id":"defakto-demo","ts":1792200000,"nonce":"0011223344556677","token":{"a":1}}"#
        );
    }

    #[test]
    fn envelope_rejects_non_object_and_non_ascii() {
        assert!(tee_envelope("d", 1, "00", b"not json").is_err());
        assert!(tee_envelope("d", 1, "00", b"[1]").is_err());
        assert!(tee_envelope("d", 1, "00", b"{\"a\":\"\xc3\xa9\"}").is_err());
    }

    /// Captured from the XIAO's TEE with `TeeAttestor::evidence(1792200000, "0011223344556677")`; the
    /// `esp32-attestor` verifier's tests use the same file. If this fails, the format has drifted; don't
    /// recapture it to make the test pass.
    const GOLDEN: &str = include_str!("../testdata/tee_envelope_golden.json");

    #[derive(serde::Deserialize)]
    struct RawToken<'a> {
        #[serde(borrow)]
        header: &'a serde_json::value::RawValue,
        #[serde(borrow)]
        eat: &'a serde_json::value::RawValue,
        #[serde(borrow)]
        public_key: &'a serde_json::value::RawValue,
    }

    #[test]
    fn tee_envelope_golden() {
        let (_, token) = GOLDEN.split_once(r#","token":"#).unwrap();
        let token = token.strip_suffix('}').unwrap();
        let rebuilt = tee_envelope("defakto-demo", 1792200000, "0011223344556677", token.as_bytes()).unwrap();
        assert_eq!(rebuilt, GOLDEN);

        let parsed: serde_json::Value = serde_json::from_str(token).unwrap();
        // The TEE prints both as signed 32-bit integers.
        assert_eq!(parsed["eat"]["nonce"].as_i64().unwrap() as u32, 0x78a5dd58);
        assert_eq!(parsed["eat"]["client_id"].as_i64().unwrap() as u32, TEE_CLIENT_ID);

        // The signature covers the exact bytes of these three objects, in this order.
        let raw: RawToken = serde_json::from_str(token).unwrap();
        let signed = [raw.header.get(), raw.eat.get(), raw.public_key.get()].concat();
        let key = hex::decode(parsed["public_key"]["compressed"].as_str().unwrap()).unwrap();
        let r = hex::decode(parsed["sign"]["r"].as_str().unwrap()).unwrap();
        let s = hex::decode(parsed["sign"]["s"].as_str().unwrap()).unwrap();
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key).unwrap();
        let sig = p256::ecdsa::Signature::from_scalars(
            <[u8; 32]>::try_from(r).unwrap(),
            <[u8; 32]>::try_from(s).unwrap(),
        )
        .unwrap();
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        key.verify_prehash(&Sha256::digest(signed.as_bytes()), &sig).unwrap();
    }

    #[test]
    fn public_key_from_sample_token() {
        let token = include_bytes!("../testdata/tee_token_sample.json");
        assert_eq!(
            tee_public_key(token).unwrap(),
            "021271237805a371e0929ee8ad5b8907060adba2eea8b6692f7856b4b2b36300ee"
        );
    }
}
