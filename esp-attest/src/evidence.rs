//! Parsing the evidence a device sends, whichever format it uses.

use serde::Deserialize;

use crate::hmac::HmacEvidence;
use crate::tee::TEE_FORMAT;
use crate::tee_verify::TeeEnvelope;
use crate::Error;

#[derive(Debug, Clone, PartialEq)]
pub enum Evidence {
    Hmac(HmacEvidence),
    Tee(TeeEnvelope),
}

/// Dispatches on `format`: absent or empty is HMAC. Unlike the Go webhook, a missing
/// field is an error rather than a zero value.
pub fn parse_evidence(raw: &[u8]) -> Result<Evidence, Error> {
    #[derive(Deserialize)]
    struct Probe {
        #[serde(default)]
        format: String,
    }
    let probe: Probe = serde_json::from_slice(raw).map_err(|e| Error(format!("evidence is not valid JSON: {e}")))?;
    match probe.format.as_str() {
        "" => serde_json::from_slice(raw)
            .map(Evidence::Hmac)
            .map_err(|e| Error(format!("invalid HMAC evidence: {e}"))),
        TEE_FORMAT => serde_json::from_slice(raw)
            .map(Evidence::Tee)
            .map_err(|e| Error(format!("invalid TEE envelope: {e}"))),
        other => Err(Error(format!("unknown evidence format {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_on_format() {
        let hmac = |format: &str| {
            format!(r#"{{{format}"device_id":"d","ts":1,"nonce":"00","mac":"00"}}"#)
        };
        assert!(matches!(parse_evidence(hmac("").as_bytes()), Ok(Evidence::Hmac(_))));
        assert!(matches!(parse_evidence(hmac(r#""format":"","#).as_bytes()), Ok(Evidence::Hmac(_))));
        assert!(parse_evidence(hmac(r#""format":"esp-tee-eat/2","#).as_bytes()).is_err());
        assert!(parse_evidence(b"not json").is_err());
        assert!(parse_evidence(br#"{"device_id":"d","ts":1,"mac":"00"}"#).is_err());
    }

    /// The deliberate differences from the Go verifier that the README lists.
    #[test]
    fn stricter_than_go() {
        let golden = include_str!("../testdata/tee_envelope_golden.json");
        assert!(matches!(parse_evidence(golden.as_bytes()), Ok(Evidence::Tee(_))));

        let hmac = r#"{"device_id":"d","ts":1,"nonce":"00","mac":"00"}"#;
        assert!(parse_evidence(hmac.as_bytes()).is_ok());
        assert!(parse_evidence(format!("{hmac} x").as_bytes()).is_err(), "trailing bytes, as in Go");
        let bad_utf8 = |from: &str, to: &[u8]| {
            let (before, after) = golden.split_once(from).unwrap();
            [before.as_bytes(), to, after.as_bytes()].concat()
        };
        for (name, raw) in [
            ("uppercase key", hmac.replace("device_id", "Device_ID").into_bytes()),
            ("repeated key", hmac.replace(r#""mac":"00""#, r#""mac":"00","mac":"01""#).into_bytes()),
            ("missing token field", golden.replacen(r#""public_key":"#, r#""publickey":"#, 1).into_bytes()),
            ("invalid UTF-8 in a field", bad_utf8("defakto-demo", b"defakto-\xff")),
            ("invalid UTF-8 in a signed object", bad_utf8(r#""chip_id":13"#, b"\"chip_id\":\"\xff\"")),
        ] {
            assert!(parse_evidence(&raw).is_err(), "{name} should be rejected");
        }
    }
}
