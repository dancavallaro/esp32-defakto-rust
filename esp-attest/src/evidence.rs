//! Parsing the evidence a device sends, whichever format it uses.

use serde::Deserialize;

use crate::hmac::HmacEvidence;
use crate::tee::TEE_FORMAT;
use crate::Error;

#[derive(Debug, Clone, PartialEq)]
pub enum Evidence {
    Hmac(HmacEvidence),
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
        TEE_FORMAT => Err(Error("TEE not yet supported".into())),
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
}
