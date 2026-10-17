//! HMAC evidence for the `esp32-attestor` webhook. Every format here must stay
//! byte-identical to `telemetry/pkg/espattest`.

/// Mirrors `espattest.ValidDeviceID`, which keeps "|" out of the signing string.
pub fn validate_device_id(id: &str) -> Result<(), String> {
    const MAX_LEN: usize = 64;
    if id.is_empty() {
        return Err("device ID is empty".into());
    }
    if id.len() > MAX_LEN {
        return Err(format!("device ID is {} characters, want at most {MAX_LEN}", id.len()));
    }
    if id == "." || id == ".." {
        return Err(format!("device ID {id:?} is reserved"));
    }
    if !id.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-')) {
        return Err(format!("device ID {id:?} may contain only lowercase letters, digits, and .-_"));
    }
    Ok(())
}

pub fn signing_string(device_id: &str, ts: i64, nonce: &str) -> String {
    format!("{device_id}|{ts}|{nonce}")
}

/// Field order matters: the server compares against Go's `json.Marshal` output.
/// The device ID and nonce need no escaping: `validate_device_id` and hex rule it out.
pub fn evidence_json(device_id: &str, ts: i64, nonce: &str, mac: &[u8; 32]) -> String {
    format!(
        r#"{{"device_id":"{device_id}","ts":{ts},"nonce":"{nonce}","mac":"{}"}}"#,
        hex::encode(mac)
    )
}

/// `fill` supplies 8 random bytes (from the OS on the host, the RNG on the device).
pub fn new_nonce(fill: impl FnOnce(&mut [u8; 8])) -> String {
    let mut bytes = [0u8; 8];
    fill(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_string_matches_espattest() {
        assert_eq!(
            signing_string("defakto-demo", 1792200000, "0011223344556677"),
            "defakto-demo|1792200000|0011223344556677"
        );
    }

    #[test]
    fn nonce_is_16_hex_chars() {
        assert_eq!(new_nonce(|b| *b = [0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3]), "deadbeef00010203");
    }

    #[test]
    fn device_id_rules() {
        assert!(validate_device_id("defakto-demo").is_ok());
        assert!(validate_device_id("a.b_c-1").is_ok());
        for bad in ["", ".", "..", "C6", "a|b", &"a".repeat(65)] {
            assert!(validate_device_id(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
