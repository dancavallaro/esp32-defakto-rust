//! The enrolled devices, parsed from the enrollment JSON, at startup and again whenever the file changes.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use esp_attest::tee_verify::TeePublicKey;
use serde::Deserialize;

const SECRET_BYTES: usize = 32;

/// What a device can attest with. A device may carry both, so it can switch attestors
/// without re-enrolling.
#[derive(Debug, Clone)]
pub struct Device {
    pub secret: Option<[u8; 32]>,
    pub tee_key: Option<TeePublicKey>,
}

pub type Devices = HashMap<String, Device>;

// Unknown fields are ignored on purpose, so enrollment can grow metadata.
#[derive(Deserialize)]
struct Entry {
    secret: Option<String>,
    tee_pubkey: Option<String>,
}

pub fn load(path: &Path) -> Result<Devices> {
    let body = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    parse(&body).with_context(|| format!("loading {}", path.display()))
}

pub fn parse(bytes: &[u8]) -> Result<Devices> {
    let entries: HashMap<String, Entry> = serde_json::from_slice(bytes).context("parsing enrollment")?;
    if entries.is_empty() {
        bail!("enrollment contains no devices");
    }
    entries
        .into_iter()
        .map(|(id, entry)| {
            esp_attest::validate_device_id(&id).map_err(|e| anyhow!(e))?;
            let device = parse_device(entry).with_context(|| format!("enrollment for {id}"))?;
            Ok((id, device))
        })
        .collect()
}

// An empty string counts as absent, as it does in the Go attestor.
fn parse_device(entry: Entry) -> Result<Device> {
    let secret = entry.secret.filter(|s| !s.is_empty());
    let tee_pubkey = entry.tee_pubkey.filter(|s| !s.is_empty());
    if secret.is_none() && tee_pubkey.is_none() {
        bail!("needs a secret, a tee_pubkey, or both");
    }
    let secret = secret
        .map(|s| {
            let bytes = STANDARD.decode(s).context("decoding secret")?;
            <[u8; SECRET_BYTES]>::try_from(bytes.as_slice())
                .map_err(|_| anyhow!("secret is {} bytes, want {SECRET_BYTES} bytes", bytes.len()))
        })
        .transpose()?;
    let tee_key = tee_pubkey
        .map(|k| TeePublicKey::parse(&k).map_err(|e| anyhow!(e)).context("parsing tee_pubkey"))
        .transpose()?;
    Ok(Device { secret, tee_key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    const SECRET: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
    const TEE_KEY: &str = "036d2a12ffea1b016cb7a230e821bdecd29d8bc4efad92fcc0e335df5e215bb350";

    fn secret_b64() -> String {
        STANDARD.encode(SECRET)
    }

    fn err_of(json: &str) -> String {
        format!("{:#}", parse(json.as_bytes()).unwrap_err())
    }

    #[test]
    fn decodes_secrets() {
        let devices = parse(format!(r#"{{"a1b2c3d4e5f6":{{"secret":"{}"}}}}"#, secret_b64()).as_bytes()).unwrap();
        assert_eq!(devices["a1b2c3d4e5f6"].secret, Some(*SECRET));
        assert!(devices["a1b2c3d4e5f6"].tee_key.is_none());
    }

    #[test]
    fn rejects_bad_base64() {
        assert!(err_of(r#"{"a1b2c3d4e5f6":{"secret":"not!base64"}}"#).contains("a1b2c3d4e5f6"));
    }

    #[test]
    fn rejects_short_secret() {
        let short = STANDARD.encode(b"tooshort");
        assert!(err_of(&format!(r#"{{"a1b2c3d4e5f6":{{"secret":"{short}"}}}}"#)).contains("32 bytes"));
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(parse(b"{").is_err());
    }

    #[test]
    fn rejects_empty_map() {
        assert!(err_of("{}").contains("no devices"));
    }

    #[test]
    fn load_rejects_missing_file() {
        let err = load(Path::new("/nonexistent/absent.json")).unwrap_err();
        assert!(format!("{err:#}").contains("absent.json"));
    }

    #[test]
    fn rejects_invalid_device_id() {
        let json = format!(r#"{{"star|lord":{{"secret":"{}"}}}}"#, secret_b64());
        assert!(err_of(&json).contains("star|lord"));
    }

    #[test]
    fn decodes_tee_key_without_secret() {
        let devices = parse(format!(r#"{{"defakto-demo":{{"tee_pubkey":"{TEE_KEY}"}}}}"#).as_bytes()).unwrap();
        let device = &devices["defakto-demo"];
        assert_eq!(device.tee_key.as_ref().unwrap().to_hex(), TEE_KEY);
        assert!(device.secret.is_none());
    }

    #[test]
    fn decodes_secret_and_tee_key() {
        let json = format!(r#"{{"defakto-demo":{{"secret":"{}","tee_pubkey":"{TEE_KEY}"}}}}"#, secret_b64());
        let device = &parse(json.as_bytes()).unwrap()["defakto-demo"];
        assert_eq!(device.secret, Some(*SECRET));
        assert_eq!(device.tee_key.as_ref().unwrap().to_hex(), TEE_KEY);
    }

    #[test]
    fn rejects_entry_with_no_credential() {
        assert!(err_of(r#"{"defakto-demo":{}}"#).contains("defakto-demo"));
    }

    #[test]
    fn rejects_invalid_tee_key() {
        let uncompressed = format!("04{}", "11".repeat(64));
        let off_curve = format!("02{}", "ff".repeat(32));
        for key in ["zz", uncompressed.as_str(), off_curve.as_str()] {
            let err = err_of(&format!(r#"{{"defakto-demo":{{"tee_pubkey":"{key}"}}}}"#));
            assert!(err.contains("defakto-demo"), "{key}: {err}");
        }
    }

    #[test]
    fn ignores_unknown_fields() {
        let json = format!(r#"{{"a1b2c3d4e5f6":{{"secret":"{}","model":"c6"}}}}"#, secret_b64());
        assert!(parse(json.as_bytes()).is_ok());
    }
}
