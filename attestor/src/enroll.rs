//! The `enroll` subcommands' output: enrollment entries to merge into the enrollment file, and the
//! NVS CSV for a device secret.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use esp_attest::tee_verify::TeePublicKey;

const SECRET_BYTES: usize = 32;

/// A fresh device secret, base64 encoded.
pub fn new_secret() -> String {
    let mut bytes = [0u8; SECRET_BYTES];
    getrandom::getrandom(&mut bytes).expect("the OS random number generator is unavailable");
    STANDARD.encode(bytes)
}

/// The enrollment entry for a device that attests with an HMAC secret.
pub fn hmac_entry(device_id: &str, secret_b64: &str) -> Result<String> {
    esp_attest::validate_device_id(device_id).map_err(|e| anyhow!(e))?;
    entry(device_id, "secret", secret_b64)
}

/// The enrollment entry for a device that attests with a TEE key, as the device's boot log prints it.
pub fn tee_entry(device_id: &str, key_hex: &str) -> Result<String> {
    esp_attest::validate_device_id(device_id).map_err(|e| anyhow!(e))?;
    let key = TeePublicKey::parse(key_hex).map_err(|e| anyhow!(e))?;
    entry(device_id, "tee_pubkey", &key.to_hex())
}

fn entry(device_id: &str, field: &str, value: &str) -> Result<String> {
    let fields = BTreeMap::from([(field, value)]);
    Ok(serde_json::to_string(&BTreeMap::from([(device_id, fields)]))?)
}

/// Only the secret goes to NVS; the firmware takes its device ID from its own configuration.
pub fn nvs_csv(secret_b64: &str) -> String {
    format!("key,type,encoding,value\nspiffe,namespace,,\ndevice_secret,data,base64,{secret_b64}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrollment;
    use base64::{engine::general_purpose::STANDARD, Engine};

    const TEE_KEY: &str = "036d2a12ffea1b016cb7a230e821bdecd29d8bc4efad92fcc0e335df5e215bb350";

    #[test]
    fn new_secret_is_distinct_32_bytes() {
        let (a, b) = (new_secret(), new_secret());
        assert_ne!(a, b);
        assert_eq!(STANDARD.decode(a).unwrap().len(), 32);
    }

    #[test]
    fn hmac_entry_round_trips_through_enrollment_parse() {
        let secret = new_secret();
        let entry = hmac_entry("a1b2c3d4e5f6", &secret).unwrap();
        let devices = enrollment::parse(entry.as_bytes()).unwrap();
        assert_eq!(devices["a1b2c3d4e5f6"].secret.unwrap().to_vec(), STANDARD.decode(&secret).unwrap());
        let json: serde_json::Value = serde_json::from_str(&entry).unwrap();
        let keys: Vec<_> = json["a1b2c3d4e5f6"].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["secret"]);
    }

    #[test]
    fn nvs_csv_carries_only_the_secret() {
        assert_eq!(
            nvs_csv("c2VjcmV0"),
            "key,type,encoding,value\nspiffe,namespace,,\ndevice_secret,data,base64,c2VjcmV0\n"
        );
    }

    #[test]
    fn hmac_rejects_invalid_device_id() {
        assert!(hmac_entry("star|lord", &new_secret()).is_err());
    }

    #[test]
    fn tee_entry_matches_webhook_format() {
        let entry = tee_entry("defakto-demo", TEE_KEY).unwrap();
        assert_eq!(entry, format!(r#"{{"defakto-demo":{{"tee_pubkey":"{TEE_KEY}"}}}}"#));
        assert!(enrollment::parse(entry.as_bytes()).unwrap()["defakto-demo"].tee_key.is_some());
    }

    #[test]
    fn tee_entry_normalises_key_case() {
        let entry = tee_entry("defakto-demo", &TEE_KEY.to_uppercase()).unwrap();
        assert!(entry.contains(TEE_KEY));
    }

    #[test]
    fn tee_rejects_invalid_device_id_or_key() {
        assert!(tee_entry("star|lord", TEE_KEY).is_err());
        assert!(tee_entry("defakto-demo", &format!("04{}", "11".repeat(64))).is_err());
        assert!(tee_entry("defakto-demo", &format!("02{}", "ff".repeat(32))).is_err());
    }
}
