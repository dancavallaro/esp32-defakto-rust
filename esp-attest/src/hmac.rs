//! HMAC evidence: a MAC over `device_id|ts|nonce`, sent as a small JSON object.

use ::hmac::{Hmac, Mac};
use sha2::Sha256;


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

/// The device's MAC over the signing string.
pub fn sign(device_id: &str, ts: i64, nonce: &str, secret: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(signing_string(device_id, ts, nonce).as_bytes());
    mac.finalize().into_bytes().into()
}

/// HMAC evidence as received, before its MAC is checked.
#[cfg(feature = "verify")]
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct HmacEvidence {
    pub device_id: String,
    pub ts: i64,
    pub nonce: String,
    pub mac: String,
}

#[cfg(feature = "verify")]
impl HmacEvidence {
    /// Accepts the MAC in either hex case; the comparison is constant-time.
    pub fn verify(&self, secret: &[u8]) -> bool {
        let Ok(mac) = hex::decode(&self.mac) else { return false };
        let mut hmac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC takes any key length");
        hmac.update(signing_string(&self.device_id, self.ts, &self.nonce).as_bytes());
        hmac.verify_slice(&mac).is_ok()
    }
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
    fn sign_matches_golden() {
        let secret: Vec<u8> = (0u8..32).collect();
        let mac = sign("defakto-demo", 1792200000, "0011223344556677", &secret);
        assert_eq!(
            evidence_json("defakto-demo", 1792200000, "0011223344556677", &mac),
            r#"{"device_id":"defakto-demo","ts":1792200000,"nonce":"0011223344556677","mac":"b8eead1bcca6bc6368900c976dab032c0a7f8b8ac1427667e337904cf7a6c033"}"#
        );
    }

    const DEVICE: &str = "a1b2c3d4e5f6";
    const TS: i64 = 1789200000;
    const NONCE: &str = "deadbeefcafe0001";
    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn sign_is_deterministic_and_key_dependent() {
        let mac = sign(DEVICE, TS, NONCE, SECRET);
        assert_eq!(mac, sign(DEVICE, TS, NONCE, SECRET));
        assert_ne!(mac, sign(DEVICE, TS, NONCE, b"wrong-secret-wrong-secret-wrong!"));
    }

    #[test]
    fn sign_covers_every_field() {
        let mac = sign(DEVICE, TS, NONCE, SECRET);
        assert_ne!(mac, sign("a1b2c3d4e5f7", TS, NONCE, SECRET));
        assert_ne!(mac, sign(DEVICE, TS + 1, NONCE, SECRET));
        assert_ne!(mac, sign(DEVICE, TS, "deadbeefcafe0002", SECRET));
    }

    #[cfg(feature = "verify")]
    mod verify {
        use super::*;
        use crate::evidence::{parse_evidence, Evidence};

        fn genuine() -> HmacEvidence {
            HmacEvidence {
                device_id: DEVICE.into(),
                ts: TS,
                nonce: NONCE.into(),
                mac: hex::encode(sign(DEVICE, TS, NONCE, SECRET)),
            }
        }

        #[test]
        fn verify_accepts_genuine_evidence() {
            assert!(genuine().verify(SECRET));
        }

        #[test]
        fn verify_rejects_tampered_evidence() {
            type Tamper = (&'static str, fn(&mut HmacEvidence));
            let tampers: [Tamper; 6] = [
                ("device_id", |e| e.device_id = "ffffffffffff".into()),
                ("ts", |e| e.ts += 1),
                ("nonce", |e| e.nonce = "deadbeefcafe0002".into()),
                ("mac", |e| e.mac = format!("{}ff", "0".repeat(62))),
                ("empty mac", |e| e.mac.clear()),
                ("non-hex mac", |e| e.mac = "zz".into()),
            ];
            for (name, tamper) in tampers {
                let mut e = genuine();
                tamper(&mut e);
                assert!(!e.verify(SECRET), "{name} should be rejected");
            }
        }

        #[test]
        fn verify_rejects_wrong_secret() {
            assert!(!genuine().verify(b"wrong-secret-wrong-secret-wrong!"));
        }

        #[test]
        fn verify_accepts_uppercase_mac() {
            let mut e = genuine();
            e.mac = e.mac.to_uppercase();
            assert!(e.verify(SECRET));
        }

        #[test]
        fn verify_rejects_truncated_mac() {
            let mut e = genuine();
            e.mac.truncate(62);
            assert!(!e.verify(SECRET));
        }

        /// Built the way libcommon's `buildEvidenceJson` does, which the fleet's devices send.
        #[test]
        fn libcommon_evidence_verifies() {
            let raw = r#"{"device_id":"defakto-demo","ts":1792200000,"nonce":"0011223344556677","mac":"b8eead1bcca6bc6368900c976dab032c0a7f8b8ac1427667e337904cf7a6c033"}"#;
            let secret: Vec<u8> = (0u8..32).collect();
            match parse_evidence(raw.as_bytes()).unwrap() {
                Evidence::Hmac(e) => assert!(e.verify(&secret)),
            }
        }
    }
}
