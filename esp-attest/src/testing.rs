//! Self-signed ESP-TEE tokens, for tests that need checks the golden envelope can't reach
//! without also breaking its signature.

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

use crate::tee::{tee_envelope, tee_nonce, TEE_CLIENT_ID};

/// The fields an ESP-TEE token is built from. `new` makes a genuine one; change a field to break it.
#[derive(Debug, Clone)]
pub struct TestToken {
    pub device_id: String,
    pub ts: i64,
    pub nonce: String,
    pub client_id: u32,
    pub header: String,
    /// `eat.sw_claims` as JSON, or `None` to leave it out.
    pub sw_claims: Option<String>,
    /// The compressed key, in hex, that the token names.
    pub public_key: String,
    /// The seed of the key that signs the token.
    pub signer: u8,
    /// Writes `r` and `s` without leading zeros.
    pub unpadded: bool,
}

impl TestToken {
    /// A token for the golden envelope's device ID, timestamp and nonce, named and signed by
    /// the key seeded with `seed`, which must be non-zero.
    pub fn new(seed: u8) -> Self {
        TestToken {
            device_id: "defakto-demo".into(),
            ts: 1792200000,
            nonce: "0011223344556677".into(),
            client_id: TEE_CLIENT_ID,
            header: r#"{"magic":"44fef7cc","encr_alg":"","sign_alg":"ecdsa_secp256r1_sha256","key_id":"tee_att_key0"}"#
                .into(),
            sw_claims: Some("{}".into()),
            public_key: public_key_hex(seed),
            signer: seed,
            unpadded: false,
        }
    }

    /// The `esp-tee-eat/1` envelope the device would send.
    pub fn envelope(&self) -> String {
        // The TEE prints both as signed 32-bit integers.
        let nonce = tee_nonce(&self.device_id, self.ts, &self.nonce) as i32;
        let client_id = self.client_id as i32;
        let sw_claims = self.sw_claims.as_ref().map(|c| format!(r#","sw_claims":{c}"#)).unwrap_or_default();
        let eat = format!(r#"{{"nonce":{nonce},"client_id":{client_id}{sw_claims}}}"#);
        let public_key = format!(r#"{{"compressed":"{}"}}"#, self.public_key);

        let digest = Sha256::digest([self.header.as_str(), &eat, &public_key].concat());
        let signature: Signature =
            signing_key(self.signer).sign_prehash(&digest).expect("P-256 signs a SHA-256 digest");
        let (r, s) = signature.split_bytes();
        let scalar = |bytes: &[u8]| {
            let digits = hex::encode(bytes);
            if self.unpadded {
                digits.trim_start_matches('0').to_owned()
            } else {
                digits
            }
        };

        let token = format!(
            r#"{{"header":{},"eat":{eat},"public_key":{public_key},"sign":{{"r":"{}","s":"{}"}}}}"#,
            self.header,
            scalar(&r),
            scalar(&s)
        );
        tee_envelope(&self.device_id, self.ts, &self.nonce, token.as_bytes())
            .expect("the token is an ASCII JSON object")
    }
}

/// The compressed public key, in lowercase hex, of the key seeded with `seed`.
pub fn public_key_hex(seed: u8) -> String {
    hex::encode(signing_key(seed).verifying_key().to_encoded_point(true))
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32].into()).expect("a non-zero seed is a valid scalar")
}
