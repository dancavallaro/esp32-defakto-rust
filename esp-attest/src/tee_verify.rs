//! Verifying ESP-TEE envelopes.

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

use crate::tee::{tee_nonce, TEE_CLIENT_ID};
use crate::Error;

const SIGN_ALG: &str = "ecdsa_secp256r1_sha256";

/// A device's enrolled TEE attestation key: a compressed SEC1 P-256 point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeePublicKey {
    bytes: [u8; 33],
    key: VerifyingKey,
}

impl TeePublicKey {
    /// Accepts either hex case.
    pub fn parse(hex: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex).map_err(|e| Error(format!("TEE public key is not hex: {e}")))?;
        let bytes: [u8; 33] = bytes
            .try_into()
            .map_err(|b: Vec<u8>| Error(format!("TEE public key is {} bytes, want 33 (compressed P-256)", b.len())))?;
        let key = VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|_| Error("TEE public key is not a compressed P-256 point".into()))?;
        Ok(TeePublicKey { bytes, key })
    }

    /// Lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.bytes
    }
}

/// An `esp-tee-eat/1` envelope as received, before its token is checked.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct TeeEnvelope {
    pub device_id: String,
    pub ts: i64,
    pub nonce: String,
    token: TeeToken,
}

/// The signature covers the exact bytes of `header`, `eat` and `public_key`, so they stay raw
/// until it has been checked.
#[derive(Debug, Clone, PartialEq, Deserialize)]
struct TeeToken {
    #[serde(deserialize_with = "raw_json")]
    header: String,
    #[serde(deserialize_with = "raw_json")]
    eat: String,
    #[serde(deserialize_with = "raw_json")]
    public_key: String,
    sign: Sign,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
struct Sign {
    r: String,
    s: String,
}

fn raw_json<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    Box::<RawValue>::deserialize(deserializer).map(|raw| raw.get().to_owned())
}

/// What the TEE attests about the images it booted.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TeeClaims {
    pub tee: ImageClaims,
    pub app: ImageClaims,
    pub bootloader: ImageClaims,
}

/// Each field is empty, 0 or false when the token leaves it out.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ImageClaims {
    pub ver: String,
    pub idf_ver: String,
    pub secure_ver: i64,
    pub calc_digest: String,
    pub sign_verified: bool,
}

/// The TEE prints `nonce` and `client_id` as signed 32-bit decimals.
#[derive(Deserialize)]
struct Eat {
    nonce: i64,
    client_id: i64,
    #[serde(default)]
    sw_claims: SwClaims,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SwClaims {
    tee: RawImageClaims,
    app: RawImageClaims,
    bootloader: RawImageClaims,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawImageClaims {
    ver: String,
    idf_ver: String,
    secure_ver: i64,
    part_digest: PartDigest,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PartDigest {
    calc_digest: String,
    sign_verified: bool,
}

impl From<RawImageClaims> for ImageClaims {
    fn from(raw: RawImageClaims) -> Self {
        ImageClaims {
            ver: raw.ver,
            idf_ver: raw.idf_ver,
            secure_ver: raw.secure_ver,
            calc_digest: raw.part_digest.calc_digest,
            sign_verified: raw.part_digest.sign_verified,
        }
    }
}

impl TeeEnvelope {
    /// Checks the token against the enrolled key and binds it to this envelope's fields.
    pub fn verify(&self, key: &TeePublicKey) -> Result<TeeClaims, Error> {
        let tok = &self.token;

        #[derive(Deserialize)]
        struct Header {
            sign_alg: String,
        }
        let header: Header = parse(&tok.header, "header")?;
        if header.sign_alg != SIGN_ALG {
            return Err(Error(format!("sign_alg {:?}, want {SIGN_ALG:?}", header.sign_alg)));
        }

        #[derive(Deserialize)]
        struct PublicKey {
            compressed: String,
        }
        let public_key: PublicKey = parse(&tok.public_key, "public_key")?;
        if hex::decode(&public_key.compressed).ok().as_deref() != Some(key.as_bytes().as_slice()) {
            return Err(Error(format!("token key {:?} is not the enrolled key", public_key.compressed)));
        }

        let signature = Signature::from_scalars(scalar(&tok.sign.r)?, scalar(&tok.sign.s)?)
            .map_err(|_| Error("signature r or s is out of range".into()))?;
        let digest = Sha256::digest([tok.header.as_str(), &tok.eat, &tok.public_key].concat());
        key.key.verify_prehash(&digest, &signature).map_err(|_| Error("signature mismatch".into()))?;

        let eat: Eat = parse(&tok.eat, "eat")?;
        let want = tee_nonce(&self.device_id, self.ts, &self.nonce);
        if eat.nonce as u32 != want {
            return Err(Error(format!(
                "eat.nonce {:#010x} is not bound to the envelope (want {want:#010x})",
                eat.nonce as u32
            )));
        }
        if eat.client_id as u32 != TEE_CLIENT_ID {
            return Err(Error(format!("eat.client_id {:#010x}, want {TEE_CLIENT_ID:#010x}", eat.client_id as u32)));
        }
        let sw = eat.sw_claims;
        Ok(TeeClaims { tee: sw.tee.into(), app: sw.app.into(), bootloader: sw.bootloader.into() })
    }
}

fn parse<'a, T: Deserialize<'a>>(raw: &'a str, what: &str) -> Result<T, Error> {
    serde_json::from_str(raw).map_err(|e| Error(format!("parsing {what}: {e}")))
}

/// Unsigned big-endian hex of any length up to 32 bytes, since leading zeros may be missing.
fn scalar(digits: &str) -> Result<[u8; 32], Error> {
    let invalid = || Error(format!("signature scalar {digits:?} is not 1 to 64 hex digits"));
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let significant = digits.trim_start_matches('0');
    if significant.len() > 64 {
        return Err(invalid());
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(format!("{significant:0>64}"), &mut bytes).map_err(|_| invalid())?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{parse_evidence, Evidence};
    use crate::tee::tee_nonce;
    use crate::testing::{public_key_hex, TestToken};

    /// Captured from the XIAO's TEE; see `tee::tests::GOLDEN`.
    const GOLDEN: &str = include_str!("../testdata/tee_envelope_golden.json");
    /// The XIAO's attestation key, which signed the golden envelope.
    const XIAO_KEY: &str = "02cded7398be59dd931161ccf6ecc7482894f7411e6b5c768f5941e838ce12cdba";
    /// The Waveshare's: a genuine key that did not sign the golden.
    const WAVESHARE_KEY: &str = "036d2a12ffea1b016cb7a230e821bdecd29d8bc4efad92fcc0e335df5e215bb350";

    fn key(hex: &str) -> TeePublicKey {
        TeePublicKey::parse(hex).unwrap()
    }

    fn envelope(raw: &str) -> TeeEnvelope {
        match parse_evidence(raw.as_bytes()).unwrap() {
            Evidence::Tee(env) => env,
            other => panic!("parsed as {other:?}"),
        }
    }

    fn verify(raw: &str, hex: &str) -> Result<TeeClaims, Error> {
        envelope(raw).verify(&key(hex))
    }

    fn verify_self_signed(tok: &TestToken) -> Result<TeeClaims, Error> {
        verify(&tok.envelope(), &public_key_hex(1))
    }

    /// The envelope's `sign.r` and `sign.s`.
    fn signature(envelope: &str) -> (String, String) {
        let env: serde_json::Value = serde_json::from_str(envelope).unwrap();
        let scalar = |name: &str| env["token"]["sign"][name].as_str().unwrap().to_owned();
        (scalar("r"), scalar("s"))
    }

    /// Checks the rejection came from the check under test, not an earlier one.
    fn assert_rejected(result: Result<TeeClaims, Error>, reason: &str) {
        match result {
            Err(Error(e)) => assert!(e.contains(reason), "rejected for {e:?}, want {reason:?}"),
            Ok(claims) => panic!("accepted with {claims:?}, want rejection for {reason:?}"),
        }
    }

    #[test]
    fn golden_envelope_verifies() {
        let env = envelope(GOLDEN);
        assert_eq!(
            (env.device_id.as_str(), env.ts, env.nonce.as_str()),
            ("defakto-demo", 1792200000, "0011223344556677")
        );

        let claims = env.verify(&key(XIAO_KEY)).unwrap();
        assert_eq!(
            claims,
            TeeClaims {
                tee: ImageClaims {
                    ver: "1.0.0".into(),
                    idf_ver: "v5.5.5-dirty".into(),
                    secure_ver: 0,
                    calc_digest: "ac91a50042bd5df20c229d5f2cdf95c80a1ad59296fb2c777896a2e615235d66".into(),
                    sign_verified: false,
                },
                app: ImageClaims {
                    ver: "0.1.0".into(),
                    idf_ver: "5.5.5".into(),
                    secure_ver: 0,
                    calc_digest: "d97d0bc6391637f6097a89294b4a7a0908a9f0036cd5d423e160862953c1df9d".into(),
                    sign_verified: false,
                },
                bootloader: ImageClaims {
                    ver: "01000000".into(),
                    idf_ver: "v5.5.5-dirty".into(),
                    secure_ver: 0,
                    calc_digest: "8415ba134050d3a0aaf53f457579a3052edf886945dbe685bd7261006a145501".into(),
                    sign_verified: false,
                },
            }
        );
    }

    #[test]
    fn rejects_tampered_eat_byte() {
        let tampered = GOLDEN.replacen(r#""ver":"0.1.0""#, r#""ver":"0.2.0""#, 1);
        assert_ne!(tampered, GOLDEN);
        assert_rejected(verify(&tampered, XIAO_KEY), "signature mismatch");
    }

    #[test]
    fn rejects_key_other_than_enrolled() {
        assert_rejected(verify(GOLDEN, WAVESHARE_KEY), "not the enrolled key");
    }

    /// ts and nonce sit outside the signed token, bound to it only through eat.nonce.
    #[test]
    fn rejects_envelope_fields_not_bound_to_token() {
        for (from, to) in [
            (r#""nonce":"0011223344556677""#, r#""nonce":"0011223344556678""#),
            (r#""ts":1792200000"#, r#""ts":1792200001"#),
            (r#""device_id":"defakto-demo""#, r#""device_id":"defakto-demo2""#),
        ] {
            let swapped = GOLDEN.replacen(from, to, 1);
            assert_ne!(swapped, GOLDEN);
            assert_rejected(verify(&swapped, XIAO_KEY), "not bound to the envelope");
        }
    }

    /// Keys are case-sensitive, so this one must not override `device_id`.
    #[test]
    fn ignores_key_differing_only_in_case() {
        let env = GOLDEN.replacen(r#""ts":"#, r#""Device_ID":"x","ts":"#, 1);
        assert_ne!(env, GOLDEN);
        assert!(verify(&env, XIAO_KEY).is_ok());
    }

    #[test]
    fn accepts_self_signed_token() {
        assert_eq!(verify_self_signed(&TestToken::new(1)).unwrap(), TeeClaims::default());
    }

    #[test]
    fn rejects_wrong_client_id() {
        let tok = TestToken { client_id: 0x0DEFA471, ..TestToken::new(1) };
        assert_rejected(verify_self_signed(&tok), "eat.client_id 0x0defa471");
    }

    /// A token that names the enrolled key but was signed by another must fail on the
    /// signature, not pass on the key comparison.
    #[test]
    fn rejects_other_signer_claiming_enrolled_key() {
        let tok = TestToken { signer: 2, ..TestToken::new(1) };
        assert_rejected(verify_self_signed(&tok), "signature mismatch");
    }

    #[test]
    fn rejects_token_naming_another_key() {
        let tok = TestToken { public_key: public_key_hex(2), ..TestToken::new(1) };
        assert_rejected(verify_self_signed(&tok), "not the enrolled key");
    }

    #[test]
    fn rejects_wrong_sign_alg() {
        let mut tok = TestToken::new(1);
        tok.header = tok.header.replace("ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384");
        assert_rejected(verify_self_signed(&tok), "sign_alg");
    }

    /// The TEE prints eat.nonce as a signed int32, so half of all nonces are negative.
    #[test]
    fn accepts_negative_eat_nonce() {
        let mut tok = TestToken::new(1);
        for n in 0u64.. {
            if (tee_nonce(&tok.device_id, tok.ts, &tok.nonce) as i32) < 0 {
                break;
            }
            tok.nonce = format!("{n:016x}");
        }
        assert!(tok.envelope().contains(r#""eat":{"nonce":-"#));
        assert!(verify_self_signed(&tok).is_ok());
    }

    /// A signer may drop leading zeros from `r` and `s`.
    #[test]
    fn accepts_unpadded_r_and_s() {
        let mut tok = TestToken { unpadded: true, ..TestToken::new(1) };
        for n in 0u64.. {
            let (r, s) = signature(&tok.envelope());
            if r.len() < 64 || s.len() < 64 {
                break;
            }
            tok.nonce = format!("{n:016x}");
        }
        assert!(verify_self_signed(&tok).is_ok());
    }

    #[test]
    fn accepts_missing_sw_claims() {
        let tok = TestToken { sw_claims: None, ..TestToken::new(1) };
        assert_eq!(verify_self_signed(&tok).unwrap(), TeeClaims::default());

        let tok = TestToken { sw_claims: Some(r#"{"app":{"ver":"2","part_digest":{}}}"#.into()), ..TestToken::new(1) };
        let claims = verify_self_signed(&tok).unwrap();
        assert_eq!(claims.app, ImageClaims { ver: "2".into(), ..ImageClaims::default() });
        assert_eq!((claims.tee, claims.bootloader), (ImageClaims::default(), ImageClaims::default()));
    }

    #[test]
    fn rejects_r_longer_than_64_digits() {
        let env = TestToken::new(1).envelope();
        let zero_padded = env.replacen(r#""r":""#, r#""r":"00"#, 1);
        assert!(verify(&zero_padded, &public_key_hex(1)).is_ok(), "leading zeros don't change r");
        let longer = env.replacen(r#""r":""#, r#""r":"1"#, 1);
        assert_rejected(verify(&longer, &public_key_hex(1)), "1 to 64 hex digits");
    }

    #[test]
    fn rejects_malformed_r_and_s() {
        let env = TestToken::new(1).envelope();
        let (r, _) = signature(&env);
        for bad in ["", "0", "zz", &format!("+{r}"), &format!("{r} ")] {
            let tampered = env.replacen(&r, bad, 1);
            assert!(verify(&tampered, &public_key_hex(1)).is_err(), "r {bad:?} should be rejected");
        }
        let upper = env.replacen(&r, &r.to_uppercase(), 1);
        assert!(verify(&upper, &public_key_hex(1)).is_ok());
    }

    #[test]
    fn tee_public_key_parse() {
        assert_eq!(key(XIAO_KEY).to_hex(), XIAO_KEY);
        assert_eq!(key(&XIAO_KEY.to_uppercase()).as_bytes(), key(XIAO_KEY).as_bytes());
        for bad in ["", "zz", &format!("04{}", "11".repeat(64)), &XIAO_KEY[..64], &format!("02{}", "ff".repeat(32))] {
            assert!(TeePublicKey::parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
