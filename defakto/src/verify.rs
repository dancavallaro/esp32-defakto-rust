//! Verifying JWT-SVIDs against a trust domain's signing keys, found through
//! its OIDC discovery document. RS256 only, which is what Defakto signs with.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;

use crate::http::{HttpClient, HttpError};

/// Tolerated clock skew, since the device's clock comes from SNTP.
const LEEWAY: i64 = 60;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum VerifyError {
    #[error("network: {0}")]
    Http(#[from] HttpError),
    #[error("{url}: HTTP {status}")]
    Status { url: String, status: u16 },
    #[error("{0} isn't valid JSON")]
    BadDocument(String),
    #[error("malformed token")]
    Malformed,
    #[error("unsupported algorithm {0}")]
    Algorithm(String),
    #[error("unknown signing key {0:?}")]
    UnknownKey(Option<String>),
    #[error("bad signature")]
    Signature,
    #[error("issued by {0}")]
    Issuer(String),
    #[error("not for {0}")]
    Audience(String),
    #[error("expired")]
    Expired,
    #[error("not valid yet")]
    NotYetValid,
    #[error("token missing {0}")]
    Missing(&'static str),
}

/// A trust domain's RSA signing keys, by key ID. Keys of other types, or
/// without an ID, are skipped.
#[derive(Debug, Clone, Default)]
pub struct Jwks(Vec<(String, RsaPublicKey)>);

impl Jwks {
    pub fn parse(json: &[u8]) -> Result<Self, VerifyError> {
        #[derive(Deserialize)]
        struct Set {
            keys: Vec<Jwk>,
        }
        #[derive(Deserialize)]
        struct Jwk {
            kty: String,
            kid: Option<String>,
            n: Option<String>,
            e: Option<String>,
        }
        let set: Set = serde_json::from_slice(json).map_err(|_| VerifyError::BadDocument("JWKS".into()))?;
        let int = |b64: &str| URL_SAFE_NO_PAD.decode(b64).ok().map(|b| BigUint::from_bytes_be(&b));
        let keys = set
            .keys
            .into_iter()
            .filter(|k| k.kty == "RSA")
            .filter_map(|k| Some((k.kid?, RsaPublicKey::new(int(&k.n?)?, int(&k.e?)?).ok()?)))
            .collect();
        Ok(Self(keys))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn get(&self, kid: &str) -> Option<&RsaPublicKey> {
        self.0.iter().find(|(id, _)| id == kid).map(|(_, key)| key)
    }
}

/// Fetches `issuer`'s keys from the `jwks_uri` its discovery document names.
pub fn fetch_jwks(http: &mut impl HttpClient, issuer: &str) -> Result<Jwks, VerifyError> {
    #[derive(Deserialize)]
    struct Discovery {
        jwks_uri: String,
    }
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let doc: Discovery =
        serde_json::from_slice(&get(http, &url)?).map_err(|_| VerifyError::BadDocument("discovery".into()))?;
    Jwks::parse(&get(http, &doc.jwks_uri)?)
}

fn get(http: &mut impl HttpClient, url: &str) -> Result<Vec<u8>, VerifyError> {
    let resp = http.get(url)?;
    if resp.status != 200 {
        return Err(VerifyError::Status { url: url.into(), status: resp.status });
    }
    Ok(resp.body)
}

/// What a token must match.
pub struct Expected<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    /// Unix seconds.
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verified {
    /// The SPIFFE ID the token was issued to.
    pub subject: String,
    pub claims: Value,
}

pub fn verify_jwt_svid(token: &str, keys: &Jwks, expected: &Expected) -> Result<Verified, VerifyError> {
    #[derive(Deserialize)]
    struct Header {
        alg: String,
        kid: Option<String>,
    }
    let (signed, signature) = token.rsplit_once('.').ok_or(VerifyError::Malformed)?;
    let (header, payload) = signed.split_once('.').ok_or(VerifyError::Malformed)?;
    let decode = |part: &str| URL_SAFE_NO_PAD.decode(part).map_err(|_| VerifyError::Malformed);
    let header: Header = serde_json::from_slice(&decode(header)?).map_err(|_| VerifyError::Malformed)?;
    if header.alg != "RS256" {
        return Err(VerifyError::Algorithm(header.alg));
    }
    let key = header.kid.as_deref().and_then(|kid| keys.get(kid)).ok_or(VerifyError::UnknownKey(header.kid))?;
    let signature = Signature::try_from(decode(signature)?.as_slice()).map_err(|_| VerifyError::Signature)?;
    VerifyingKey::<Sha256>::new(key.clone())
        .verify(signed.as_bytes(), &signature)
        .map_err(|_| VerifyError::Signature)?;

    let claims: Value = serde_json::from_slice(&decode(payload)?).map_err(|_| VerifyError::Malformed)?;
    let text = |name| claims.get(name).and_then(Value::as_str);
    let number = |name| claims.get(name).and_then(Value::as_i64);
    let issuer = text("iss").ok_or(VerifyError::Missing("iss"))?;
    if issuer != expected.issuer {
        return Err(VerifyError::Issuer(issuer.into()));
    }
    let for_us = match claims.get("aud") {
        Some(Value::String(aud)) => aud == expected.audience,
        Some(Value::Array(auds)) => auds.iter().any(|a| a.as_str() == Some(expected.audience)),
        _ => false,
    };
    if !for_us {
        return Err(VerifyError::Audience(expected.audience.into()));
    }
    if number("exp").ok_or(VerifyError::Missing("exp"))? + LEEWAY <= expected.now {
        return Err(VerifyError::Expired);
    }
    if number("nbf").is_some_and(|nbf| nbf - LEEWAY > expected.now) {
        return Err(VerifyError::NotYetValid);
    }
    let subject = text("sub").ok_or(VerifyError::Missing("sub"))?.to_owned();
    Ok(Verified { subject, claims })
}

#[cfg(test)]
mod tests {
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;
    use serde_json::json;

    use super::*;
    use crate::testing::FakeHttp;

    const ISSUER: &str = "https://td.example/t-1";
    const NOW: i64 = 1_800_000_000;

    fn keys() -> Jwks {
        Jwks::parse(include_bytes!("../testdata/jwks.json")).unwrap()
    }

    fn sign(header: &Value, claims: &Value) -> String {
        let key = RsaPrivateKey::from_pkcs8_pem(include_str!("../testdata/test_key.pem")).unwrap();
        let enc = |v: &Value| URL_SAFE_NO_PAD.encode(v.to_string());
        let signed = format!("{}.{}", enc(header), enc(claims));
        let signature = SigningKey::<Sha256>::new(key).sign(signed.as_bytes());
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    fn claims() -> Value {
        json!({"iss": ISSUER, "aud": "defakto-demo", "sub": "spiffe://td/users/alice", "exp": NOW + 300})
    }

    fn token(claims: &Value) -> String {
        sign(&json!({"alg": "RS256", "kid": "test-key", "typ": "JWT"}), claims)
    }

    fn check(token: &str) -> Result<Verified, VerifyError> {
        verify_jwt_svid(token, &keys(), &Expected { issuer: ISSUER, audience: "defakto-demo", now: NOW })
    }

    #[test]
    fn accepts_a_valid_token() {
        let verified = check(&token(&claims())).unwrap();
        assert_eq!(verified.subject, "spiffe://td/users/alice");
    }

    #[test]
    fn accepts_an_audience_list() {
        let mut c = claims();
        c["aud"] = json!(["other", "defakto-demo"]);
        assert!(check(&token(&c)).is_ok());
    }

    #[test]
    fn refuses_a_tampered_payload() {
        let good = token(&claims());
        let mut c = claims();
        c["sub"] = json!("spiffe://td/users/mallory");
        let forged_payload = URL_SAFE_NO_PAD.encode(c.to_string());
        let parts: Vec<&str> = good.split('.').collect();
        let forged = format!("{}.{forged_payload}.{}", parts[0], parts[2]);
        assert_eq!(check(&forged), Err(VerifyError::Signature));
    }

    #[test]
    fn refuses_wrong_claims() {
        let with = |key: &str, value: Value| {
            let mut c = claims();
            c[key] = value;
            check(&token(&c))
        };
        assert_eq!(with("iss", json!("https://evil")), Err(VerifyError::Issuer("https://evil".into())));
        assert_eq!(with("aud", json!("testing123")), Err(VerifyError::Audience("defakto-demo".into())));
        assert_eq!(with("exp", json!(NOW - 61)), Err(VerifyError::Expired));
        assert!(with("exp", json!(NOW - 59)).is_ok(), "within the leeway");
        assert_eq!(with("nbf", json!(NOW + 120)), Err(VerifyError::NotYetValid));
        let mut c = claims();
        c.as_object_mut().unwrap().remove("sub");
        assert_eq!(check(&token(&c)), Err(VerifyError::Missing("sub")));
    }

    #[test]
    fn refuses_other_algorithms_and_keys() {
        let none = sign(&json!({"alg": "none", "kid": "test-key"}), &claims());
        assert_eq!(check(&none), Err(VerifyError::Algorithm("none".into())));
        let other = sign(&json!({"alg": "RS256", "kid": "rotated"}), &claims());
        assert_eq!(check(&other), Err(VerifyError::UnknownKey(Some("rotated".into()))));
        assert_eq!(check("not.a-token"), Err(VerifyError::Malformed));
    }

    #[test]
    fn fetches_keys_through_discovery() {
        let discovery = json!({"issuer": ISSUER, "jwks_uri": "https://td.example/t-1/jwks"}).to_string();
        let mut http =
            FakeHttp::default().reply(200, discovery).reply(200, include_bytes!("../testdata/jwks.json").to_vec());
        let jwks = fetch_jwks(&mut http, &format!("{ISSUER}/")).unwrap();
        assert_eq!(jwks.len(), 1);
        let urls: Vec<_> = http.requests.iter().map(|r| r.url.as_str()).collect();
        assert_eq!(urls, ["https://td.example/t-1/.well-known/openid-configuration", "https://td.example/t-1/jwks"]);
    }

    #[test]
    fn discovery_failures_say_where() {
        let mut http = FakeHttp::default().reply(404, "");
        assert_eq!(
            fetch_jwks(&mut http, ISSUER).unwrap_err(),
            VerifyError::Status { url: format!("{ISSUER}/.well-known/openid-configuration"), status: 404 }
        );
    }
}
