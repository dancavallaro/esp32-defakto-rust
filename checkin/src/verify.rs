//! Checks a check-in's OBO token: Defakto's signature, who it's for, and that
//! the user and the device acting for them are ones this service accepts.

use std::collections::HashMap;

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The trust domain's signing keys, by key ID.
#[derive(Default)]
pub struct Keys(HashMap<String, DecodingKey>);

impl Keys {
    /// Keys without a key ID are skipped, since tokens pick their key by ID.
    pub fn from_jwks(jwks: &JwkSet) -> Self {
        let keys = jwks
            .keys
            .iter()
            .filter_map(|jwk| Some((jwk.common.key_id.clone()?, DecodingKey::from_jwk(jwk).ok()?)))
            .collect();
        Self(keys)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Attendee {
    pub name: Option<String>,
    pub email: Option<String>,
    pub user_sub: String,
    pub user_iss: String,
    /// The device's SPIFFE ID: the OBO token's actor.
    pub device: String,
    pub txn: Option<String>,
}

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum Rejection {
    #[error("no bearer token")]
    NoToken,
    /// Signed by a key this service hasn't fetched; refreshing the keys may help.
    #[error("unknown signing key {0:?}")]
    UnknownKey(Option<String>),
    #[error("invalid token: {0}")]
    Invalid(String),
    #[error("not an OBO token: no {0}")]
    NotObo(&'static str),
    #[error("device {0} isn't allowed to check people in")]
    DeviceNotAllowed(String),
    #[error("users from {0} can't check in")]
    UserIssuerNotAllowed(String),
}

pub struct Verifier {
    pub issuer: String,
    pub audience: String,
    /// Empty accepts any device.
    pub devices: Vec<String>,
    /// Empty accepts users from any IdP.
    pub user_issuers: Vec<String>,
}

impl Verifier {
    pub fn verify(&self, keys: &Keys, token: &str) -> Result<Attendee, Rejection> {
        let kid = decode_header(token).map_err(|e| Rejection::Invalid(e.to_string()))?.kid;
        let key = kid.as_ref().and_then(|k| keys.0.get(k)).ok_or(Rejection::UnknownKey(kid))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        let claims = decode::<Value>(token, key, &validation).map_err(|e| Rejection::Invalid(e.to_string()))?.claims;

        let attendee = attendee(&claims)?;
        if !self.devices.is_empty() && !self.devices.contains(&attendee.device) {
            return Err(Rejection::DeviceNotAllowed(attendee.device));
        }
        if !self.user_issuers.is_empty() && !self.user_issuers.contains(&attendee.user_iss) {
            return Err(Rejection::UserIssuerNotAllowed(attendee.user_iss));
        }
        Ok(attendee)
    }
}

fn attendee(claims: &Value) -> Result<Attendee, Rejection> {
    let obo = claims.get("obo").ok_or(Rejection::NotObo("obo claim"))?;
    let text = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).map(str::to_owned);
    // Where additionalClaims land isn't documented, so accept either level, as the device does.
    let extra = |key: &str| text(claims, key).or_else(|| text(obo, key));
    Ok(Attendee {
        name: extra("name"),
        email: extra("email"),
        user_sub: text(obo, "sub").ok_or(Rejection::NotObo("obo.sub"))?,
        user_iss: text(obo, "iss").ok_or(Rejection::NotObo("obo.iss"))?,
        device: obo.get("act").and_then(|a| text(a, "sub")).ok_or(Rejection::NotObo("obo.act.sub"))?,
        txn: text(claims, "txn"),
    })
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    use super::*;

    const ISSUER: &str = "https://td.example";
    const DEVICE: &str = "spiffe://example.org/iot/badge-reader";
    const IDP: &str = "https://id.example.com";

    fn keys() -> Keys {
        Keys::from_jwks(&serde_json::from_str(include_str!("../testdata/jwks.json")).unwrap())
    }

    fn verifier() -> Verifier {
        Verifier {
            issuer: ISSUER.into(),
            audience: "checkin".into(),
            devices: vec![DEVICE.into()],
            user_issuers: vec![IDP.into()],
        }
    }

    fn claims() -> Value {
        json!({
            "iss": ISSUER,
            "aud": "checkin",
            "sub": DEVICE,
            "exp": 4_000_000_000u64,
            "txn": "9b2e",
            "name": "Alice Smith",
            "email": "alice@example.com",
            "obo": {"sub": "u-123", "iss": IDP, "act": {"sub": DEVICE}}
        })
    }

    fn sign(claims: &Value, kid: &str) -> String {
        let key = EncodingKey::from_rsa_pem(include_bytes!("../testdata/test_key.pem")).unwrap();
        encode(&Header { kid: Some(kid.into()), ..Header::new(Algorithm::RS256) }, claims, &key).unwrap()
    }

    #[test]
    fn accepts_an_obo_token_from_an_allowed_device() {
        let attendee = verifier().verify(&keys(), &sign(&claims(), "test-key")).unwrap();
        assert_eq!(
            attendee,
            Attendee {
                name: Some("Alice Smith".into()),
                email: Some("alice@example.com".into()),
                user_sub: "u-123".into(),
                user_iss: IDP.into(),
                device: DEVICE.into(),
                txn: Some("9b2e".into()),
            }
        );
    }

    #[test]
    fn rejects_an_unknown_key() {
        let err = verifier().verify(&keys(), &sign(&claims(), "other")).unwrap_err();
        assert_eq!(err, Rejection::UnknownKey(Some("other".into())));
    }

    #[test]
    fn rejects_a_tampered_token() {
        let token = sign(&claims(), "test-key");
        let mut forged = claims();
        forged["obo"]["sub"] = json!("mallory");
        let forged_payload = sign(&forged, "test-key").split('.').nth(1).unwrap().to_owned();
        let parts: Vec<&str> = token.split('.').collect();
        let tampered = format!("{}.{forged_payload}.{}", parts[0], parts[2]);
        assert!(matches!(verifier().verify(&keys(), &tampered), Err(Rejection::Invalid(_))));
    }

    #[test]
    fn rejects_the_wrong_audience_issuer_or_an_expired_token() {
        for (claim, value) in [("aud", json!("someone-else")), ("iss", json!("https://evil.example")), ("exp", json!(1))] {
            let mut c = claims();
            c[claim] = value;
            let result = verifier().verify(&keys(), &sign(&c, "test-key"));
            assert!(matches!(result, Err(Rejection::Invalid(_))), "{claim}: {result:?}");
        }
    }

    #[test]
    fn rejects_a_plain_svid() {
        let mut c = claims();
        c.as_object_mut().unwrap().remove("obo");
        assert_eq!(verifier().verify(&keys(), &sign(&c, "test-key")), Err(Rejection::NotObo("obo claim")));
    }

    #[test]
    fn enforces_the_allow_lists() {
        let mut c = claims();
        c["obo"]["act"]["sub"] = json!("spiffe://example.org/iot/other");
        let err = verifier().verify(&keys(), &sign(&c, "test-key")).unwrap_err();
        assert_eq!(err, Rejection::DeviceNotAllowed("spiffe://example.org/iot/other".into()));

        let mut c = claims();
        c["obo"]["iss"] = json!("https://other-idp.example");
        let err = verifier().verify(&keys(), &sign(&c, "test-key")).unwrap_err();
        assert_eq!(err, Rejection::UserIssuerNotAllowed("https://other-idp.example".into()));
    }

    #[test]
    fn empty_allow_lists_accept_anyone() {
        let open = Verifier { devices: vec![], user_issuers: vec![], ..verifier() };
        let mut c = claims();
        c["obo"]["act"]["sub"] = json!("spiffe://example.org/iot/other");
        assert!(open.verify(&keys(), &sign(&c, "test-key")).is_ok());
    }
}
