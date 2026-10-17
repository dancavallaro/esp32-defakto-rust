//! What the result screen shows, read from the OBO token. Its signature isn't
//! checked: it arrives straight from the Trust Domain Server over TLS and is
//! only displayed.

use defakto::jwt::{decode_claims, JwtError};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct DisplayClaims {
    pub greeting: String,
    pub email: Option<String>,
    pub user_sub: String,
    pub user_iss: String,
    pub actor: String,
    pub txn: Option<String>,
    pub exp: i64,
}

impl DisplayClaims {
    pub fn from_obo_jwt(jwt: &str) -> Result<Self, JwtError> {
        let claims = decode_claims(jwt)?;
        let obo = claims.get("obo").ok_or(JwtError::Missing("obo"))?;
        let text = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).map(str::to_owned);
        // Where additionalClaims land isn't documented, so accept either level.
        let extra = |key: &str| text(&claims, key).or_else(|| text(obo, key));

        let email = extra("email");
        Ok(Self {
            greeting: greeting(extra("name").as_deref(), email.as_deref()),
            email,
            user_sub: text(obo, "sub").ok_or(JwtError::Missing("obo.sub"))?,
            user_iss: text(obo, "iss").ok_or(JwtError::Missing("obo.iss"))?,
            actor: obo
                .get("act")
                .and_then(|a| text(a, "sub"))
                .or_else(|| text(&claims, "sub"))
                .ok_or(JwtError::Missing("sub"))?,
            txn: text(&claims, "txn"),
            exp: claims.get("exp").and_then(Value::as_i64).ok_or(JwtError::Missing("exp"))?,
        })
    }
}

fn greeting(name: Option<&str>, email: Option<&str>) -> String {
    let who = name
        .and_then(|n| n.split_whitespace().next())
        .or_else(|| email.and_then(|e| e.split('@').next()))
        .filter(|w| !w.is_empty());
    match who {
        Some(w) => format!("Hi, {w}!"),
        None => "Hi!".into(),
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use serde_json::{json, Value};

    pub fn alice_obo() -> Value {
        json!({
            "sub": "spiffe://prod.cavallaro.local/iot/c6-demo",
            "exp": 1792203600,
            "txn": "7f3a",
            "email": "alice@example.com",
            "name": "Alice Smith",
            "obo": {
                "sub": "google-oauth2|123",
                "iss": "https://t.us.auth0.com/",
                "act": {"sub": "spiffe://prod.cavallaro.local/iot/c6-demo"}
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use defakto::testing::make_jwt;
    use serde_json::json;

    #[test]
    fn display_claims_from_obo() {
        let c = DisplayClaims::from_obo_jwt(&make_jwt(&alice_obo())).unwrap();
        assert_eq!(
            c,
            DisplayClaims {
                greeting: "Hi, Alice!".into(),
                email: Some("alice@example.com".into()),
                user_sub: "google-oauth2|123".into(),
                user_iss: "https://t.us.auth0.com/".into(),
                actor: "spiffe://prod.cavallaro.local/iot/c6-demo".into(),
                txn: Some("7f3a".into()),
                exp: 1792203600,
            }
        );
    }

    #[test]
    fn claims_inside_obo() {
        let payload = json!({
            "sub": "spiffe://x/y", "exp": 1,
            "obo": {"sub": "u", "iss": "i", "email": "alice@example.com"}
        });
        let c = DisplayClaims::from_obo_jwt(&make_jwt(&payload)).unwrap();
        assert_eq!(c.email.as_deref(), Some("alice@example.com"));
        assert_eq!(c.greeting, "Hi, alice!");
        assert_eq!(c.actor, "spiffe://x/y");
        assert_eq!(c.txn, None);
    }

    #[test]
    fn greeting_without_name_or_email() {
        let payload = json!({"sub": "s", "exp": 1, "obo": {"sub": "u", "iss": "i"}});
        assert_eq!(DisplayClaims::from_obo_jwt(&make_jwt(&payload)).unwrap().greeting, "Hi!");
    }

    #[test]
    fn missing_obo_is_error() {
        let payload = json!({"sub": "s", "exp": 1});
        assert_eq!(DisplayClaims::from_obo_jwt(&make_jwt(&payload)), Err(JwtError::Missing("obo")));
    }
}
