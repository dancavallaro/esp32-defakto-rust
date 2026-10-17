//! Reading JWT claims without verifying the signature, for display and
//! debugging only.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum JwtError {
    #[error("malformed token")]
    Malformed,
    #[error("token missing {0}")]
    Missing(&'static str),
}

pub fn decode_claims(jwt: &str) -> Result<Value, JwtError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let mut parts = jwt.split('.');
    let payload = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(_), Some(p), Some(_), None) => p,
        _ => return Err(JwtError::Malformed),
    };
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| JwtError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| JwtError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::make_jwt;
    use serde_json::json;

    #[test]
    fn decodes_payload() {
        let payload = json!({"sub": "spiffe://p/iot/c6-demo", "exp": 1});
        assert_eq!(decode_claims(&make_jwt(&payload)), Ok(payload));
    }

    #[test]
    fn garbage_is_malformed() {
        assert_eq!(decode_claims("not-a-jwt"), Err(JwtError::Malformed));
        assert_eq!(decode_claims("a.!!!.c"), Err(JwtError::Malformed));
    }
}
