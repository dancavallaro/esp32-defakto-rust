//! Finds and fetches the trust domain's signing keys through OIDC discovery.

use anyhow::{Context, Result};
use jsonwebtoken::jwk::JwkSet;
use serde::Deserialize;

use crate::verify::Keys;

/// The `jwks_uri` from `issuer`'s discovery document.
pub fn discover_jwks_uri(issuer: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Discovery {
        jwks_uri: String,
    }
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let doc: Discovery = ureq::get(&url).call()?.into_json().with_context(|| format!("reading {url}"))?;
    Ok(doc.jwks_uri)
}

pub fn fetch(jwks_uri: &str) -> Result<Keys> {
    let jwks: JwkSet = ureq::get(jwks_uri).call()?.into_json().with_context(|| format!("reading {jwks_uri}"))?;
    Ok(Keys::from_jwks(&jwks))
}
