//! The check-in service the badge reader checks people in with. It accepts
//! a check-in only with an OBO token that Defakto signed, naming the user and
//! the device acting for them, and shows who's here on a live page.
//!
//! Settings come from `CHECKIN_*` env vars, optionally loaded from
//! `checkin/.env`; see the README.

mod keys;
mod roster;
mod verify;
mod web;

use std::env;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::sync::broadcast;

use crate::roster::Roster;
use crate::verify::Verifier;
use crate::web::App;

fn main() -> Result<()> {
    let _ = dotenvy::from_path(concat!(env!("CARGO_MANIFEST_DIR"), "/.env"));
    let verifier = Verifier {
        issuer: required("CHECKIN_ISSUER")?,
        audience: required("CHECKIN_AUDIENCE")?,
        devices: list("CHECKIN_DEVICES"),
        user_issuers: list("CHECKIN_USER_ISSUERS"),
    };
    let listen = env::var("CHECKIN_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());

    let jwks_uri = keys::discover_jwks_uri(&verifier.issuer)?;
    let keys = keys::fetch(&jwks_uri)?;
    println!("trust domain {}: {} signing key(s)", verifier.issuer, keys.len());
    println!("audience {}", verifier.audience);
    describe("devices", &verifier.devices);
    describe("user IdPs", &verifier.user_issuers);

    let app = Arc::new(App {
        verifier,
        jwks_uri,
        keys: RwLock::new(keys),
        keys_fetched: Mutex::new(Instant::now()),
        roster: Mutex::new(Roster::default()),
        updates: broadcast::channel(64).0,
    });
    tokio::runtime::Runtime::new()?.block_on(async {
        let listener = tokio::net::TcpListener::bind(&listen).await.with_context(|| format!("binding {listen}"))?;
        println!("listening on http://{listen}");
        axum::serve(listener, web::router(app)).await?;
        Ok(())
    })
}

fn required(name: &str) -> Result<String> {
    env::var(name).ok().filter(|v| !v.is_empty()).with_context(|| format!("set {name}"))
}

/// A comma-separated list; unset or empty means no restriction.
fn list(name: &str) -> Vec<String> {
    env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect()
}

fn describe(what: &str, allowed: &[String]) {
    if allowed.is_empty() {
        println!("accepting any {what}");
    } else {
        println!("accepting {what}: {}", allowed.join(", "));
    }
}
