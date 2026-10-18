//! The check-in service the badge reader checks people in with. It accepts
//! a check-in only with an OBO token that Defakto signed, naming the user and
//! the device acting for them, and shows who's here on a live page.
//!
//! Settings come from `CHECKIN_*` env vars, optionally loaded from
//! `checkin/.env`; see the README.

mod journal;
mod keys;
mod roster;
mod verify;
mod web;

use std::env;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::sync::broadcast;

use crate::journal::CheckIns;
use crate::verify::Verifier;
use crate::web::App;

/// Fixed to loopback because `/reset` has no authentication: reaching it takes `kubectl port-forward`.
const ADMIN_LISTEN: &str = "127.0.0.1:8081";

fn main() -> Result<()> {
    let _ = dotenvy::from_path(concat!(env!("CARGO_MANIFEST_DIR"), "/.env"));
    let verifier = Verifier {
        issuer: required("CHECKIN_ISSUER")?,
        audience: required("CHECKIN_AUDIENCE")?,
        devices: list("CHECKIN_DEVICES"),
        user_issuers: list("CHECKIN_USER_ISSUERS"),
    };
    let listen = optional("CHECKIN_LISTEN").unwrap_or_else(|| "0.0.0.0:8080".into());

    let jwks_uri = keys::discover_jwks_uri(&verifier.issuer)?;
    let keys = keys::fetch(&jwks_uri)?;
    println!("trust domain {}: {} signing key(s)", verifier.issuer, keys.len());
    println!("audience {}", verifier.audience);
    describe("devices", &verifier.devices);
    describe("user IdPs", &verifier.user_issuers);

    let checkins = match optional("CHECKIN_DATA") {
        Some(path) => {
            let checkins = CheckIns::open(Path::new(&path)).with_context(|| format!("opening {path}"))?;
            println!("journal {path}: {} attendee(s) checked in", checkins.entries().len());
            checkins
        }
        None => {
            println!("no CHECKIN_DATA: check-ins last until a restart");
            CheckIns::in_memory()
        }
    };

    let app = Arc::new(App {
        verifier,
        jwks_uri,
        keys: RwLock::new(keys),
        keys_fetched: Mutex::new(Instant::now()),
        checkins: Mutex::new(checkins),
        updates: broadcast::channel(64).0,
    });
    tokio::runtime::Runtime::new()?.block_on(async {
        let listener = tokio::net::TcpListener::bind(&listen).await.with_context(|| format!("binding {listen}"))?;
        let admin = tokio::net::TcpListener::bind(ADMIN_LISTEN).await.with_context(|| format!("binding {ADMIN_LISTEN}"))?;
        println!("listening on http://{listen}, and for POST /reset on http://{ADMIN_LISTEN}");
        tokio::try_join!(axum::serve(listener, web::router(app.clone())), axum::serve(admin, web::admin_router(app)))?;
        Ok(())
    })
}

fn required(name: &str) -> Result<String> {
    optional(name).with_context(|| format!("set {name}"))
}

fn optional(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
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
