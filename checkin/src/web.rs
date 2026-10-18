//! The HTTP side: devices post check-ins, and the check-in page reads the
//! roster and follows new check-ins as server-sent events. A separate admin
//! router, meant to listen only on localhost, has `POST /reset` to empty the
//! roster.

use std::convert::Infallible;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};

use crate::journal::CheckIns;
use crate::keys;
use crate::roster::Entry;
use crate::verify::{Keys, Rejection, Verifier};

/// Keeps a stream of forged key IDs from hammering the JWKS endpoint.
const MIN_KEY_REFRESH: Duration = Duration::from_secs(60);

pub struct App {
    pub verifier: Verifier,
    pub jwks_uri: String,
    pub keys: RwLock<Keys>,
    pub keys_fetched: Mutex<Instant>,
    pub checkins: Mutex<CheckIns>,
    pub updates: broadcast::Sender<Update>,
}

#[derive(Clone)]
pub enum Update {
    CheckIn(Entry),
    Reset,
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/checkins", post(check_in))
        .route("/roster", get(roster))
        .route("/events", get(events))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(app)
}

/// Unauthenticated, so it relies on listening where only an admin can reach it.
pub fn admin_router(app: Arc<App>) -> Router {
    Router::new().route("/reset", post(reset)).with_state(app)
}

async fn page() -> Html<&'static str> {
    Html(include_str!("page.html"))
}

async fn check_in(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let result = match bearer(&headers) {
        None => Err(Rejection::NoToken),
        Some(token) => verify(&app, token).await,
    };
    let attendee = match result {
        Ok(attendee) => attendee,
        Err(e) => {
            println!("rejected: {e}");
            let status = match e {
                Rejection::DeviceNotAllowed(_) | Rejection::UserIssuerNotAllowed(_) => StatusCode::FORBIDDEN,
                _ => StatusCode::UNAUTHORIZED,
            };
            return (status, Json(json!({ "error": e.to_string() }))).into_response();
        }
    };
    let recorded = app.checkins.lock().unwrap().record(attendee, unix_now());
    let (entry, new) = match recorded {
        Ok(recorded) => recorded,
        Err(e) => {
            println!("saving a check-in failed: {e}");
            let error = json!({ "error": "couldn't save the check-in" });
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response();
        }
    };
    println!(
        "checked in: {} ({}) via {}",
        entry.attendee.email.as_deref().unwrap_or(&entry.attendee.user_sub),
        entry.attendee.user_iss,
        entry.attendee.device
    );
    // No subscribers is fine: nobody has the page open.
    let _ = app.updates.send(Update::CheckIn(entry.clone()));
    let status = if new { StatusCode::CREATED } else { StatusCode::OK };
    (status, Json(entry)).into_response()
}

async fn reset(State(app): State<Arc<App>>) -> StatusCode {
    if let Err(e) = app.checkins.lock().unwrap().reset(unix_now()) {
        println!("resetting the roster failed: {e}");
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    println!("roster reset");
    let _ = app.updates.send(Update::Reset);
    StatusCode::NO_CONTENT
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")
}

/// Verifies `token`, refetching the trust domain's keys once if it names one
/// this service hasn't seen, since the trust domain rotates them.
async fn verify(app: &Arc<App>, token: &str) -> Result<crate::verify::Attendee, Rejection> {
    let first = app.verifier.verify(&app.keys.read().unwrap(), token);
    if !matches!(first, Err(Rejection::UnknownKey(_))) || !refresh_keys(app).await {
        return first;
    }
    app.verifier.verify(&app.keys.read().unwrap(), token)
}

async fn refresh_keys(app: &Arc<App>) -> bool {
    {
        let mut fetched = app.keys_fetched.lock().unwrap();
        if fetched.elapsed() < MIN_KEY_REFRESH {
            return false;
        }
        *fetched = Instant::now();
    }
    let uri = app.jwks_uri.clone();
    match tokio::task::spawn_blocking(move || keys::fetch(&uri)).await {
        Ok(Ok(keys)) => {
            println!("refreshed signing keys: {} key(s)", keys.len());
            *app.keys.write().unwrap() = keys;
            true
        }
        Ok(Err(e)) => {
            println!("refreshing signing keys failed: {e:#}");
            false
        }
        Err(e) => {
            println!("refreshing signing keys failed: {e}");
            false
        }
    }
}

async fn roster(State(app): State<Arc<App>>) -> Json<serde_json::Value> {
    let v = &app.verifier;
    Json(json!({
        "issuer": v.issuer,
        "audience": v.audience,
        "devices": v.devices,
        "user_issuers": v.user_issuers,
        "attendees": app.checkins.lock().unwrap().entries(),
    }))
}

/// Each check-in as a `checkin` event, and each reset as a `reset` event. A
/// subscriber that falls behind skips what it missed; the page reloads the
/// roster whenever it reconnects.
async fn events(State(app): State<Arc<App>>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let updates = BroadcastStream::new(app.updates.subscribe()).filter_map(|update| update.ok()).map(|update| {
        Ok(match update {
            Update::CheckIn(entry) => Event::default().event("checkin").json_data(entry).expect("entries serialize"),
            // A browser drops an event with no data.
            Update::Reset => Event::default().event("reset").data("reset"),
        })
    });
    // Some browsers don't open the stream until its first bytes, which would otherwise wait for a keep-alive.
    let hello = tokio_stream::once(Ok(Event::default().comment("connected")));
    Sse::new(hello.chain(updates)).keep_alive(KeepAlive::default())
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock after 1970").as_secs() as i64
}
