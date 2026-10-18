//! The HTTP side: devices post check-ins, and the check-in page reads the
//! roster and follows new check-ins as server-sent events.

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

use crate::keys;
use crate::roster::{Entry, Roster};
use crate::verify::{Keys, Rejection, Verifier};

/// Keeps a stream of forged key IDs from hammering the JWKS endpoint.
const MIN_KEY_REFRESH: Duration = Duration::from_secs(60);

pub struct App {
    pub verifier: Verifier,
    pub jwks_uri: String,
    pub keys: RwLock<Keys>,
    pub keys_fetched: Mutex<Instant>,
    pub roster: Mutex<Roster>,
    pub updates: broadcast::Sender<Entry>,
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

async fn page() -> Html<&'static str> {
    Html(include_str!("page.html"))
}

async fn check_in(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let result = match token {
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
    let (entry, new) = app.roster.lock().unwrap().record(attendee, unix_now());
    println!(
        "checked in: {} ({}) via {}",
        entry.attendee.email.as_deref().unwrap_or(&entry.attendee.user_sub),
        entry.attendee.user_iss,
        entry.attendee.device
    );
    // No subscribers is fine: nobody has the page open.
    let _ = app.updates.send(entry.clone());
    let status = if new { StatusCode::CREATED } else { StatusCode::OK };
    (status, Json(entry)).into_response()
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
        "attendees": app.roster.lock().unwrap().entries(),
    }))
}

/// Each check-in as a `checkin` event. A subscriber that falls behind skips
/// what it missed; the page reloads the roster whenever it reconnects.
async fn events(State(app): State<Arc<App>>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(app.updates.subscribe())
        .filter_map(|entry| entry.ok())
        .map(|entry| Ok(Event::default().event("checkin").json_data(entry).expect("entries serialize")));
    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock after 1970").as_secs() as i64
}
