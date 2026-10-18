//! The webhook's HTTP routes.

use std::sync::Arc;
use std::time::SystemTime;

use axum::body::Bytes;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::verifier::{Decision, Outcome, Response, Verifier, REJECT_INVALID};

/// Defakto's request. Its `_meta` and `cluster` fields are ignored.
#[derive(Deserialize)]
struct AttestRequest {
    payload: String,
}

/// `POST /attest` and `GET /healthz`.
pub fn router(verifier: Arc<Verifier>) -> Router {
    Router::new()
        .route("/attest", post(attest))
        .route("/healthz", get(|| async { "ok\n" }))
        .with_state(verifier)
}

// The body is read as bytes rather than `Json` so that a missing or wrong `Content-Type`
// isn't refused.
async fn attest(State(verifier): State<Arc<Verifier>>, body: Bytes) -> Json<Response> {
    let (response, decision) = match serde_json::from_slice::<AttestRequest>(&body) {
        Ok(request) => verifier.attest(&request.payload, SystemTime::now()),
        Err(e) => undecodable(&e),
    };
    println!("{decision}");
    Json(response)
}

/// Rejections are 200s, because the trust domain server gives up on a non-200 without reading
/// the reason.
fn undecodable(e: &serde_json::Error) -> (Response, Decision) {
    let response = Response::from([("error".to_owned(), REJECT_INVALID.to_owned())]);
    let decision = Decision {
        device_id: None,
        anchor: None,
        outcome: Outcome::Rejected,
        reason: Some(format!("undecodable request body: {e}")),
        tee: None,
    };
    (response, decision)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use axum::body::Body;
    use axum::http::{header, Method, Request, StatusCode};
    use esp_attest::hmac::{evidence_json, sign};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use crate::enrollment::{Device, Devices};
    use crate::verifier::Verifier;

    const DEVICE_ID: &str = "a1b2c3d4e5f6";
    const SECRET: [u8; 32] = *b"0123456789abcdef0123456789abcdef";

    fn app() -> axum::Router {
        let devices = Devices::from([(DEVICE_ID.to_owned(), Device { secret: Some(SECRET), tee_key: None })]);
        router(Arc::new(Verifier::new(devices, Duration::from_secs(60))))
    }

    fn now() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
    }

    /// A fresh nonce per call, so tests never hit each other's replay entries.
    fn genuine_evidence(nonce: &str) -> String {
        let ts = now();
        evidence_json(DEVICE_ID, ts, nonce, &sign(DEVICE_ID, ts, nonce, &SECRET))
    }

    fn attest_body(nonce: &str) -> String {
        serde_json::json!({ "payload": genuine_evidence(nonce) }).to_string()
    }

    async fn send(request: Request<Body>) -> (StatusCode, String) {
        let response = app().oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    fn post(body: impl Into<Body>, content_type: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method(Method::POST).uri("/attest");
        if let Some(content_type) = content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        builder.body(body.into()).unwrap()
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder().method(Method::GET).uri(uri).body(Body::empty()).unwrap()
    }

    fn json(body: &str) -> serde_json::Value {
        serde_json::from_str(body).unwrap()
    }

    #[tokio::test]
    async fn routes_attest_and_healthz() {
        let (status, body) = send(post(attest_body("0000000000000001"), Some("application/json"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json(&body)["device_id"], DEVICE_ID);
        assert!(json(&body).get("error").is_none());

        assert_eq!(send(get("/healthz")).await, (StatusCode::OK, "ok\n".to_owned()));
        assert_eq!(send(get("/attest")).await.0, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn malformed_body_is_invalid_with_200() {
        let (status, body) = send(post("{", Some("application/json"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json(&body), serde_json::json!({ "error": "invalid evidence" }));
    }

    #[tokio::test]
    async fn attest_ignores_content_type() {
        for (nonce, content_type) in [("0000000000000002", None), ("0000000000000003", Some("text/plain"))] {
            let (status, body) = send(post(attest_body(nonce), content_type)).await;
            assert_eq!(status, StatusCode::OK, "content type {content_type:?}");
            assert_eq!(json(&body)["device_id"], DEVICE_ID, "content type {content_type:?}");
        }
    }

    #[tokio::test]
    async fn ignores_meta_and_cluster() {
        let body = serde_json::json!({
            "_meta": { "version": "1.0" },
            "cluster": { "cluster_id": "" },
            "payload": genuine_evidence("0000000000000004"),
        });
        let (status, body) = send(post(body.to_string(), Some("application/json"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json(&body)["device_id"], DEVICE_ID);
    }
}
