//! Test doubles for code built on this crate, behind the `testing` feature.

use std::cell::Cell;
use std::collections::VecDeque;
use std::rc::Rc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};

use crate::http::{HttpClient, HttpError, HttpResponse};
use crate::{grpcweb, serverless};

#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub url: String,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub read_headers: Vec<String>,
}

/// Answers each post with the next queued reply and records the request.
#[derive(Default)]
pub struct FakeHttp {
    pub replies: VecDeque<Result<HttpResponse, HttpError>>,
    pub requests: Vec<Request>,
    /// Shared so a test can watch the count while the client is borrowed.
    pub posts: Rc<Cell<usize>>,
}

impl FakeHttp {
    pub fn reply(mut self, status: u16, body: impl Into<Vec<u8>>) -> Self {
        self.replies.push_back(Ok(HttpResponse { status, headers: vec![], body: body.into() }));
        self
    }

    pub fn fail(mut self, message: &str) -> Self {
        self.replies.push_back(Err(HttpError(message.into())));
        self
    }
}

impl HttpClient for FakeHttp {
    fn post(
        &mut self,
        url: &str,
        content_type: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        read_headers: &[&str],
    ) -> Result<HttpResponse, HttpError> {
        self.posts.set(self.posts.get() + 1);
        self.requests.push(Request {
            url: url.into(),
            content_type: content_type.into(),
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: body.to_vec(),
            read_headers: read_headers.iter().map(|h| h.to_string()).collect(),
        });
        self.replies.pop_front().expect("unexpected request")
    }
}

/// A successful gRPC-web reply to `FetchJWTSVID`, carrying one SVID.
pub fn svid_response(spiffe_id: &str, token: &str) -> Vec<u8> {
    let mut body = grpcweb::frame(&serverless::encode_response(&[(spiffe_id, token)]));
    body.extend([0x80, 0, 0, 0, 15]);
    body.extend(b"grpc-status:0\r\n");
    body
}

/// An unsigned JWT carrying `payload`.
pub fn make_jwt(payload: &Value) -> String {
    let enc = |v: &Value| URL_SAFE_NO_PAD.encode(v.to_string());
    format!("{}.{}.sig", enc(&json!({"alg":"ES256","typ":"JWT"})), enc(payload))
}
