use std::io::Read;
use std::time::Duration;

use defakto::http::{HttpClient, HttpError, HttpResponse};

const TIMEOUT: Duration = Duration::from_secs(15);
const MAX_BODY: u64 = 64 * 1024;

pub struct UreqClient(ureq::Agent);

impl UreqClient {
    pub fn new() -> Self {
        Self(ureq::AgentBuilder::new().timeout(TIMEOUT).build())
    }
}

impl HttpClient for UreqClient {
    fn post(
        &mut self,
        url: &str,
        content_type: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        read_headers: &[&str],
    ) -> Result<HttpResponse, HttpError> {
        let req = headers.iter().fold(self.0.post(url).set("content-type", content_type), |req, (k, v)| req.set(k, v));
        let resp = match req.send_bytes(body) {
            Ok(r) | Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(HttpError(e.to_string())),
        };
        read(resp, read_headers)
    }

    fn get(&mut self, url: &str) -> Result<HttpResponse, HttpError> {
        match self.0.get(url).call() {
            Ok(r) | Err(ureq::Error::Status(_, r)) => read(r, &[]),
            Err(e) => Err(HttpError(e.to_string())),
        }
    }
}

fn read(resp: ureq::Response, read_headers: &[&str]) -> Result<HttpResponse, HttpError> {
    let status = resp.status();
    let headers = read_headers
        .iter()
        .filter_map(|h| resp.header(h).map(|v| (h.to_string(), v.to_string())))
        .collect();
    let mut body = Vec::new();
    resp.into_reader()
        .take(MAX_BODY)
        .read_to_end(&mut body)
        .map_err(|e| HttpError(e.to_string()))?;
    Ok(HttpResponse { status, headers, body })
}
