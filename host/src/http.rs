use std::io::Read;
use std::time::Duration;

use obo_core::http::{HttpClient, HttpError, HttpResponse};

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
        body: &[u8],
        read_headers: &[&str],
    ) -> Result<HttpResponse, HttpError> {
        let resp = match self.0.post(url).set("content-type", content_type).send_bytes(body) {
            Ok(r) | Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(HttpError(e.to_string())),
        };
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
}
