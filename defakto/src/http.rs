//! The network seam: every call posts through `HttpClient`, which each platform
//! implements (ureq on the host, ESP-IDF's HTTP client on the device).

#[derive(Debug, Clone, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Looks a header up case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct HttpError(pub String);

pub trait HttpClient {
    /// Non-2xx responses are returned as `Ok`; `Err` means no response at all.
    /// `headers` are sent besides the content type. `read_headers` names the
    /// response headers the caller needs, since ESP-IDF can only look headers
    /// up by name.
    fn post(
        &mut self,
        url: &str,
        content_type: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        read_headers: &[&str],
    ) -> Result<HttpResponse, HttpError>;

    /// Like `post`, for a GET without headers.
    fn get(&mut self, url: &str) -> Result<HttpResponse, HttpError>;
}
