//! `HttpClient` over ESP-IDF's HTTP client, trusting the built-in CA bundle.

use std::time::Duration;

use defakto::http::{HttpClient, HttpError, HttpResponse};
use esp_idf_svc::http::client::{Configuration, EspHttpConnection};
use esp_idf_svc::http::Method;

const TIMEOUT: Duration = Duration::from_secs(15);
/// Responses here are a few KB; the cap keeps a bad server from exhausting the heap.
const MAX_BODY: usize = 64 * 1024;

pub struct EspClient;

impl EspClient {
    fn connect() -> Result<EspHttpConnection, HttpError> {
        EspHttpConnection::new(&Configuration {
            crt_bundle_attach: Some(esp_idf_svc::sys::esp_crt_bundle_attach),
            timeout: Some(TIMEOUT),
            buffer_size: Some(4096),
            // Headers go out through this buffer, and the check-in's bearer token alone outgrows the 512-byte default.
            buffer_size_tx: Some(4096),
            ..Default::default()
        })
        .map_err(err)
    }
}

impl HttpClient for EspClient {
    fn post(
        &mut self,
        url: &str,
        content_type: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        read_headers: &[&str],
    ) -> Result<HttpResponse, HttpError> {
        let mut conn = Self::connect()?;
        let len = body.len().to_string();
        let mut all = vec![("content-type", content_type), ("content-length", len.as_str())];
        all.extend_from_slice(headers);
        conn.initiate_request(Method::Post, url, &all).map_err(err)?;
        conn.write_all(body).map_err(err)?;
        conn.initiate_response().map_err(err)?;
        read(conn, read_headers)
    }

    fn get(&mut self, url: &str) -> Result<HttpResponse, HttpError> {
        let mut conn = Self::connect()?;
        conn.initiate_request(Method::Get, url, &[]).map_err(err)?;
        conn.initiate_response().map_err(err)?;
        read(conn, &[])
    }
}

fn read(mut conn: EspHttpConnection, read_headers: &[&str]) -> Result<HttpResponse, HttpError> {
    let status = conn.status();
    let headers = read_headers
        .iter()
        .filter_map(|h| conn.header(h).map(|v| (h.to_string(), v.to_string())))
        .collect();
    let mut body = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = conn.read(&mut buf).map_err(err)?;
        if n == 0 {
            break;
        }
        if body.len() + n > MAX_BODY {
            return Err(HttpError(format!("response over {MAX_BODY} bytes")));
        }
        body.extend_from_slice(&buf[..n]);
    }
    Ok(HttpResponse { status, headers, body })
}

fn err(e: impl std::fmt::Display) -> HttpError {
    HttpError(e.to_string())
}
