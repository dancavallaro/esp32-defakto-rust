//! gRPC-Web (binary) framing for unary calls.

use crate::http::HttpResponse;

pub const CONTENT_TYPE: &str = "application/grpc-web+proto";
pub const READ_HEADERS: &[&str] = &["grpc-status", "grpc-message"];

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum GrpcError {
    #[error("HTTP {0}")]
    Http(u16),
    #[error("truncated gRPC-Web body")]
    Truncated,
    #[error("no gRPC status")]
    NoStatus,
    #[error("gRPC status {code}: {message}")]
    Status { code: u32, message: String },
    #[error("empty gRPC response")]
    NoMessage,
}

/// Frames one message: flag 0x00, big-endian u32 length, then the message.
pub fn frame(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + message.len());
    out.push(0x00);
    out.extend_from_slice(&(message.len() as u32).to_be_bytes());
    out.extend_from_slice(message);
    out
}

const FRAME_HEADER_LEN: usize = 5;
const TRAILER_FLAG: u8 = 0x80;

/// Returns the response message, or the gRPC status if it is non-zero.
///
/// The status may arrive in HTTP headers (a trailers-only response, which Envoy
/// sends for errors) or in a trailer frame at the end of the body.
pub fn parse_response(resp: &HttpResponse) -> Result<Vec<u8>, GrpcError> {
    if let Some(code) = resp.header("grpc-status") {
        let message = resp.header("grpc-message").unwrap_or_default();
        check_status(code, message)?;
    } else if !(200..300).contains(&resp.status) {
        return Err(GrpcError::Http(resp.status));
    }

    let (message, trailer) = split_frames(&resp.body)?;
    match trailer {
        Some(t) => check_status(
            trailer_value(&t, "grpc-status").ok_or(GrpcError::NoStatus)?,
            trailer_value(&t, "grpc-message").unwrap_or_default(),
        )?,
        None if resp.header("grpc-status").is_none() => return Err(GrpcError::NoStatus),
        None => {}
    }
    message.ok_or(GrpcError::NoMessage)
}

fn split_frames(body: &[u8]) -> Result<(Option<Vec<u8>>, Option<String>), GrpcError> {
    let (mut message, mut trailer) = (None, None);
    let mut rest = body;
    while !rest.is_empty() {
        if rest.len() < FRAME_HEADER_LEN {
            return Err(GrpcError::Truncated);
        }
        let len = u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]) as usize;
        let payload = rest[FRAME_HEADER_LEN..]
            .get(..len)
            .ok_or(GrpcError::Truncated)?;
        if rest[0] & TRAILER_FLAG != 0 {
            trailer = Some(String::from_utf8_lossy(payload).into_owned());
        } else if message.is_none() {
            message = Some(payload.to_vec());
        }
        rest = &rest[FRAME_HEADER_LEN + len..];
    }
    Ok((message, trailer))
}

fn trailer_value<'a>(trailer: &'a str, name: &str) -> Option<&'a str> {
    trailer.split("\r\n").find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn check_status(code: &str, message: &str) -> Result<(), GrpcError> {
    let code: u32 = code.trim().parse().map_err(|_| GrpcError::NoStatus)?;
    if code == 0 {
        return Ok(());
    }
    Err(GrpcError::Status { code, message: percent_decode(message) })
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok());
        match (bytes[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(b)) => {
                out.push(b);
                i += 3;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, headers: &[(&str, &str)], body: Vec<u8>) -> HttpResponse {
        HttpResponse {
            status,
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body,
        }
    }

    fn trailer(text: &str) -> Vec<u8> {
        let mut out = vec![0x80];
        out.extend_from_slice(&(text.len() as u32).to_be_bytes());
        out.extend_from_slice(text.as_bytes());
        out
    }

    #[test]
    fn frame_prefixes_flag_and_length() {
        assert_eq!(frame(b"abc"), vec![0, 0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn parse_data_then_trailer() {
        let mut body = frame(b"hi");
        body.extend(trailer("grpc-status:0\r\n"));
        assert_eq!(parse_response(&resp(200, &[], body)), Ok(b"hi".to_vec()));
    }

    #[test]
    fn parse_trailer_error() {
        let body = trailer("grpc-status:7\r\ngrpc-message:denied\r\n");
        assert_eq!(
            parse_response(&resp(200, &[], body)),
            Err(GrpcError::Status { code: 7, message: "denied".into() })
        );
    }

    #[test]
    fn parse_trailers_only_error() {
        let headers = [("grpc-status", "16"), ("grpc-message", "bad%20evidence")];
        assert_eq!(
            parse_response(&resp(200, &headers, vec![])),
            Err(GrpcError::Status { code: 16, message: "bad evidence".into() })
        );
    }

    #[test]
    fn parse_truncated() {
        assert_eq!(
            parse_response(&resp(200, &[], vec![0, 0, 0, 0, 9, 1, 2])),
            Err(GrpcError::Truncated)
        );
    }

    #[test]
    fn parse_http_error() {
        assert_eq!(parse_response(&resp(503, &[], vec![])), Err(GrpcError::Http(503)));
    }

    #[test]
    fn parse_ok_status_without_message() {
        let body = trailer("grpc-status:0\r\n");
        assert_eq!(parse_response(&resp(200, &[], body)), Err(GrpcError::NoMessage));
    }
}
