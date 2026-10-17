//! Defakto's serverless SPIFFE Workload API, JWT-SVID half.

use prost::Message;

use crate::attest::Evidence;
use crate::grpcweb;

pub const FETCH_JWT_SVID_PATH: &str =
    "/com.spirl.serverless.alpha.SpiffeWorkloadAPI/FetchJWTSVID";

#[derive(Debug, Clone, PartialEq)]
pub struct SvidToken {
    pub spiffe_id: String,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ServerlessError {
    #[error("bad protobuf: {0}")]
    Decode(String),
    #[error("server returned no SVID")]
    NoSvid,
}

/// Field numbers transcribed from the live server's gRPC reflection.
mod pb {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct FetchJwtSvidRequest {
        #[prost(message, repeated, tag = "1")]
        pub attestations: Vec<MethodAttestation>,
        #[prost(string, repeated, tag = "2")]
        pub audience: Vec<String>,
        #[prost(string, tag = "3")]
        pub spiffe_id: String,
        #[prost(string, tag = "4")]
        pub cluster_id: String,
        #[prost(string, tag = "5")]
        pub cluster_name: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct MethodAttestation {
        #[prost(string, tag = "1")]
        pub method_type: String,
        #[prost(string, tag = "2")]
        pub method_version: String,
        #[prost(bytes = "vec", tag = "3")]
        pub evidence: Vec<u8>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct FetchJwtSvidResponse {
        #[prost(message, optional, tag = "1")]
        pub jwt_svids: Option<JwtSvidResult>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct JwtSvidResult {
        #[prost(message, repeated, tag = "1")]
        pub svids: Vec<JwtSvid>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct JwtSvid {
        #[prost(string, tag = "1")]
        pub spiffe_id: String,
        #[prost(string, tag = "2")]
        pub svid: String,
        #[prost(string, tag = "3")]
        pub hint: String,
    }
}

/// Returns the framed gRPC-Web request body.
pub fn fetch_jwt_svid_body(evidence: &Evidence, audience: &str) -> Vec<u8> {
    let req = pb::FetchJwtSvidRequest {
        attestations: vec![pb::MethodAttestation {
            method_type: evidence.method_type.into(),
            method_version: evidence.method_version.into(),
            evidence: evidence.payload.clone(),
        }],
        audience: vec![audience.into()],
        ..Default::default()
    };
    grpcweb::frame(&req.encode_to_vec())
}

/// Parses the response message, returning its first SVID.
pub fn parse_fetch_jwt_svid(message: &[u8]) -> Result<SvidToken, ServerlessError> {
    let resp = pb::FetchJwtSvidResponse::decode(message)
        .map_err(|e| ServerlessError::Decode(e.to_string()))?;
    let first = resp
        .jwt_svids
        .and_then(|r| r.svids.into_iter().next())
        .ok_or(ServerlessError::NoSvid)?;
    Ok(SvidToken { spiffe_id: first.spiffe_id, token: first.svid })
}

/// Encodes a response message holding the given `(spiffe_id, token)` SVIDs.
#[cfg(test)]
pub(crate) fn encode_response(svids: &[(&str, &str)]) -> Vec<u8> {
    let svids = svids
        .iter()
        .map(|(id, token)| pb::JwtSvid { spiffe_id: (*id).into(), svid: (*token).into(), hint: String::new() })
        .collect();
    pb::FetchJwtSvidResponse { jwt_svids: Some(pb::JwtSvidResult { svids }) }.encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> Evidence {
        Evidence { method_type: "extension", method_version: "1.0", payload: b"{\"x\":1}".to_vec() }
    }

    #[test]
    fn request_round_trips() {
        let body = fetch_jwt_svid_body(&evidence(), "aud-x");
        assert_eq!(body[0], 0);
        assert_eq!(u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize, body.len() - 5);

        let req = pb::FetchJwtSvidRequest::decode(&body[5..]).unwrap();
        assert_eq!(req.attestations.len(), 1);
        assert_eq!(req.attestations[0].method_type, "extension");
        assert_eq!(req.attestations[0].method_version, "1.0");
        assert_eq!(req.attestations[0].evidence, evidence().payload);
        assert_eq!(req.audience, vec!["aud-x".to_string()]);
        assert!(req.spiffe_id.is_empty() && req.cluster_id.is_empty());
    }

    fn svid(id: &str, token: &str) -> pb::JwtSvid {
        pb::JwtSvid { spiffe_id: id.into(), svid: token.into(), hint: String::new() }
    }

    #[test]
    fn response_first_svid() {
        let msg = pb::FetchJwtSvidResponse {
            jwt_svids: Some(pb::JwtSvidResult { svids: vec![svid("spiffe://a/1", "t1"), svid("spiffe://a/2", "t2")] }),
        }
        .encode_to_vec();
        assert_eq!(
            parse_fetch_jwt_svid(&msg),
            Ok(SvidToken { spiffe_id: "spiffe://a/1".into(), token: "t1".into() })
        );
    }

    #[test]
    fn response_without_svids() {
        let msg = pb::FetchJwtSvidResponse { jwt_svids: Some(pb::JwtSvidResult { svids: vec![] }) }.encode_to_vec();
        assert_eq!(parse_fetch_jwt_svid(&msg), Err(ServerlessError::NoSvid));
        assert_eq!(parse_fetch_jwt_svid(&[]), Err(ServerlessError::NoSvid));
    }

    #[test]
    fn response_garbage_is_decode_error() {
        assert!(matches!(parse_fetch_jwt_svid(&[0x0a, 0xff]), Err(ServerlessError::Decode(_))));
    }
}
