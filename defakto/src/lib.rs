//! Client for Defakto's serverless SPIFFE APIs: attest a device for a JWT-SVID,
//! then present that SVID to exchange tokens. Nothing here touches hardware;
//! callers supply the HTTP transport and the attestation key.

pub mod attest;
pub mod evidence;
pub mod grpcweb;
pub mod http;
pub mod jwt;
pub mod oauth;
pub mod serverless;
pub mod tee_evidence;
pub mod token_exchange;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

use attest::AttestError;
use grpcweb::GrpcError;
use http::HttpError;
use oauth::OAuthError;
use serverless::ServerlessError;

/// `Display` stays short enough for a small screen.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("clock not set")]
    ClockNotSet,
    #[error("network: {0}")]
    Http(#[from] HttpError),
    #[error(transparent)]
    Grpc(#[from] GrpcError),
    #[error(transparent)]
    Attest(#[from] AttestError),
    #[error(transparent)]
    Serverless(#[from] ServerlessError),
    #[error(transparent)]
    OAuth(#[from] OAuthError),
}
