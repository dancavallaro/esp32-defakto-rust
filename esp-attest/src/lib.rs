//! The evidence formats an ESP32 device attests with: an HMAC over
//! `device_id|ts|nonce`, or an ESP-TEE attestation token wrapped in an envelope that
//! binds it to the same fields. Pure formats, with no transport and no hardware.

mod device_id;
#[cfg(feature = "verify")]
pub mod evidence;
pub mod hmac;
pub mod tee;
#[cfg(feature = "verify")]
pub mod tee_verify;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use device_id::validate_device_id;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct Error(pub String);
