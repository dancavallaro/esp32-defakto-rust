//! The ESP-TEE attestation service, as a token source for `TeeAttestor`.

use std::ffi::CStr;

use defakto::attest::{AttestError, TeeTokenSource};
use esp_idf_svc::sys::tee::esp_tee_att_generate_token;

/// Tokens run to about 1.6 KB.
const TOKEN_BUF_LEN: usize = 2048;

/// Not checked by the webhook. The TEE reads 20 bytes from this pointer, so it must be
/// exactly 19 characters plus the terminator.
const PSA_CERT_REF: &CStr = c"0716053550477-10100";

pub struct EspTee;

impl TeeTokenSource for EspTee {
    fn token(&self, nonce: u32, client_id: u32) -> Result<Vec<u8>, AttestError> {
        let mut buf = vec![0u8; TOKEN_BUF_LEN];
        let mut len = 0u32;
        let err = unsafe {
            esp_tee_att_generate_token(nonce, client_id, PSA_CERT_REF.as_ptr(), buf.as_mut_ptr(), buf.len(), &mut len)
        };
        if err != 0 {
            return Err(AttestError(format!("esp_tee_att_generate_token: {err}")));
        }
        buf.truncate(len as usize);
        Ok(buf)
    }
}
