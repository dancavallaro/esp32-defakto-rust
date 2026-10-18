//! Builds attestors by kind. The worker only ever sees `dyn Attestor`, so
//! backends switch at runtime.

use anyhow::{bail, ensure, Result};
use defakto::attest::{AttestError, Attestor, HmacAttestor, HmacKey, TeeAttestor, TeeTokenSource};
use esp_attest::tee::tee_public_key;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};
use esp_idf_svc::sys::{self, esp_err_t, EspError};
use log::info;

use crate::tee::EspTee;

/// Where the active backend is remembered across reboots.
const CHOICE_NAMESPACE: &str = "demo";
const CHOICE_KEY: &str = "attestor";

/// The order a long press cycles through.
const KINDS: [&str; 2] = ["efuse", "tee"];

/// What boot falls back to when the saved backend can't be built, e.g. a broken TEE.
pub const FALLBACK: &str = "efuse";

pub struct Attestors {
    device_id: String,
    efuse_key: u8,
    nvs: EspDefaultNvsPartition,
}

impl Attestors {
    pub fn new(device_id: String, efuse_key: u8, nvs: EspDefaultNvsPartition) -> Self {
        Self { device_id, efuse_key, nvs }
    }

    pub fn build(&self, kind: &str) -> Result<Box<dyn Attestor>> {
        let id = self.device_id.clone();
        match kind {
            "efuse" => Ok(Box::new(HmacAttestor::new(id, EfuseHmacKey::new(self.efuse_key)?, "eFuse HMAC"))),
            "tee" => {
                // Logged so the key can be enrolled with the webhook.
                info!("TEE attestation key: {}", tee_public_key(&EspTee.token(0, 0)?)?);
                Ok(Box::new(TeeAttestor::new(id, EspTee)))
            }
            other => bail!("unknown attestor {other:?}"),
        }
    }

    /// The saved choice, or `default` if there is none or it names a backend
    /// this build no longer has (an older build saved `nvs`).
    pub fn saved(&self, default: &str) -> String {
        let read = || -> Result<Option<String>> {
            let store: EspNvs<NvsDefault> = EspNvs::new(self.nvs.clone(), CHOICE_NAMESPACE, false)?;
            let mut buf = [0u8; 16];
            Ok(store.get_str(CHOICE_KEY, &mut buf)?.map(str::to_owned))
        };
        read().ok().flatten().filter(|k| KINDS.contains(&k.as_str())).unwrap_or_else(|| default.to_owned())
    }

    pub fn save(&self, kind: &str) -> Result<()> {
        let store: EspNvs<NvsDefault> = EspNvs::new(self.nvs.clone(), CHOICE_NAMESPACE, true)?;
        store.set_str(CHOICE_KEY, kind)?;
        Ok(())
    }
}

pub fn next(kind: &str) -> &'static str {
    let i = KINDS.iter().position(|k| *k == kind).map_or(0, |i| i + 1);
    KINDS[i % KINDS.len()]
}

/// The device secret burned into an eFuse key block with purpose `HMAC_UP`.
/// Software never sees the key: the HMAC peripheral reads it directly.
struct EfuseHmacKey {
    id: u8,
}

impl EfuseHmacKey {
    fn new(id: u8) -> Result<Self> {
        ensure!(id <= 5, "eFuse key {id} doesn't exist; the C6 has keys 0 to 5");
        Ok(Self { id })
    }
}

// Not in esp-idf-sys's bindings; see `esp_hw_support/include/esp_hmac.h`.
extern "C" {
    fn esp_hmac_calculate(key_id: u32, message: *const core::ffi::c_void, message_len: usize, hmac: *mut u8) -> esp_err_t;
}

impl HmacKey for EfuseHmacKey {
    fn hmac_sha256(&self, msg: &[u8]) -> Result<[u8; 32], AttestError> {
        let block = sys::esp_efuse_block_t_EFUSE_BLK_KEY0 + self.id as sys::esp_efuse_block_t;
        let purpose = unsafe { sys::esp_efuse_get_key_purpose(block) };
        if purpose != sys::esp_efuse_purpose_t_ESP_EFUSE_KEY_PURPOSE_HMAC_UP {
            return Err(AttestError(format!("eFuse key {} isn't an HMAC_UP key (purpose {purpose})", self.id)));
        }
        let mut out = [0u8; 32];
        let err = unsafe { esp_hmac_calculate(self.id as u32, msg.as_ptr().cast(), msg.len(), out.as_mut_ptr()) };
        EspError::convert(err).map_err(|e| AttestError(format!("eFuse HMAC: {e}")))?;
        Ok(out)
    }
}
