//! Builds attestors by kind. The worker only ever sees `dyn Attestor`, so
//! backends switch at runtime.

use anyhow::{bail, ensure, Context, Result};
use defakto::attest::{AttestError, Attestor, HmacAttestor, HmacKey, SoftwareHmacKey, TeeAttestor, TeeTokenSource};
use defakto::tee_evidence::tee_public_key;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};
use esp_idf_svc::sys::{self, esp_err_t, EspError};
use log::info;

use crate::tee::EspTee;

/// Where `esp32-enroll generate` puts the secret (see its `nvs.csv`).
const SECRET_NAMESPACE: &str = "spiffe";
const SECRET_KEY: &str = "device_secret";
/// Where the active backend is remembered across reboots.
const CHOICE_NAMESPACE: &str = "demo";
const CHOICE_KEY: &str = "attestor";

/// The order a long press cycles through.
const KINDS: [&str; 2] = ["nvs", "efuse"];

pub struct Attestors {
    device_id: &'static str,
    efuse_key: u8,
    nvs: EspDefaultNvsPartition,
}

impl Attestors {
    pub fn new(device_id: &'static str, efuse_key: u8, nvs: EspDefaultNvsPartition) -> Self {
        Self { device_id, efuse_key, nvs }
    }

    pub fn build(&self, kind: &str) -> Result<Box<dyn Attestor>> {
        let id = self.device_id.into();
        match kind {
            "nvs" => Ok(Box::new(HmacAttestor::new(id, nvs_key(&self.nvs)?, "NVS HMAC"))),
            "efuse" => Ok(Box::new(HmacAttestor::new(id, EfuseHmacKey::new(self.efuse_key)?, "eFuse HMAC"))),
            "tee" => {
                // Logged so the key can be enrolled with the webhook.
                let token = EspTee.token(0, 0)?;
                let token = token.strip_suffix(&[0]).unwrap_or(&token);
                info!("TEE attestation key: {}", tee_public_key(token)?);
                Ok(Box::new(TeeAttestor::new(id, EspTee)))
            }
            other => bail!("unknown attestor {other:?}"),
        }
    }

    /// The saved choice, or `default` if there is none.
    pub fn saved(&self, default: &str) -> String {
        let read = || -> Result<Option<String>> {
            let store: EspNvs<NvsDefault> = EspNvs::new(self.nvs.clone(), CHOICE_NAMESPACE, false)?;
            let mut buf = [0u8; 16];
            Ok(store.get_str(CHOICE_KEY, &mut buf)?.map(str::to_owned))
        };
        read().ok().flatten().unwrap_or_else(|| default.to_owned())
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

fn nvs_key(nvs: &EspDefaultNvsPartition) -> Result<SoftwareHmacKey> {
    let store: EspNvs<NvsDefault> =
        EspNvs::new(nvs.clone(), SECRET_NAMESPACE, false).context("NVS namespace `spiffe` missing; flash nvs.bin")?;
    let mut buf = [0u8; 64];
    let secret = store.get_blob(SECRET_KEY, &mut buf)?.context("no device_secret in NVS; flash nvs.bin")?;
    ensure!(secret.len() == 32, "device_secret is {} bytes, want 32", secret.len());
    Ok(SoftwareHmacKey(secret.to_vec()))
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
