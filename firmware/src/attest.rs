//! Builds the configured attestor. The worker only ever sees `dyn Attestor`,
//! so the eFuse and TEE backends slot in here.

use anyhow::{bail, ensure, Context, Result};
use defakto::attest::{Attestor, HmacAttestor, SoftwareHmacKey};
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};

/// Where `esp32-enroll generate` puts the secret (see its `nvs.csv`).
const NVS_NAMESPACE: &str = "spiffe";
const NVS_KEY: &str = "device_secret";

pub fn build(kind: &str, device_id: &str, nvs: &EspDefaultNvsPartition) -> Result<Box<dyn Attestor>> {
    match kind {
        "nvs" => Ok(Box::new(HmacAttestor::new(device_id.into(), nvs_key(nvs)?, "NVS HMAC"))),
        other => bail!("unknown attestor {other:?}"),
    }
}

pub fn nvs_key(nvs: &EspDefaultNvsPartition) -> Result<SoftwareHmacKey> {
    let store: EspNvs<NvsDefault> =
        EspNvs::new(nvs.clone(), NVS_NAMESPACE, false).context("NVS namespace `spiffe` missing; flash nvs.bin")?;
    let mut buf = [0u8; 64];
    let secret = store.get_blob(NVS_KEY, &mut buf)?.context("no device_secret in NVS; flash nvs.bin")?;
    ensure!(secret.len() == 32, "device_secret is {} bytes, want 32", secret.len());
    Ok(SoftwareHmacKey(secret.to_vec()))
}
