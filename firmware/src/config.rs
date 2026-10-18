//! Settings: what the setup wizard saved in NVS, over the build-time defaults
//! from `cfg.toml` (see `cfg.toml.example`), which may be left empty.

use anyhow::Result;
use demo::setup::Settings;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};

const NAMESPACE: &str = "demo";
const KEY: &str = "settings";

#[toml_cfg::toml_config]
pub struct Config {
    #[default("")]
    wifi_ssid: &'static str,
    #[default("")]
    wifi_psk: &'static str,
    #[default("defakto-demo")]
    device_id: &'static str,
    #[default("")]
    login_device_url: &'static str,
    #[default("")]
    login_token_url: &'static str,
    #[default("")]
    login_client_id: &'static str,
    #[default("")]
    svid_audience: &'static str,
    #[default("urn:ietf:params:oauth:token-type:id_token")]
    subject_token_type: &'static str,
    #[default("urn:defakto:security:token-type:jwt-svid-obo")]
    requested_token_type: &'static str,
    #[default("defakto-demo")]
    obo_audience: &'static str,
    /// The check-in service's endpoint; empty for none.
    #[default("")]
    checkin_url: &'static str,
    #[default("efuse")]
    default_attestor: &'static str,
    /// The eFuse key block (0 to 5) holding the device secret for `efuse`.
    #[default(5)]
    efuse_hmac_key: u8,
}

fn defaults() -> Settings {
    Settings {
        wifi_ssid: CONFIG.wifi_ssid.into(),
        wifi_psk: CONFIG.wifi_psk.into(),
        login_device_url: CONFIG.login_device_url.into(),
        login_token_url: CONFIG.login_token_url.into(),
        login_client_id: CONFIG.login_client_id.into(),
        svid_audience: CONFIG.svid_audience.into(),
        device_id: CONFIG.device_id.into(),
        obo_audience: CONFIG.obo_audience.into(),
        subject_token_type: CONFIG.subject_token_type.into(),
        requested_token_type: CONFIG.requested_token_type.into(),
        checkin_url: CONFIG.checkin_url.into(),
    }
}

pub fn load(nvs: &EspDefaultNvsPartition) -> Settings {
    let read = || -> Result<Option<String>> {
        let store: EspNvs<NvsDefault> = EspNvs::new(nvs.clone(), NAMESPACE, false)?;
        let Some(len) = store.str_len(KEY)? else { return Ok(None) };
        let mut buf = vec![0u8; len];
        Ok(store.get_str(KEY, &mut buf)?.map(str::to_owned))
    };
    match read() {
        Ok(Some(saved)) => defaults().overlaid(&saved),
        _ => defaults(),
    }
}

pub fn save(nvs: &EspDefaultNvsPartition, settings: &Settings) -> Result<()> {
    let store: EspNvs<NvsDefault> = EspNvs::new(nvs.clone(), NAMESPACE, true)?;
    store.set_str(KEY, &settings.to_form())?;
    Ok(())
}
