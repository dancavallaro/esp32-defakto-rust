//! Settings: what the setup wizard saved in NVS, over the build-time defaults
//! from `cfg.toml` (see `cfg.toml.example`), which may be left empty. A newly
//! flashed build's first boot puts its non-empty defaults back over the saved ones.

use anyhow::Result;
use demo::setup::{self, DevIdGate, Settings};
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};

const NAMESPACE: &str = "demo";
const SETTINGS: &str = "settings";
/// Settings the wizard saved with a DevID the device hasn't verified yet.
const PENDING: &str = "pending";
/// Why the last settings were refused, for the wizard to show.
const PROBLEM: &str = "problem";
/// The ELF SHA-256 of the build that last applied its settings.
const BUILD: &str = "build";

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
    /// Defakto's serverless API; token exchange is at its `/oauth/token`.
    #[default("https://defakto.o.cavnet.cloud")]
    defakto_endpoint: &'static str,
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
    /// The attestation methods enabled, and which one a new board starts with.
    #[default("efuse,tee")]
    attestors: &'static str,
    #[default("efuse")]
    default_attestor: &'static str,
    /// The eFuse key block (0 to 5) holding the device secret for `efuse`.
    #[default(5)]
    efuse_hmac_key: u8,
    /// The issuer of the DevIDs that may set up the device; empty for none,
    /// which leaves the wizard open to anyone who can read its password.
    #[default("")]
    devid_issuer: &'static str,
    /// The SPIFFE ID prefix those DevIDs must have.
    #[default("")]
    devid_subjects: &'static str,
}

pub fn devid_gate() -> Option<DevIdGate> {
    (!CONFIG.devid_issuer.is_empty())
        .then(|| DevIdGate { issuer: CONFIG.devid_issuer.into(), subjects: CONFIG.devid_subjects.into() })
}

fn defaults() -> Settings {
    Settings {
        wifi_ssid: CONFIG.wifi_ssid.into(),
        wifi_psk: CONFIG.wifi_psk.into(),
        login_device_url: CONFIG.login_device_url.into(),
        login_token_url: CONFIG.login_token_url.into(),
        login_client_id: CONFIG.login_client_id.into(),
        defakto_endpoint: CONFIG.defakto_endpoint.into(),
        svid_audience: CONFIG.svid_audience.into(),
        device_id: CONFIG.device_id.into(),
        attestors: CONFIG.attestors.into(),
        obo_audience: CONFIG.obo_audience.into(),
        subject_token_type: CONFIG.subject_token_type.into(),
        requested_token_type: CONFIG.requested_token_type.into(),
        checkin_url: CONFIG.checkin_url.into(),
    }
}

pub fn load(nvs: &EspDefaultNvsPartition) -> Settings {
    match read(nvs, SETTINGS) {
        Some(saved) => defaults().overlaid(&saved),
        None => defaults(),
    }
}

/// On a newly flashed build's first boot, its settings replace the saved
/// ones, except where `cfg.toml` leaves a field empty.
pub fn rebuild(nvs: &EspDefaultNvsPartition) -> Result<()> {
    let mut sha = [0 as core::ffi::c_char; 65];
    unsafe { esp_idf_svc::sys::esp_app_get_elf_sha256(sha.as_mut_ptr(), sha.len()) };
    let sha = unsafe { core::ffi::CStr::from_ptr(sha.as_ptr()) }.to_string_lossy().into_owned();
    if read(nvs, BUILD).as_deref() == Some(sha.as_str()) {
        return Ok(());
    }
    if let Some(saved) = read(nvs, SETTINGS) {
        log::info!("new build: applying cfg.toml over the saved settings");
        save(nvs, &defaults().overlaid(&saved).rebuilt(&defaults()))?;
    }
    write(nvs, BUILD, &sha)
}

pub fn save(nvs: &EspDefaultNvsPartition, settings: &Settings) -> Result<()> {
    write(nvs, SETTINGS, &settings.to_form())
}

pub fn save_pending(nvs: &EspDefaultNvsPartition, settings: &Settings, devid: &str) -> Result<()> {
    write(nvs, PENDING, &setup::pending_form(settings, devid))
}

/// Pending settings and their DevID, removed from NVS: whether they're taken
/// or refused, they're only tried once.
pub fn take_pending(nvs: &EspDefaultNvsPartition) -> Option<(Settings, String)> {
    let form = take(nvs, PENDING)?;
    Some((load(nvs).overlaid(&form), setup::pending_token(&form).unwrap_or_default()))
}

pub fn save_problem(nvs: &EspDefaultNvsPartition, problem: &str) -> Result<()> {
    write(nvs, PROBLEM, problem)
}

pub fn take_problem(nvs: &EspDefaultNvsPartition) -> Option<String> {
    take(nvs, PROBLEM)
}

fn read(nvs: &EspDefaultNvsPartition, key: &str) -> Option<String> {
    let read = || -> Result<Option<String>> {
        let store: EspNvs<NvsDefault> = EspNvs::new(nvs.clone(), NAMESPACE, false)?;
        let Some(len) = store.str_len(key)? else { return Ok(None) };
        let mut buf = vec![0u8; len];
        Ok(store.get_str(key, &mut buf)?.map(str::to_owned))
    };
    read().ok().flatten()
}

fn write(nvs: &EspDefaultNvsPartition, key: &str, value: &str) -> Result<()> {
    let store: EspNvs<NvsDefault> = EspNvs::new(nvs.clone(), NAMESPACE, true)?;
    store.set_str(key, value)?;
    Ok(())
}

fn take(nvs: &EspDefaultNvsPartition, key: &str) -> Option<String> {
    let value = read(nvs, key)?;
    if let Err(e) = EspNvs::<NvsDefault>::new(nvs.clone(), NAMESPACE, true).and_then(|store| store.remove(key)) {
        log::warn!("removing {key} from NVS failed: {e}");
    }
    Some(value)
}
