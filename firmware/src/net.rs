//! WiFi and clock. Attestation evidence carries a timestamp the server checks,
//! so nothing network-facing runs until SNTP has set the clock.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::modem::Modem;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::sntp::{EspSntp, SyncStatus};
use esp_idf_svc::wifi::{AuthMethod, BlockingWifi, ClientConfiguration, Configuration, EspWifi};
use log::info;

use crate::config::CONFIG;

const SNTP_TIMEOUT: Duration = Duration::from_secs(30);
/// 2024-01-01: anything earlier means the clock was never set.
const EARLIEST_VALID_TIME: u64 = 1_704_067_200;

/// Keeps WiFi up and SNTP resyncing for as long as it lives.
pub struct Net {
    _wifi: BlockingWifi<EspWifi<'static>>,
    _sntp: EspSntp<'static>,
}

pub fn connect(modem: Modem<'static>, sysloop: EspSystemEventLoop, nvs: EspDefaultNvsPartition) -> Result<Net> {
    let mut wifi = BlockingWifi::wrap(EspWifi::new(modem, sysloop.clone(), Some(nvs))?, sysloop)?;
    wifi.set_configuration(&Configuration::Client(ClientConfiguration {
        ssid: CONFIG.wifi_ssid.try_into().map_err(|_| anyhow::anyhow!("wifi_ssid too long"))?,
        password: CONFIG.wifi_psk.try_into().map_err(|_| anyhow::anyhow!("wifi_psk too long"))?,
        auth_method: if CONFIG.wifi_psk.is_empty() { AuthMethod::None } else { AuthMethod::WPA2Personal },
        ..Default::default()
    }))?;
    wifi.start()?;
    info!("joining {:?}", CONFIG.wifi_ssid);
    wifi.connect().context("WiFi connect")?;
    wifi.wait_netif_up()?;
    let ip = wifi.wifi().sta_netif().get_ip_info()?;
    info!("IP {}", ip.ip);

    let sntp = EspSntp::new_default()?;
    let started = Instant::now();
    while sntp.get_sync_status() != SyncStatus::Completed || unix_now() < EARLIEST_VALID_TIME {
        if started.elapsed() > SNTP_TIMEOUT {
            bail!("SNTP didn't sync within {} s", SNTP_TIMEOUT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(Net { _wifi: wifi, _sntp: sntp })
}

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
