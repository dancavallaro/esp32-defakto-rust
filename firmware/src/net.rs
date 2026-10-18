//! WiFi and clock. Attestation evidence carries a timestamp the server checks,
//! so nothing network-facing runs until SNTP has set the clock.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use esp_idf_svc::eventloop::{EspSubscription, EspSystemEventLoop, System};
use esp_idf_svc::hal::modem::Modem;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::sntp::{EspSntp, SyncStatus};
use esp_idf_svc::sys::{esp, esp_wifi_connect};
use esp_idf_svc::wifi::{AuthMethod, BlockingWifi, ClientConfiguration, Configuration, EspWifi, WifiEvent};
use log::{info, warn};

const SNTP_TIMEOUT: Duration = Duration::from_secs(30);
/// 2024-01-01: anything earlier means the clock was never set.
const EARLIEST_VALID_TIME: u64 = 1_704_067_200;

/// Keeps WiFi up and SNTP resyncing for as long as it lives.
pub struct Net {
    wifi: BlockingWifi<EspWifi<'static>>,
    _rejoin: EspSubscription<'static, System>,
    _sntp: EspSntp<'static>,
}

impl Net {
    /// Joined and holding an address.
    pub fn is_up(&self) -> bool {
        self.wifi.is_up().unwrap_or(false)
    }
}

pub fn connect(
    modem: Modem<'static>,
    sysloop: EspSystemEventLoop,
    nvs: EspDefaultNvsPartition,
    ssid: &str,
    psk: &str,
) -> Result<Net> {
    let mut wifi = BlockingWifi::wrap(EspWifi::new(modem, sysloop.clone(), Some(nvs))?, sysloop.clone())?;
    wifi.set_configuration(&Configuration::Client(ClientConfiguration {
        ssid: ssid.try_into().map_err(|_| anyhow::anyhow!("wifi_ssid too long"))?,
        password: psk.try_into().map_err(|_| anyhow::anyhow!("wifi_psk too long"))?,
        auth_method: if psk.is_empty() { AuthMethod::None } else { AuthMethod::WPA2Personal },
        ..Default::default()
    }))?;
    wifi.start()?;
    info!("joining {ssid:?}");
    wifi.connect().context("WiFi connect")?;
    wifi.wait_netif_up()?;
    let ip = wifi.wifi().sta_netif().get_ip_info()?;
    info!("IP {}", ip.ip);
    // The driver never rejoins by itself, so a hotspot that drops the device
    // would strand it until a reboot. A failed attempt fires another disconnect.
    let rejoin = sysloop.subscribe::<WifiEvent, _>(|event| {
        if let WifiEvent::StaDisconnected(d) = event {
            warn!("WiFi dropped (reason {}); rejoining", d.reason());
            if let Err(e) = esp!(unsafe { esp_wifi_connect() }) {
                warn!("rejoining WiFi failed: {e}");
            }
        }
    })?;

    let sntp = EspSntp::new_default()?;
    let started = Instant::now();
    while sntp.get_sync_status() != SyncStatus::Completed || unix_now() < EARLIEST_VALID_TIME {
        if started.elapsed() > SNTP_TIMEOUT {
            bail!("SNTP didn't sync within {} s", SNTP_TIMEOUT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(Net { wifi, _rejoin: rejoin, _sntp: sntp })
}

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
