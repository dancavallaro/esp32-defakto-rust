//! The setup wizard's access point, its captive DNS, and the portal that edits
//! the settings. `demo::setup` holds everything here that isn't hardware.

use std::net::{Ipv4Addr, UdpSocket};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use demo::captive;
use demo::setup::{self, DevIdGate, Settings};
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::modem::Modem;
use esp_idf_svc::http::server::{self as http, EspHttpConnection, EspHttpServer, Request};
use esp_idf_svc::http::Method;
use esp_idf_svc::io::Write;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::wifi::{
    AccessPointConfiguration, AuthMethod, BlockingWifi, ClientConfiguration, Configuration, EspWifi, WifiDeviceId,
};
use log::{info, warn};

use crate::config;

const PASSWORD_LEN: usize = 8;
const MAX_NETWORKS: usize = 12;
/// The form is a few hundred bytes; the cap keeps a bad client from exhausting the heap.
const MAX_FORM: usize = 4096;
const HTTP_STACK: usize = 10 * 1024;
const DNS_STACK: usize = 6 * 1024;

/// Keeps the access point, DNS and portal up for as long as it lives.
pub struct Portal {
    pub ssid: String,
    pub password: String,
    /// The portal's address, for anyone whose phone doesn't open it by itself.
    pub url: String,
    _wifi: BlockingWifi<EspWifi<'static>>,
    _server: EspHttpServer<'static>,
}

/// What the portal edits and how it guards saving.
pub struct Wizard {
    pub current: Settings,
    /// Asks for a DevID, which the device checks once it's online.
    pub gate: Option<DevIdGate>,
    /// Why the last settings were refused, shown until the next submission.
    pub problem: Option<String>,
}

/// Starts the wizard. The receiver fires once new settings are saved, when
/// the device should restart.
pub fn start(
    modem: Modem<'static>,
    sysloop: EspSystemEventLoop,
    nvs: EspDefaultNvsPartition,
    wizard: Wizard,
) -> Result<(Portal, Receiver<()>)> {
    let mut wifi = BlockingWifi::wrap(EspWifi::new(modem, sysloop.clone(), Some(nvs.clone()))?, sysloop)?;
    // Scanning first gives the form its list of networks, and the password is
    // drawn once the radio is on, when the RNG is truly random.
    wifi.set_configuration(&Configuration::Client(ClientConfiguration::default()))?;
    wifi.start()?;
    let networks = scan(&mut wifi);
    let password = random_password();
    wifi.stop()?;

    let mac = wifi.wifi().get_mac(WifiDeviceId::Ap)?;
    let ssid = format!("defakto-setup-{:02X}{:02X}", mac[4], mac[5]);
    wifi.set_configuration(&Configuration::AccessPoint(AccessPointConfiguration {
        ssid: ssid.as_str().try_into().map_err(|_| anyhow::anyhow!("SSID too long"))?,
        password: password.as_str().try_into().map_err(|_| anyhow::anyhow!("password too long"))?,
        auth_method: AuthMethod::WPA2Personal,
        max_connections: 4,
        ..Default::default()
    }))?;
    wifi.start()?;
    wifi.wait_netif_up()?;
    let ip = wifi.wifi().ap_netif().get_ip_info()?.ip;
    info!("setup network {ssid:?} up at {ip}");

    std::thread::Builder::new().name("dns".into()).stack_size(DNS_STACK).spawn(move || serve_dns(ip))?;
    let (saved_tx, saved) = mpsc::channel();
    let server = serve_portal(ip, nvs, wizard, networks, saved_tx)?;
    let url = format!("http://{ip}");
    Ok((Portal { ssid, password, url, _wifi: wifi, _server: server }, saved))
}

/// Network names by signal strength, strongest first, without duplicates.
fn scan(wifi: &mut BlockingWifi<EspWifi<'static>>) -> Vec<String> {
    let mut found = wifi.scan().unwrap_or_else(|e| {
        warn!("scanning for networks failed: {e}");
        Vec::new()
    });
    found.sort_by_key(|ap| std::cmp::Reverse(ap.signal_strength));
    let mut names: Vec<String> = Vec::new();
    for ap in found {
        if !ap.ssid.is_empty() && !names.iter().any(|n| n == ap.ssid.as_str()) {
            names.push(ap.ssid.to_string());
        }
    }
    names.truncate(MAX_NETWORKS);
    names
}

fn random_password() -> String {
    let mut random = [0u8; PASSWORD_LEN];
    unsafe { esp_idf_svc::sys::esp_fill_random(random.as_mut_ptr().cast(), random.len()) };
    setup::ap_password(&random)
}

fn serve_dns(ip: Ipv4Addr) {
    let socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 53)) {
        Ok(socket) => socket,
        Err(e) => return warn!("captive DNS couldn't bind: {e}"),
    };
    let mut buf = [0u8; 512];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                if let Some(reply) = captive::dns_answer(&buf[..n], ip.octets()) {
                    let _ = socket.send_to(&reply, from);
                }
            }
            Err(e) => warn!("captive DNS: {e}"),
        }
    }
}

fn serve_portal(
    ip: Ipv4Addr,
    nvs: EspDefaultNvsPartition,
    Wizard { current, gate, problem }: Wizard,
    networks: Vec<String>,
    saved: mpsc::Sender<()>,
) -> Result<EspHttpServer<'static>> {
    let mut server = EspHttpServer::new(&http::Configuration {
        stack_size: HTTP_STACK,
        uri_match_wildcard: true,
        // Phones open a burst of connections to check for a captive portal.
        lru_purge_enable: true,
        ..Default::default()
    })?;
    let current = Arc::new(Mutex::new(current));
    let problem = Arc::new(Mutex::new(problem));
    let (networks, gate) = (Arc::new(networks), Arc::new(gate));

    let (shown, shown_problem, offered, asked) = (current.clone(), problem.clone(), networks.clone(), gate.clone());
    server.fn_handler::<anyhow::Error, _>("/", Method::Get, move |req| {
        let problem = shown_problem.lock().unwrap();
        let html = setup::page(&shown.lock().unwrap(), &offered, problem.as_deref(), asked.as_ref().as_ref());
        respond(req, 200, &html)
    })?;

    let saved = Mutex::new(saved);
    server.fn_handler::<anyhow::Error, _>("/", Method::Post, move |mut req| {
        let form = read_form(&mut req)?;
        let mut current = current.lock().unwrap();
        *problem.lock().unwrap() = None;
        let gate = gate.as_ref().as_ref();
        let submitted = current.submit(&form).and_then(|next| match gate {
            Some(gate) => gate.precheck(&form, &next.device_id).map(|devid| (next, Some(devid))),
            None => Ok((next, None)),
        });
        match submitted {
            Ok((next, devid)) => {
                match &devid {
                    Some(devid) => config::save_pending(&nvs, &next, devid),
                    None => config::save(&nvs, &next),
                }
                .context("saving settings")?;
                info!("settings saved{}", if devid.is_some() { ", pending their DevID" } else { "" });
                *current = next;
                respond(req, 200, &setup::saved_page(devid.is_some()))?;
                let _ = saved.lock().unwrap().send(());
                Ok(())
            }
            Err(problem) => {
                // What they typed, minus the password, which the page never shows.
                let typed = Settings { wifi_psk: current.wifi_psk.clone(), ..current.overlaid(&form) };
                respond(req, 400, &setup::page(&typed, &networks, Some(&problem), gate))
            }
        }
    })?;

    // Registered last so it only takes what "/" didn't. Answering the phone's
    // connectivity check with a redirect is what makes it open the portal.
    let home = format!("http://{ip}/");
    server.fn_handler::<anyhow::Error, _>("/*", Method::Get, move |req| {
        req.into_response(302, None, &[("location", &home), ("cache-control", "no-store")])?;
        Ok(())
    })?;
    Ok(server)
}

fn read_form(req: &mut Request<&mut EspHttpConnection>) -> Result<String> {
    let mut body = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let n = req.read(&mut buf).map_err(|e| anyhow::anyhow!("reading the form: {e:?}"))?;
        if n == 0 {
            break;
        }
        anyhow::ensure!(body.len() + n <= MAX_FORM, "form over {MAX_FORM} bytes");
        body.extend_from_slice(&buf[..n]);
    }
    Ok(String::from_utf8(body)?)
}

fn respond(req: Request<&mut EspHttpConnection>, status: u16, html: &str) -> Result<()> {
    let headers = [("content-type", "text/html; charset=utf-8"), ("cache-control", "no-store")];
    req.into_response(status, None, &headers)?.write_all(html.as_bytes())?;
    Ok(())
}
