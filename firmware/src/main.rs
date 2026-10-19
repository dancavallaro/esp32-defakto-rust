mod attest;
mod button;
mod config;
mod console;
#[cfg(not(feature = "xiao"))]
mod display;
mod http;
mod net;
mod setup;
mod tee;
#[cfg(not(feature = "xiao"))]
mod touch;
#[cfg(not(feature = "xiao"))]
mod ui;
mod worker;

use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::Result;
use demo::app::{App, Event, Provisioning, Screen, Status};
use demo::flow;
use demo::gesture::{Detector, Gesture};
use demo::setup::Settings;
use demo::pacing::Pacer;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::modem::Modem;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use log::{error, info, warn};

use crate::attest::Attestors;
use crate::config::CONFIG;
use crate::http::EspClient;
use crate::worker::{Active, EspClock, Worker};

const POLL: Duration = Duration::from_millis(20);
const RESTART_DELAY: Duration = Duration::from_secs(5);
/// How long after boot a press can start that, held, opens the setup wizard.
const SETUP_HOLD_WINDOW: Duration = Duration::from_secs(1);
/// Long enough for the portal's "saved" page to reach the phone.
const SAVED_RESTART_DELAY: Duration = Duration::from_secs(2);
/// How long the DevID check's outcome stays on screen before the restart.
const PROVISIONED_DELAY: Duration = Duration::from_secs(6);

// Puts the crate version in the image header, which the TEE reports as `sw_claims.app.ver`.
esp_idf_svc::sys::esp_app_desc!();

fn main() {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    info!("demo-firmware {}", env!("CARGO_PKG_VERSION"));

    // A demo nobody can fix on the spot is better off retrying than sitting
    // on a dark screen, e.g. while the hotspot comes up.
    if let Err(e) = run() {
        error!("{e:#}; restarting in {} s", RESTART_DELAY.as_secs());
        std::thread::sleep(RESTART_DELAY);
        unsafe { esp_idf_svc::sys::esp_restart() };
    }
}

fn run() -> Result<()> {
    let peripherals = Peripherals::take()?;
    let sysloop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    #[cfg(feature = "xiao")]
    let _antenna = xiao::enable_antenna(peripherals.pins.gpio3, peripherals.pins.gpio14)?;

    #[cfg(not(feature = "xiao"))]
    let mut screens = Screens::new(ui::Ui::new(display::Display::new(
        peripherals.spi2,
        display::Pins {
            sclk: peripherals.pins.gpio1,
            mosi: peripherals.pins.gpio2,
            cs: peripherals.pins.gpio14,
            dc: peripherals.pins.gpio15,
            rst: peripherals.pins.gpio22,
            backlight: peripherals.pins.gpio23,
        },
        peripherals.ledc.timer0,
        peripherals.ledc.channel0,
    )?));
    #[cfg(feature = "xiao")]
    let mut screens = Screens::new();

    let mut button = button::Button::new(peripherals.pins.gpio9)?;
    #[cfg(not(feature = "xiao"))]
    let mut touch = touch::Touch::new(
        peripherals.i2c0,
        peripherals.pins.gpio18,
        peripherals.pins.gpio19,
        peripherals.pins.gpio20,
    )?;

    if let Some(pending) = config::take_pending(&nvs) {
        provision(peripherals.modem, sysloop, nvs, pending, &mut screens);
    }

    let settings = config::load(&nvs);
    let cfg = settings.flow_config();
    let mut app = App::new(Status::default());
    app.checks_in = cfg.checkin_url.is_some();
    screens.show(&app);

    #[cfg(not(feature = "xiao"))]
    let held = held_at_boot(|| button.is_down() || touch.is_down().unwrap_or(false));
    #[cfg(feature = "xiao")]
    let held = held_at_boot(|| button.is_down());
    let problem = config::take_problem(&nvs);
    let why = match &problem {
        Some(problem) => Some(format!("the last settings were refused: {problem}")),
        None if held => Some("held at boot".into()),
        None => settings.validate().err(),
    };
    if let Some(why) = why {
        info!("setting up: {why}");
        let wizard = setup::Wizard { current: settings, gate: config::devid_gate(), problem };
        return run_wizard(peripherals.modem, sysloop, nvs, wizard, &mut screens);
    }

    // After the wizard's chance to run, so settings whose only attestor is
    // broken can still be changed.
    let attestors =
        Attestors::new(settings.device_id.clone(), CONFIG.efuse_hmac_key, settings.enabled_attestors(), nvs.clone());
    let (kind, attestor) = attestors.build_any(&attestors.saved(CONFIG.default_attestor))?;
    app.status.attestor = attestor.label().to_string();
    app.switchable = attestors.switchable();
    screens.show(&app);

    let net = net::connect(peripherals.modem, sysloop, nvs.clone(), &settings.wifi_ssid, &settings.wifi_psk)?;
    info!("time {} (unix)", net::unix_now());
    app.status.wifi = true;
    screens.show(&app);

    info!("free heap {} B before attesting", free_heap());
    match flow::fetch_svid(&mut EspClient, &cfg, attestor.as_ref(), flow_now(), &worker::nonce()) {
        Ok(svid) => {
            info!("attested as {}", svid.spiffe_id);
            app.status.svid = true;
        }
        Err(e) => warn!("boot attestation failed: {e}"),
    }
    info!("free heap {} B after, low-water {} B", free_heap(), min_free_heap());
    screens.show(&app);

    let (events_tx, events) = mpsc::channel();
    let worker = Worker::spawn(cfg, attestors, Active { kind, attestor }, events_tx)?;
    let mut pacer = Pacer::default();
    let epoch = Instant::now();

    loop {
        let (screen, status) = (app.screen.clone(), app.status.clone());
        app.status.wifi = net.is_up();
        #[cfg(not(feature = "xiao"))]
        let gesture = touch.poll().unwrap_or_else(|e| {
            warn!("reading touch failed: {e}");
            None
        });
        #[cfg(feature = "xiao")]
        let gesture = None;
        if button.pressed() || gesture == Some(Gesture::Tap) {
            worker.send(app.handle(Event::Tap));
        }
        if gesture == Some(Gesture::LongPress) {
            worker.send(app.handle(Event::LongPress));
        }
        while let Ok(ev) = events.try_recv() {
            pacer.push(ev);
        }
        while let Some(ev) = pacer.next(&app.screen, epoch.elapsed()) {
            worker.send(app.handle(ev));
        }
        if app.screen != screen || app.status != status {
            screens.show(&app);
        } else {
            screens.animate(&app);
        }
        std::thread::sleep(POLL);
    }
}

/// Whether a press that starts within `SETUP_HOLD_WINDOW` of boot is held
/// into a long press, which reruns the setup wizard.
fn held_at_boot(mut down: impl FnMut() -> bool) -> bool {
    let mut detector = Detector::default();
    let start = Instant::now();
    loop {
        let is_down = down();
        if detector.update(is_down, start.elapsed()) == Some(Gesture::LongPress) {
            return true;
        }
        if !is_down && start.elapsed() > SETUP_HOLD_WINDOW {
            return false;
        }
        std::thread::sleep(POLL);
    }
}

/// Serves the setup wizard until it saves new settings, then restarts with them.
fn run_wizard(
    modem: Modem<'static>,
    sysloop: EspSystemEventLoop,
    nvs: EspDefaultNvsPartition,
    wizard: setup::Wizard,
    screens: &mut Screens,
) -> Result<()> {
    let (portal, saved) = setup::start(modem, sysloop, nvs, wizard)?;
    let mut app = App::new(Status::default());
    app.screen = Screen::Setup { ssid: portal.ssid.clone(), password: portal.password.clone(), portal: portal.url.clone() };
    screens.show(&app);
    let _ = saved.recv();
    app.screen = Screen::Restarting;
    screens.show(&app);
    std::thread::sleep(SAVED_RESTART_DELAY);
    restart();
}

/// Joins the network the wizard's pending settings name and checks the DevID
/// that came with them, keeping them only if it passes. Then restarts, into
/// the demo or back into the wizard.
fn provision(
    modem: Modem<'static>,
    sysloop: EspSystemEventLoop,
    nvs: EspDefaultNvsPartition,
    (pending, devid): (Settings, String),
    screens: &mut Screens,
) -> ! {
    let mut app = App::new(Status::default());
    app.screen = Screen::Provisioning(Provisioning::Checking);
    screens.show(&app);
    let outcome = check_devid(modem, sysloop, nvs.clone(), &pending, &devid)
        .and_then(|user| config::save(&nvs, &pending).map(|_| user).map_err(|e| format!("{e:#}")));
    app.screen = Screen::Provisioning(match outcome {
        Ok(user) => {
            info!("took the settings from {user}");
            Provisioning::Configured(user)
        }
        Err(why) => {
            warn!("refused the settings: {why}");
            if let Err(e) = config::save_problem(&nvs, &why) {
                warn!("saving why failed: {e:#}");
            }
            Provisioning::Refused(why)
        }
    });
    screens.show(&app);
    std::thread::sleep(PROVISIONED_DELAY);
    restart();
}

/// The SPIFFE ID of the user whose DevID vouches for `pending`.
fn check_devid(
    modem: Modem<'static>,
    sysloop: EspSystemEventLoop,
    nvs: EspDefaultNvsPartition,
    pending: &Settings,
    devid: &str,
) -> Result<String, String> {
    let gate = config::devid_gate().ok_or("this build has no DevID issuer")?;
    let _net = net::connect(modem, sysloop, nvs, &pending.wifi_ssid, &pending.wifi_psk)
        .map_err(|e| format!("couldn't join {:?}: {e:#}", pending.wifi_ssid))?;
    gate.check(&mut EspClient, devid, &pending.device_id, flow_now())
}

fn restart() -> ! {
    unsafe { esp_idf_svc::sys::esp_restart() }
}

/// Where screens go: the serial console always, since it also carries the QR
/// code as text, and the LCD on boards that have one.
struct Screens {
    #[cfg(not(feature = "xiao"))]
    lcd: ui::Ui,
}

impl Screens {
    #[cfg(not(feature = "xiao"))]
    fn new(lcd: ui::Ui) -> Self {
        Self { lcd }
    }

    #[cfg(feature = "xiao")]
    fn new() -> Self {
        Self {}
    }

    fn show(&mut self, app: &App) {
        console::render(&app.screen, &app.status);
        #[cfg(not(feature = "xiao"))]
        if let Err(e) = self.lcd.render(&app.screen, &app.status, flow_now()) {
            warn!("drawing the screen failed: {e}");
        }
    }

    fn animate(&mut self, _app: &App) {
        #[cfg(not(feature = "xiao"))]
        if let Err(e) = self.lcd.animate(&_app.screen, &_app.status, flow_now()) {
            warn!("drawing the screen failed: {e}");
        }
    }
}

fn flow_now() -> i64 {
    use demo::flow::Clock;
    EspClock.unix_now()
}

fn free_heap() -> u32 {
    unsafe { esp_idf_svc::sys::esp_get_free_heap_size() }
}

fn min_free_heap() -> u32 {
    unsafe { esp_idf_svc::sys::esp_get_minimum_free_heap_size() }
}

#[cfg(feature = "xiao")]
mod xiao {
    use anyhow::Result;
    use esp_idf_svc::hal::gpio::{Gpio14, Gpio3, Output, PinDriver};

    pub type Antenna = (PinDriver<'static, Output>, PinDriver<'static, Output>);

    /// The XIAO routes the radio through an RF switch: GPIO3 low powers it and
    /// GPIO14 low picks the built-in ceramic antenna. Dropping the drivers would
    /// release the pins, so the caller holds them for the program's lifetime.
    pub fn enable_antenna(power: Gpio3<'static>, select: Gpio14<'static>) -> Result<Antenna> {
        let mut power = PinDriver::output(power)?;
        power.set_low()?;
        std::thread::sleep(std::time::Duration::from_millis(100));
        let mut select = PinDriver::output(select)?;
        select.set_low()?;
        Ok((power, select))
    }
}
