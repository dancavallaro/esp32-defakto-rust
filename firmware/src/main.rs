mod attest;
mod button;
mod config;
mod console;
#[cfg(not(feature = "xiao"))]
mod display;
mod http;
mod net;
mod tee;
#[cfg(not(feature = "xiao"))]
mod touch;
#[cfg(not(feature = "xiao"))]
mod ui;
mod worker;

use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::Result;
use demo::app::{App, Event, Status};
use demo::flow;
use demo::gesture::Gesture;
use demo::pacing::Pacer;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use log::{error, info, warn};

use crate::attest::Attestors;
use crate::config::CONFIG;
use crate::http::EspClient;
use crate::worker::{Active, EspClock, Worker};

const POLL: Duration = Duration::from_millis(20);
const RESTART_DELAY: Duration = Duration::from_secs(5);

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

    let cfg = config::flow_config();
    let attestors = Attestors::new(CONFIG.device_id, CONFIG.efuse_hmac_key, nvs.clone());
    let kind = attestors.saved(CONFIG.default_attestor);
    let attestor = attestors.build(&kind)?;
    let mut app = App::new(Status { wifi: false, svid: false, attestor: attestor.label().to_string() });
    screens.show(&app);

    let _net = net::connect(peripherals.modem, sysloop, nvs.clone())?;
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
    let mut button = button::Button::new(peripherals.pins.gpio9)?;
    #[cfg(not(feature = "xiao"))]
    let mut touch = touch::Touch::new(
        peripherals.i2c0,
        peripherals.pins.gpio18,
        peripherals.pins.gpio19,
        peripherals.pins.gpio20,
    )?;
    let mut pacer = Pacer::default();
    let epoch = Instant::now();

    loop {
        let (screen, status) = (app.screen.clone(), app.status.clone());
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
