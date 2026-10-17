//! Runs the network steps off the UI loop: TLS handshakes need a big stack,
//! and polling for sign-in blocks for minutes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

use defakto::attest::Attestor;
use demo::app::{Command, Event};
use demo::flow::{self, Clock, Config, FlowError};

use crate::http::EspClient;
use crate::net;

const STACK_SIZE: usize = 24 * 1024;

pub struct Worker {
    commands: Sender<Command>,
    cancel: Arc<AtomicBool>,
}

impl Worker {
    pub fn spawn(cfg: Config, attestor: Box<dyn Attestor>, events: Sender<Event>) -> anyhow::Result<Self> {
        let (commands, inbox) = std::sync::mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        std::thread::Builder::new()
            .name("worker".into())
            .stack_size(STACK_SIZE)
            .spawn(move || run(cfg, attestor, inbox, events, flag))?;
        Ok(Self { commands, cancel })
    }

    /// `Cancel` is a flag rather than a message because the worker is busy
    /// polling, not reading its inbox, when it matters.
    pub fn send(&self, cmd: Command) {
        match cmd {
            Command::None => {}
            Command::Cancel => self.cancel.store(true, Ordering::SeqCst),
            Command::StartLogin => {
                let _ = self.commands.send(cmd);
            }
        }
    }
}

fn run(cfg: Config, attestor: Box<dyn Attestor>, inbox: Receiver<Command>, events: Sender<Event>, cancel: Arc<AtomicBool>) {
    for cmd in inbox {
        if cmd != Command::StartLogin {
            continue;
        }
        cancel.store(false, Ordering::SeqCst);
        match login(&cfg, attestor.as_ref(), &events, &cancel) {
            Ok(()) | Err(FlowError::Cancelled) => {}
            Err(e) => {
                let _ = events.send(Event::Failed(e.to_string()));
            }
        }
    }
}

fn login(cfg: &Config, attestor: &dyn Attestor, events: &Sender<Event>, cancel: &AtomicBool) -> Result<(), FlowError> {
    let http = &mut EspClient;
    let auth = flow::start_login(http, cfg)?;
    let _ = events.send(Event::LoginStarted { auth: auth.clone(), now: EspClock.unix_now() });
    let id_token = flow::wait_for_id_token(http, cfg, &auth, &mut EspClock, &|| cancel.load(Ordering::SeqCst))?;
    let _ = events.send(Event::SignedIn);
    let svid = flow::fetch_svid(http, cfg, attestor, EspClock.unix_now(), &nonce())?;
    let _ = events.send(Event::SvidReady);
    let claims = flow::exchange(http, cfg, &id_token, &svid)?;
    let _ = events.send(Event::Exchanged(claims));
    Ok(())
}

/// Only random once the radio is on, which it is by the time anything attests.
pub fn nonce() -> String {
    defakto::evidence::new_nonce(|b| unsafe { esp_idf_svc::sys::esp_fill_random(b.as_mut_ptr().cast(), b.len()) })
}

pub struct EspClock;

impl Clock for EspClock {
    fn unix_now(&self) -> i64 {
        net::unix_now() as i64
    }
    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}
