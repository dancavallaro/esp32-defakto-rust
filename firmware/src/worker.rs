//! Runs the network steps off the UI loop: TLS handshakes need a big stack,
//! and polling for sign-in blocks for minutes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

use defakto::attest::Attestor;
use demo::app::{Command, Event};
use demo::flow::{self, Clock, Config, FlowError};

use log::{info, warn};

use crate::attest::{self, Attestors};
use crate::http::EspClient;
use crate::net;

const STACK_SIZE: usize = 24 * 1024;

pub struct Worker {
    commands: Sender<Command>,
    cancel: Arc<AtomicBool>,
}

impl Worker {
    pub fn spawn(cfg: Config, attestors: Attestors, active: Active, events: Sender<Event>) -> anyhow::Result<Self> {
        let (commands, inbox) = std::sync::mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        std::thread::Builder::new()
            .name("worker".into())
            .stack_size(STACK_SIZE)
            .spawn(move || run(cfg, attestors, active, inbox, events, flag))?;
        Ok(Self { commands, cancel })
    }

    /// `Cancel` is a flag rather than a message because the worker is busy
    /// polling, not reading its inbox, when it matters.
    pub fn send(&self, cmd: Command) {
        match cmd {
            Command::None => {}
            Command::Cancel => self.cancel.store(true, Ordering::SeqCst),
            Command::StartLogin | Command::SwitchAttestor => {
                let _ = self.commands.send(cmd);
            }
        }
    }
}

/// The attestor in use and the kind it was built from.
pub struct Active {
    pub kind: String,
    pub attestor: Box<dyn Attestor>,
}

fn run(
    cfg: Config,
    attestors: Attestors,
    mut active: Active,
    inbox: Receiver<Command>,
    events: Sender<Event>,
    cancel: Arc<AtomicBool>,
) {
    for cmd in inbox {
        match cmd {
            Command::StartLogin => {
                cancel.store(false, Ordering::SeqCst);
                match login(&cfg, active.attestor.as_ref(), &events, &cancel) {
                    Ok(()) | Err(FlowError::Cancelled) => {}
                    Err(e) => {
                        let _ = events.send(Event::Failed(e.to_string()));
                    }
                }
            }
            Command::SwitchAttestor => match switch(&cfg, &attestors, &mut active) {
                Ok(svid) => {
                    let label = active.attestor.label().to_owned();
                    let _ = events.send(Event::AttestorChanged { label, svid });
                }
                Err(e) => warn!("switching attestor failed: {e:#}"),
            },
            Command::None | Command::Cancel => {}
        }
    }
}

/// Moves to the next attestor and re-attests with it, returning whether that
/// worked. The choice is kept either way, so the screen shows a failing
/// backend as unattested instead of hiding it.
fn switch(cfg: &Config, attestors: &Attestors, active: &mut Active) -> anyhow::Result<bool> {
    let kind = attest::next(&active.kind);
    *active = Active { kind: kind.to_owned(), attestor: attestors.build(kind)? };
    attestors.save(kind)?;
    match flow::fetch_svid(&mut EspClient, cfg, active.attestor.as_ref(), EspClock.unix_now(), &nonce()) {
        Ok(svid) => {
            info!("attested with {} as {}", active.attestor.label(), svid.spiffe_id);
            Ok(true)
        }
        Err(e) => {
            warn!("attesting with {} failed: {e}", active.attestor.label());
            Ok(false)
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
    info!("free heap {} B after sign-in, low-water {} B", crate::free_heap(), crate::min_free_heap());
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
