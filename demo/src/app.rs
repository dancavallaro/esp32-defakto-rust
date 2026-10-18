//! The demo's screens and how taps and flow events move between them. The
//! firmware renders `App::screen` and carries out the returned `Command`s.

use crate::claims::DisplayClaims;
use crate::login::DeviceAuthorization;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Step {
    Pending,
    Active,
    Done,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Progress {
    pub attested: Step,
    pub signed_in: Step,
    pub got_svid: Step,
    pub exchanged: Step,
    /// `None` when no check-in service is configured.
    pub checked_in: Option<Step>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    Idle,
    Starting,
    Qr { uri: String, verification_uri: String, user_code: String, issued_at: i64, expires_at: i64 },
    Progress(Progress),
    Result { claims: DisplayClaims, checked_in: bool },
    Error(String),
    /// The setup wizard's network, and the portal it serves.
    Setup { ssid: String, password: String, portal: String },
    /// The wizard saved new settings and the device is restarting.
    Restarting,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Status {
    pub wifi: bool,
    pub svid: bool,
    pub attestor: String,
    /// A long press is re-attesting with the next attestor.
    pub switching: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Tap,
    LongPress,
    /// The worker switched attestors and re-attested with the new one.
    AttestorChanged { label: String, svid: bool },
    LoginStarted { auth: DeviceAuthorization, now: i64 },
    SignedIn,
    SvidReady,
    Exchanged(DisplayClaims),
    /// The check-in service accepted the OBO token.
    CheckedIn(DisplayClaims),
    /// The sign-in code expired before anyone used it.
    Expired,
    Failed(String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Command {
    None,
    StartLogin,
    Cancel,
    SwitchAttestor,
}

pub struct App {
    pub screen: Screen,
    pub status: Status,
    /// Whether a sign-in ends by recording a check-in.
    pub checks_in: bool,
}

impl App {
    pub fn new(status: Status) -> Self {
        Self { screen: Screen::Idle, status, checks_in: false }
    }

    /// Events that don't fit the current screen are ignored: they come from a
    /// login the user already cancelled.
    pub fn handle(&mut self, ev: Event) -> Command {
        use Screen::*;
        if let Event::AttestorChanged { label, svid } = ev {
            self.status.attestor = label;
            self.status.svid = svid;
            self.status.switching = false;
            return Command::None;
        }
        let in_flight = matches!(self.screen, Starting | Qr { .. } | Progress(_));
        let (next, cmd) = match (&self.screen, ev) {
            (Idle, Event::Tap) => (Starting, Command::StartLogin),
            (Idle, Event::LongPress) if !self.status.switching => {
                self.status.switching = true;
                (Idle, Command::SwitchAttestor)
            }
            (Qr { .. }, Event::Tap) => (Idle, Command::Cancel),
            (Result { .. } | Error(_), Event::Tap) => (Idle, Command::None),
            (Starting, Event::LoginStarted { auth, now }) => (
                Qr {
                    uri: auth.verification_uri_complete.unwrap_or_else(|| auth.verification_uri.clone()),
                    verification_uri: auth.verification_uri,
                    user_code: auth.user_code,
                    issued_at: now,
                    expires_at: now + auth.expires_in as i64,
                },
                Command::None,
            ),
            (Qr { .. }, Event::SignedIn) => (
                Progress(self::Progress {
                    attested: Step::Done,
                    signed_in: Step::Done,
                    got_svid: Step::Active,
                    exchanged: Step::Pending,
                    checked_in: self.checks_in.then_some(Step::Pending),
                }),
                Command::None,
            ),
            (Progress(p), Event::SvidReady) => (
                Progress(self::Progress { got_svid: Step::Done, exchanged: Step::Active, ..p.clone() }),
                Command::None,
            ),
            (Progress(p), Event::Exchanged(claims)) => match p.checked_in {
                Some(_) => (
                    Progress(self::Progress { exchanged: Step::Done, checked_in: Some(Step::Active), ..p.clone() }),
                    Command::None,
                ),
                None => (Result { claims, checked_in: false }, Command::None),
            },
            (Progress(_), Event::CheckedIn(claims)) => (Result { claims, checked_in: true }, Command::None),
            (Qr { .. }, Event::Expired) => (Idle, Command::None),
            // A login nobody is looking at, e.g. one queued behind a cancelled run.
            (Idle | Result { .. } | Error(_), Event::LoginStarted { .. }) => return Command::Cancel,
            (_, Event::Failed(msg)) if in_flight => (Error(msg), Command::None),
            _ => return Command::None,
        };
        self.screen = next;
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> DeviceAuthorization {
        DeviceAuthorization {
            device_code: "dc".into(),
            user_code: "WDJB-MJHT".into(),
            verification_uri: "https://t/activate".into(),
            verification_uri_complete: Some("https://t/activate?user_code=WDJB-MJHT".into()),
            expires_in: 300,
            interval: None,
        }
    }

    fn claims() -> DisplayClaims {
        DisplayClaims {
            greeting: "Hi, Alice!".into(),
            email: Some("alice@example.com".into()),
            user_sub: "u".into(),
            user_iss: "i".into(),
            actor: "spiffe://p/iot/defakto-demo".into(),
            txn: None,
            exp: 0,
        }
    }

    fn progress(got_svid: Step, exchanged: Step) -> Screen {
        Screen::Progress(Progress { attested: Step::Done, signed_in: Step::Done, got_svid, exchanged, checked_in: None })
    }

    fn result(checked_in: bool) -> Screen {
        Screen::Result { claims: claims(), checked_in }
    }

    fn started() -> Event {
        Event::LoginStarted { auth: auth(), now: 1000 }
    }

    #[test]
    fn happy_path() {
        let mut app = App::new(Status::default());
        assert_eq!(app.handle(Event::Tap), Command::StartLogin);
        assert_eq!(app.screen, Screen::Starting);

        assert_eq!(app.handle(started()), Command::None);
        assert_eq!(
            app.screen,
            Screen::Qr {
                uri: "https://t/activate?user_code=WDJB-MJHT".into(),
                verification_uri: "https://t/activate".into(),
                user_code: "WDJB-MJHT".into(),
                issued_at: 1000,
                expires_at: 1300,
            }
        );

        app.handle(Event::SignedIn);
        assert_eq!(app.screen, progress(Step::Active, Step::Pending));
        app.handle(Event::SvidReady);
        assert_eq!(app.screen, progress(Step::Done, Step::Active));
        app.handle(Event::Exchanged(claims()));
        assert_eq!(app.screen, result(false));

        assert_eq!(app.handle(Event::Tap), Command::None);
        assert_eq!(app.screen, Screen::Idle);
    }

    #[test]
    fn check_in_follows_the_exchange() {
        let mut app = App::new(Status::default());
        app.checks_in = true;
        app.handle(Event::Tap);
        app.handle(started());
        app.handle(Event::SignedIn);
        app.handle(Event::SvidReady);
        let Screen::Progress(p) = &app.screen else { panic!("{:?}", app.screen) };
        assert_eq!((p.exchanged, p.checked_in), (Step::Active, Some(Step::Pending)));

        app.handle(Event::Exchanged(claims()));
        let Screen::Progress(p) = &app.screen else { panic!("{:?}", app.screen) };
        assert_eq!((p.exchanged, p.checked_in), (Step::Done, Some(Step::Active)));

        app.handle(Event::CheckedIn(claims()));
        assert_eq!(app.screen, result(true));
    }

    #[test]
    fn qr_falls_back_to_plain_uri() {
        let mut app = App::new(Status::default());
        app.handle(Event::Tap);
        let mut a = auth();
        a.verification_uri_complete = None;
        app.handle(Event::LoginStarted { auth: a, now: 0 });
        assert!(matches!(&app.screen, Screen::Qr { uri, .. } if uri == "https://t/activate"));
    }

    #[test]
    fn double_tap_starts_one_login() {
        let mut app = App::new(Status::default());
        assert_eq!([app.handle(Event::Tap), app.handle(Event::Tap)], [Command::StartLogin, Command::None]);
    }

    #[test]
    fn tap_ignored_during_progress() {
        let mut app = App::new(Status::default());
        app.screen = progress(Step::Active, Step::Pending);
        assert_eq!(app.handle(Event::Tap), Command::None);
        assert_eq!(app.screen, progress(Step::Active, Step::Pending));
    }

    #[test]
    fn qr_tap_cancels() {
        let mut app = App::new(Status::default());
        app.handle(Event::Tap);
        app.handle(started());
        assert_eq!(app.handle(Event::Tap), Command::Cancel);
        assert_eq!(app.screen, Screen::Idle);
    }

    #[test]
    fn late_login_after_cancel_ignored() {
        let mut app = App::new(Status::default());
        app.handle(Event::Tap);
        app.handle(started());
        app.handle(Event::Tap);
        app.handle(started());
        app.handle(Event::SignedIn);
        assert_eq!(app.screen, Screen::Idle);
    }

    #[test]
    fn error_tap_returns_idle() {
        let mut app = App::new(Status::default());
        app.handle(Event::Tap);
        app.handle(Event::Failed("network: timeout".into()));
        assert_eq!(app.screen, Screen::Error("network: timeout".into()));
        assert_eq!(app.handle(Event::Tap), Command::None);
        assert_eq!(app.screen, Screen::Idle);
    }

    #[test]
    fn failure_after_cancel_ignored() {
        let mut app = App::new(Status::default());
        app.handle(Event::Tap);
        app.handle(started());
        app.handle(Event::Tap);
        app.handle(Event::Failed("late".into()));
        assert_eq!(app.screen, Screen::Idle);
    }

    #[test]
    fn a_login_start_with_no_login_showing_is_cancelled() {
        for screen in [Screen::Idle, Screen::Error("x".into()), result(true)] {
            let mut app = App::new(Status::default());
            app.screen = screen.clone();
            assert_eq!(app.handle(started()), Command::Cancel);
            assert_eq!(app.screen, screen);
        }
    }

    #[test]
    fn expiry_returns_to_idle() {
        let mut app = App::new(Status::default());
        app.handle(Event::Tap);
        app.handle(started());
        assert_eq!(app.handle(Event::Expired), Command::None);
        assert_eq!(app.screen, Screen::Idle);
    }

    #[test]
    fn switching_shows_until_the_new_attestor_lands() {
        let mut app = App::new(Status { wifi: true, svid: true, attestor: "eFuse HMAC".into(), switching: false });
        app.handle(Event::LongPress);
        assert!(app.status.switching);
        assert_eq!(app.handle(Event::LongPress), Command::None, "a second press mid-switch");
        app.handle(Event::AttestorChanged { label: "ESP-TEE".into(), svid: true });
        assert_eq!(app.status, Status { wifi: true, svid: true, attestor: "ESP-TEE".into(), switching: false });
    }

    #[test]
    fn setup_ignores_input() {
        let mut app = App::new(Status::default());
        app.screen = Screen::Setup { ssid: "s".into(), password: "p".into(), portal: "http://192.168.4.1".into() };
        let before = app.screen.clone();
        for ev in [Event::Tap, Event::LongPress, Event::Failed("x".into()), started()] {
            app.handle(ev);
            assert_eq!(app.screen, before);
        }
    }

    #[test]
    fn long_press_on_idle_switches() {
        let mut app = App::new(Status::default());
        assert_eq!(app.handle(Event::LongPress), Command::SwitchAttestor);
        assert_eq!(app.screen, Screen::Idle);
    }

    #[test]
    fn long_press_elsewhere_ignored() {
        let mut app = App::new(Status::default());
        app.handle(Event::Tap);
        app.handle(started());
        assert_eq!(app.handle(Event::LongPress), Command::None);
        assert!(matches!(app.screen, Screen::Qr { .. }));
    }

    #[test]
    fn attestor_changed_updates_status() {
        let mut app = App::new(Status { wifi: true, svid: true, attestor: "eFuse HMAC".into(), switching: false });
        assert_eq!(app.handle(Event::AttestorChanged { label: "ESP-TEE".into(), svid: false }), Command::None);
        assert_eq!(app.status, Status { wifi: true, svid: false, attestor: "ESP-TEE".into(), switching: false });
        assert_eq!(app.screen, Screen::Idle);
    }
}
