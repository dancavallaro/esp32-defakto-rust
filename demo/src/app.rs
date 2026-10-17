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
}

#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    Idle,
    Starting,
    Qr { uri: String, verification_uri: String, user_code: String, issued_at: i64, expires_at: i64 },
    Progress(Progress),
    Result(DisplayClaims),
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Status {
    pub wifi: bool,
    pub svid: bool,
    pub attestor: String,
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
}

impl App {
    pub fn new(status: Status) -> Self {
        Self { screen: Screen::Idle, status }
    }

    /// Events that don't fit the current screen are ignored: they come from a
    /// login the user already cancelled.
    pub fn handle(&mut self, ev: Event) -> Command {
        use Screen::*;
        if let Event::AttestorChanged { label, svid } = ev {
            self.status.attestor = label;
            self.status.svid = svid;
            return Command::None;
        }
        let in_flight = matches!(self.screen, Starting | Qr { .. } | Progress(_));
        let (next, cmd) = match (&self.screen, ev) {
            (Idle, Event::Tap) => (Starting, Command::StartLogin),
            (Idle, Event::LongPress) => (Idle, Command::SwitchAttestor),
            (Qr { .. }, Event::Tap) => (Idle, Command::Cancel),
            (Result(_) | Error(_), Event::Tap) => (Idle, Command::None),
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
                }),
                Command::None,
            ),
            (Progress(p), Event::SvidReady) => (
                Progress(self::Progress { got_svid: Step::Done, exchanged: Step::Active, ..p.clone() }),
                Command::None,
            ),
            (Progress(_), Event::Exchanged(claims)) => (Result(claims), Command::None),
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
        Screen::Progress(Progress { attested: Step::Done, signed_in: Step::Done, got_svid, exchanged })
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
        assert_eq!(app.screen, Screen::Result(claims()));

        assert_eq!(app.handle(Event::Tap), Command::None);
        assert_eq!(app.screen, Screen::Idle);
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
        let mut app = App::new(Status { wifi: true, svid: true, attestor: "eFuse HMAC".into() });
        assert_eq!(app.handle(Event::AttestorChanged { label: "eFuse HMAC".into(), svid: false }), Command::None);
        assert_eq!(app.status, Status { wifi: true, svid: false, attestor: "eFuse HMAC".into() });
        assert_eq!(app.screen, Screen::Idle);
    }
}
