//! Holds flow events back so each step of the progress checklist stays on
//! screen long enough to read. The flow itself isn't slowed, only what's shown.

use std::collections::VecDeque;
use std::time::Duration;

use crate::app::{Event, Screen};

pub const STEP_DWELL: Duration = Duration::from_millis(2000);

#[derive(Default)]
pub struct Pacer {
    queue: VecDeque<Event>,
    shown: Option<Screen>,
    shown_at: Duration,
}

impl Pacer {
    pub fn push(&mut self, ev: Event) {
        self.queue.push_back(ev);
    }

    /// The next event to hand to the app, given what's on `screen` at `now`.
    pub fn next(&mut self, screen: &Screen, now: Duration) -> Option<Event> {
        if self.shown.as_ref() != Some(screen) {
            self.shown = Some(screen.clone());
            self.shown_at = now;
        }
        let holding = matches!(screen, Screen::Progress(_)) && now - self.shown_at < STEP_DWELL;
        if holding {
            None
        } else {
            self.queue.pop_front()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{Progress, Step};

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn progress(got_svid: Step) -> Screen {
        Screen::Progress(Progress { attested: Step::Done, signed_in: Step::Done, got_svid, exchanged: Step::Pending })
    }

    #[test]
    fn events_pass_straight_through_off_the_checklist() {
        let mut p = Pacer::default();
        p.push(Event::SignedIn);
        assert_eq!(p.next(&Screen::Starting, ms(0)), Some(Event::SignedIn));
        assert_eq!(p.next(&Screen::Starting, ms(0)), None);
    }

    #[test]
    fn checklist_steps_stay_up_for_the_dwell() {
        let mut p = Pacer::default();
        assert_eq!(p.next(&progress(Step::Active), ms(5000)), None);
        p.push(Event::SvidReady);
        assert_eq!(p.next(&progress(Step::Active), ms(5100)), None);
        assert_eq!(p.next(&progress(Step::Active), ms(6999)), None);
        assert_eq!(p.next(&progress(Step::Active), ms(7000)), Some(Event::SvidReady));
    }

    #[test]
    fn each_new_step_restarts_the_dwell() {
        let mut p = Pacer::default();
        p.next(&progress(Step::Active), ms(0));
        p.push(Event::SvidReady);
        p.push(Event::Failed("x".into()));
        assert_eq!(p.next(&progress(Step::Active), ms(2000)), Some(Event::SvidReady));
        assert_eq!(p.next(&progress(Step::Done), ms(2000)), None);
        assert_eq!(p.next(&progress(Step::Done), ms(3999)), None);
        assert_eq!(p.next(&progress(Step::Done), ms(4000)), Some(Event::Failed("x".into())));
    }

    #[test]
    fn a_step_already_shown_long_enough_releases_at_once() {
        let mut p = Pacer::default();
        p.next(&progress(Step::Active), ms(0));
        p.push(Event::SvidReady);
        assert_eq!(p.next(&progress(Step::Active), ms(3000)), Some(Event::SvidReady));
    }
}
