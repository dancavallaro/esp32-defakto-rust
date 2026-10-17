//! Turns touch samples (finger down or not) into taps and long presses.

use std::time::Duration;

pub const LONG_PRESS: Duration = Duration::from_millis(1500);

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Gesture {
    Tap,
    LongPress,
}

#[derive(Debug, Default)]
pub struct Detector {
    pressed_at: Option<Duration>,
    long_sent: bool,
}

impl Detector {
    /// Feeds one sample taken at `now` (any monotonic clock).
    pub fn update(&mut self, down: bool, now: Duration) -> Option<Gesture> {
        match (down, self.pressed_at) {
            (true, None) => {
                self.pressed_at = Some(now);
                self.long_sent = false;
                None
            }
            (true, Some(at)) if !self.long_sent && now - at >= LONG_PRESS => {
                self.long_sent = true;
                Some(Gesture::LongPress)
            }
            (false, Some(_)) => {
                self.pressed_at = None;
                (!self.long_sent).then_some(Gesture::Tap)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// Feeds `(down, at_ms)` samples and collects what they produce.
    fn run(samples: &[(bool, u64)]) -> Vec<Gesture> {
        let mut d = Detector::default();
        samples.iter().filter_map(|&(down, at)| d.update(down, ms(at))).collect()
    }

    #[test]
    fn short_press_is_one_tap_on_release() {
        assert_eq!(run(&[(false, 0), (true, 30), (true, 60), (true, 90)]), vec![]);
        assert_eq!(run(&[(true, 30), (true, 60), (false, 90), (false, 120)]), vec![Gesture::Tap]);
    }

    #[test]
    fn long_hold_is_one_long_press_and_no_tap() {
        let hold: Vec<_> = (0..=70).map(|i| (true, i * 30)).chain([(false, 2130)]).collect();
        assert_eq!(run(&hold), vec![Gesture::LongPress]);
    }

    #[test]
    fn long_press_fires_at_the_threshold_not_on_release() {
        let mut d = Detector::default();
        assert_eq!(d.update(true, ms(0)), None);
        assert_eq!(d.update(true, ms(1499)), None);
        assert_eq!(d.update(true, ms(1500)), Some(Gesture::LongPress));
    }

    #[test]
    fn presses_after_a_long_press_still_tap() {
        assert_eq!(
            run(&[(true, 0), (true, 1600), (false, 1700), (true, 2000), (false, 2100)]),
            vec![Gesture::LongPress, Gesture::Tap]
        );
    }

    #[test]
    fn nothing_without_contact() {
        assert_eq!(run(&[(false, 0), (false, 5000)]), vec![]);
    }
}
