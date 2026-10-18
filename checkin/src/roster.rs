//! Who has checked in, once per user, newest first.

use serde::Serialize;

use crate::verify::Attendee;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Entry {
    #[serde(flatten)]
    pub attendee: Attendee,
    /// Unix seconds.
    pub first_seen: i64,
    pub last_seen: i64,
    pub check_ins: u32,
}

#[derive(Default)]
pub struct Roster(Vec<Entry>);

impl Roster {
    /// Records a check-in, returning the attendee's entry and whether they're new.
    /// A user is the same user if their IdP and subject match.
    pub fn record(&mut self, attendee: Attendee, now: i64) -> (Entry, bool) {
        let same_user = |e: &Entry| e.attendee.user_iss == attendee.user_iss && e.attendee.user_sub == attendee.user_sub;
        match self.0.iter_mut().find(|e| same_user(e)) {
            Some(entry) => {
                entry.attendee = attendee;
                entry.last_seen = now;
                entry.check_ins += 1;
                (entry.clone(), false)
            }
            None => {
                let entry = Entry { attendee, first_seen: now, last_seen: now, check_ins: 1 };
                self.0.insert(0, entry.clone());
                (entry, true)
            }
        }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attendee(sub: &str, iss: &str) -> Attendee {
        Attendee {
            name: None,
            email: None,
            user_sub: sub.into(),
            user_iss: iss.into(),
            device: "spiffe://example.org/iot/badge-reader".into(),
            txn: None,
        }
    }

    #[test]
    fn new_users_go_first() {
        let mut roster = Roster::default();
        assert!(roster.record(attendee("a", "idp"), 10).1);
        assert!(roster.record(attendee("b", "idp"), 20).1);
        let subs: Vec<_> = roster.entries().iter().map(|e| e.attendee.user_sub.as_str()).collect();
        assert_eq!(subs, ["b", "a"]);
    }

    #[test]
    fn a_repeat_check_in_updates_the_entry() {
        let mut roster = Roster::default();
        roster.record(attendee("a", "idp"), 10);
        let (entry, new) = roster.record(attendee("a", "idp"), 30);
        assert!(!new);
        assert_eq!((entry.first_seen, entry.last_seen, entry.check_ins), (10, 30, 2));
        assert_eq!(roster.entries().len(), 1);
    }

    #[test]
    fn the_same_subject_from_another_idp_is_another_user() {
        let mut roster = Roster::default();
        roster.record(attendee("a", "idp-1"), 10);
        assert!(roster.record(attendee("a", "idp-2"), 20).1);
    }
}
