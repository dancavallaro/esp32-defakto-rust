//! Check-ins that survive a restart: each check-in and reset is appended to a
//! JSON Lines journal, which is replayed into the roster at startup.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::roster::{Entry, Roster};
use crate::verify::Attendee;

#[derive(Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Line {
    CheckIn {
        at: i64,
        #[serde(flatten)]
        attendee: Attendee,
    },
    Reset {
        at: i64,
    },
}

/// The roster, kept in step with its journal when it has one.
pub struct CheckIns {
    roster: Roster,
    journal: Option<File>,
}

impl CheckIns {
    pub fn in_memory() -> Self {
        CheckIns { roster: Roster::default(), journal: None }
    }

    /// Opens the journal at `path`, creating it if it's missing, and replays it.
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut file = OpenOptions::new().read(true).append(true).create(true).open(path)?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        let mut roster = Roster::default();
        for (n, line) in text.lines().enumerate().filter(|(_, line)| !line.trim().is_empty()) {
            match serde_json::from_str(line) {
                Ok(Line::CheckIn { at, attendee }) => {
                    roster.record(attendee, at);
                }
                Ok(Line::Reset { .. }) => roster = Roster::default(),
                Err(e) => println!("{}:{}: skipping unreadable line: {e}", path.display(), n + 1),
            }
        }
        // A crash mid-write can leave a partial line; end it so the next line starts clean.
        if !text.is_empty() && !text.ends_with('\n') {
            file.write_all(b"\n")?;
        }
        Ok(CheckIns { roster, journal: Some(file) })
    }

    /// Records a check-in, returning the attendee's entry and whether they're new.
    /// Nothing changes if the journal can't be written.
    pub fn record(&mut self, attendee: Attendee, now: i64) -> io::Result<(Entry, bool)> {
        self.write(&Line::CheckIn { at: now, attendee: attendee.clone() })?;
        Ok(self.roster.record(attendee, now))
    }

    /// Empties the roster. The journal keeps the earlier check-ins, but they're no longer replayed.
    pub fn reset(&mut self, now: i64) -> io::Result<()> {
        self.write(&Line::Reset { at: now })?;
        self.roster = Roster::default();
        Ok(())
    }

    pub fn entries(&self) -> &[Entry] {
        self.roster.entries()
    }

    fn write(&mut self, line: &Line) -> io::Result<()> {
        let Some(file) = &mut self.journal else { return Ok(()) };
        let mut bytes = serde_json::to_vec(line).expect("lines serialize");
        bytes.push(b'\n');
        file.write_all(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn attendee(sub: &str) -> Attendee {
        Attendee {
            name: Some("Ada, Countess".into()),
            email: None,
            user_sub: sub.into(),
            user_iss: "https://idp.example.org".into(),
            device: "spiffe://example.org/iot/badge-reader".into(),
            txn: Some("txn-1".into()),
        }
    }

    fn journal_path(test: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("checkin-{}-{test}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn check_ins_survive_a_reopen() {
        let path = journal_path("reopen");
        let mut checkins = CheckIns::open(&path).unwrap();
        checkins.record(attendee("a"), 10).unwrap();
        checkins.record(attendee("b"), 20).unwrap();
        checkins.record(attendee("a"), 30).unwrap();
        let before = checkins.entries().to_vec();
        drop(checkins);

        assert_eq!(CheckIns::open(&path).unwrap().entries(), before);
        assert_eq!((before[1].first_seen, before[1].last_seen, before[1].check_ins), (10, 30, 2));
    }

    #[test]
    fn a_reset_survives_a_reopen() {
        let path = journal_path("reset");
        let mut checkins = CheckIns::open(&path).unwrap();
        checkins.record(attendee("a"), 10).unwrap();
        checkins.reset(20).unwrap();
        checkins.record(attendee("b"), 30).unwrap();
        drop(checkins);

        let subs: Vec<_> =
            CheckIns::open(&path).unwrap().entries().iter().map(|e| e.attendee.user_sub.clone()).collect();
        assert_eq!(subs, ["b"]);
    }

    #[test]
    fn a_partial_last_line_is_skipped_and_ended() {
        let path = journal_path("partial");
        let mut checkins = CheckIns::open(&path).unwrap();
        checkins.record(attendee("a"), 10).unwrap();
        drop(checkins);
        OpenOptions::new().append(true).open(&path).unwrap().write_all(br#"{"event":"check_in","at":2"#).unwrap();

        let mut checkins = CheckIns::open(&path).unwrap();
        assert_eq!(checkins.entries().len(), 1);
        checkins.record(attendee("b"), 30).unwrap();
        drop(checkins);
        assert_eq!(CheckIns::open(&path).unwrap().entries().len(), 2);
    }
}
