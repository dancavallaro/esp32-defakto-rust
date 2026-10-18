//! Shows the demo's screens on the LCD, redrawing only what changes.

use std::cell::Cell;
use std::f32::consts::TAU;
use std::ops::Range;
use std::time::Instant;

use anyhow::Result;
use demo::app::{Screen, Status};
use qrcodegen::QrCode;
use screens::{draw, qr, Frame, HEIGHT, TAP_ROWS};

use crate::display::Display;

const PULSE_SECS: f32 = 1.6;

pub struct Ui {
    display: Display,
    epoch: Instant,
    qr: Option<(String, QrCode)>,
    drawn_at: i64,
    /// The rows of the last screen drawn that change each second.
    ticking: Option<(i32, i32)>,
}

impl Ui {
    pub fn new(display: Display) -> Self {
        Self { display, epoch: Instant::now(), qr: None, drawn_at: 0, ticking: None }
    }

    pub fn render(&mut self, screen: &Screen, status: &Status, now: i64) -> Result<()> {
        self.render_rows(0..HEIGHT, screen, status, now)
    }

    /// Redraws what moves on `screen`: the idle prompt every frame, and the
    /// countdowns once a second. Only those rows, because touch isn't polled
    /// while drawing and a full redraw is long enough to miss a tap.
    pub fn animate(&mut self, screen: &Screen, status: &Status, now: i64) -> Result<()> {
        match (screen, self.ticking) {
            (Screen::Idle, _) => self.render_rows(TAP_ROWS, screen, status, now),
            (_, Some((top, bottom))) if now != self.drawn_at => {
                self.render_rows(top as u16..bottom as u16, screen, status, now)
            }
            _ => Ok(()),
        }
    }

    fn render_rows(&mut self, rows: Range<u16>, screen: &Screen, status: &Status, now: i64) -> Result<()> {
        if let Screen::Qr { uri, .. } = screen {
            if self.qr.as_ref().is_none_or(|(cached, _)| cached != uri) {
                self.qr = qr::encode(uri).map(|code| (uri.clone(), code));
            }
        }
        let frame = Frame { screen, status, now, pulse: self.pulse(), qr: self.qr.as_ref().map(|(_, code)| code) };
        self.drawn_at = now;
        let ticking = Cell::new(None);
        self.display.draw(rows, |s| ticking.set(draw(s, &frame)))?;
        self.ticking = ticking.get();
        Ok(())
    }

    /// Opacity of the tap prompt, easing between 1.0 and 0.35.
    fn pulse(&self) -> f32 {
        let phase = self.epoch.elapsed().as_secs_f32() / PULSE_SECS;
        0.675 + 0.325 * (TAU * phase).cos()
    }
}

