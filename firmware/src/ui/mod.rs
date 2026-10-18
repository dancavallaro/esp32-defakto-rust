//! Draws the demo's screens on the LCD, following the approved mockups.

mod logo;
mod qr;

use std::cell::Cell;
use std::f32::consts::TAU;
use std::ops::Range;
use std::time::Instant;

use anyhow::Result;
use demo::app::{Progress, Provisioning, Screen, Status, Step};
use demo::claims::DisplayClaims;
use demo::setup::wifi_qr;
use demo::text::{abbreviate, countdown, without_scheme, wrap, wrap_at_most};
use embedded_graphics::mono_font::iso_8859_1::{FONT_10X20, FONT_6X10, FONT_8X13};
use embedded_graphics::mono_font::{MonoFont, MonoTextStyle};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{Circle, PrimitiveStyle, Polyline, Rectangle};
use embedded_graphics::text::{Alignment, Baseline, Text, TextStyleBuilder};
use qrcodegen::QrCode;

use crate::display::{Display, Strip, HEIGHT, WIDTH};

const BG: Rgb565 = rgb(0x0c0816);
const BAR_BG: Rgb565 = rgb(0x160f26);
const FG: Rgb565 = rgb(0xe9e4f5);
const PURPLE: Rgb565 = rgb(0xa07cff);
const DIM: Rgb565 = rgb(0x7d7690);
const OK: Rgb565 = rgb(0x5ee3a1);
const WARN: Rgb565 = rgb(0xffcf5c);
const TRACK: Rgb565 = rgb(0x2a2140);

const BODY: MonoFont = FONT_6X10;
const HEADING: MonoFont = FONT_8X13;
const BIG: MonoFont = FONT_10X20;
const WORDMARK: MonoFont = MonoFont { character_spacing: 2, ..FONT_10X20 };

const CENTER_X: i32 = WIDTH as i32 / 2;
const MARGIN: i32 = 10;
const CONTENT_W: i32 = WIDTH as i32 - 2 * MARGIN;
const BAR_H: u32 = 20;
/// The panel's corners are rounded, so the bar's text keeps clear of them.
const BAR_INSET: Point = Point::new(12, 6);
const LOGO_TOP: i32 = 64;
const TAP_TOP: u16 = 280;
const TAP_ROWS: Range<u16> = TAP_TOP..TAP_TOP + 10;
const FOOTER_TOP: i32 = 302;
/// What fits between the error heading and the footer.
const MAX_DETAIL_LINES: usize = 12;
const BAR_TRACK_W: u32 = 144;
const PULSE_SECS: f32 = 1.6;

pub struct Ui {
    display: Display,
    epoch: Instant,
    qr: Option<(String, QrCode)>,
    drawn_at: i64,
    /// The rows of the last screen drawn that change each second.
    ticking: Option<(i32, i32)>,
}

/// Everything a screen is drawn from.
struct Frame<'a> {
    screen: &'a Screen,
    status: &'a Status,
    now: i64,
    pulse: f32,
    qr: Option<&'a QrCode>,
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
        let qr_text = match screen {
            Screen::Qr { uri, .. } => Some(uri.clone()),
            Screen::Setup { ssid, password, .. } => Some(wifi_qr(ssid, password)),
            _ => None,
        };
        if let Some(text) = qr_text {
            if self.qr.as_ref().is_none_or(|(cached, _)| *cached != text) {
                self.qr = qr::encode(&text).map(|code| (text, code));
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

/// Draws the whole screen, returning the rows of its countdown, if it has one.
fn draw(s: &mut Strip, f: &Frame) -> Option<(i32, i32)> {
    let _ = s.clear(BG);
    status_bar(s, f.status);
    match f.screen {
        Screen::Idle => idle(s, f.status, f.pulse),
        Screen::Starting => message(s, "Contacting the identity provider...", None),
        Screen::Qr { verification_uri, user_code, issued_at, expires_at, .. } => {
            return Some(sign_in(s, f.qr, verification_uri, user_code, (*expires_at - f.now, *expires_at - *issued_at)))
        }
        Screen::Progress(p) => progress(s, p, &f.status.attestor),
        Screen::Result { claims, checked_in } => return Some(result(s, claims, *checked_in, f.now)),
        Screen::Error(msg) => message(s, "Check-in failed", Some(msg)),
        Screen::Setup { ssid, password, portal } => setup(s, f.qr, ssid, password, portal),
        Screen::Restarting => message(s, "Saved. Restarting...", None),
        Screen::Provisioning(p) => provisioning(s, p),
    }
    None
}

fn status_bar(s: &mut Strip, status: &Status) {
    fill(s, Rectangle::new(Point::zero(), Size::new(WIDTH as u32, BAR_H)), BAR_BG);
    let (mut x, y) = (BAR_INSET.x, BAR_INSET.y);
    for (name, ok) in [("WiFi", status.wifi), ("SVID", status.svid)] {
        text(s, name, Point::new(x, y), &BODY, FG, Alignment::Left);
        x += name.len() as i32 * 6 + 4;
        let _ = Circle::new(Point::new(x, y + 2), 6)
            .into_styled(PrimitiveStyle::with_fill(if ok { OK } else { DIM }))
            .draw(s);
        x += 14;
    }
    text(s, &status.attestor, Point::new(WIDTH as i32 - BAR_INSET.x, y), &BODY, DIM, Alignment::Right);
}

fn idle(s: &mut Strip, status: &Status, pulse: f32) {
    logo::draw(s, Point::new(CENTER_X - logo::SIZE.width as i32 / 2, LOGO_TOP), PURPLE);
    let word_top = LOGO_TOP + logo::SIZE.height as i32 + 12;
    text(s, "defakto", Point::new(CENTER_X, word_top), &WORDMARK, FG, Alignment::Center);
    let tap = blend(FG, BG, pulse);
    text(s, "[ tap to check in ]", Point::new(CENTER_X, TAP_TOP as i32), &BODY, tap, Alignment::Center);
    let footer = match (status.switching, status.svid) {
        (true, _) => "switching attestor...".into(),
        (false, true) => format!("attested via {}", status.attestor),
        (false, false) => "not attested".into(),
    };
    text(s, &footer, Point::new(CENTER_X, FOOTER_TOP), &BODY, DIM, Alignment::Center);
}

/// The QR code and its fallbacks. `left` and `lifetime` are in seconds.
fn sign_in(s: &mut Strip, qr: Option<&QrCode>, uri: &str, code: &str, (left, lifetime): (i64, i64)) -> (i32, i32) {
    let mut y = BAR_H as i32 + 8;
    y = centered(s, "Scan to sign in", y, &HEADING, FG) + 6;
    match qr {
        Some(qr) => {
            qr::draw(s, qr, Point::new(CENTER_X - qr::size(qr) / 2, y));
            y += qr::size(qr) + 8;
        }
        None => y = centered(s, "(link too long for a QR code)", y, &BODY, WARN) + 8,
    }
    y = centered(s, "OR VISIT", y, &BODY, DIM) + 2;
    y = centered(s, without_scheme(uri), y, &BODY, FG) + 6;
    y = centered(s, "CODE", y, &BODY, DIM) + 2;
    y = centered(s, code, y, &BIG, PURPLE) + 4;

    let track = Rectangle::new(Point::new(CENTER_X - BAR_TRACK_W as i32 / 2, y), Size::new(BAR_TRACK_W, 4));
    fill(s, track, TRACK);
    let filled = BAR_TRACK_W as i64 * left.clamp(0, lifetime) / lifetime.max(1);
    fill(s, Rectangle::new(track.top_left, Size::new(filled as u32, 4)), PURPLE);
    let bottom = centered(s, &format!("{} \u{b7} tap to cancel", countdown(left)), y + 10, &BODY, DIM);
    (y, bottom)
}

/// The QR code that joins the setup network, and what to type without one.
fn setup(s: &mut Strip, qr: Option<&QrCode>, ssid: &str, password: &str, portal: &str) {
    let mut y = BAR_H as i32 + 8;
    y = centered(s, "Set up this device", y, &HEADING, FG) + 6;
    if let Some(qr) = qr {
        qr::draw(s, qr, Point::new(CENTER_X - qr::size(qr) / 2, y));
        y += qr::size(qr) + 8;
    }
    y = centered(s, "SCAN, OR JOIN", y, &BODY, DIM) + 2;
    y = centered(s, ssid, y, &BODY, FG) + 6;
    y = centered(s, "PASSWORD", y, &BODY, DIM) + 2;
    y = centered(s, password, y, &BIG, PURPLE) + 8;
    centered(s, &format!("then open {}", without_scheme(portal)), y, &BODY, DIM);
}

fn provisioning(s: &mut Strip, p: &Provisioning) {
    let (heading, color, detail) = match p {
        Provisioning::Checking => ("Checking DevID...", FG, None),
        Provisioning::Configured(developer) => ("Set up by", OK, Some(developer.as_str())),
        Provisioning::Refused(why) => ("Settings refused", WARN, Some(why.as_str())),
    };
    let mut y = centered(s, heading, 120, &HEADING, color) + 10;
    for line in wrap_at_most(detail.unwrap_or_default(), columns(&BODY), MAX_DETAIL_LINES) {
        y = centered(s, &line, y, &BODY, FG);
    }
    let footer = if matches!(p, Provisioning::Checking) { "joining WiFi, then verifying" } else { "restarting..." };
    centered(s, footer, FOOTER_TOP, &BODY, DIM);
}

fn result(s: &mut Strip, c: &DisplayClaims, checked_in: bool, now: i64) -> (i32, i32) {
    let mut y = centered(s, &c.greeting, BAR_H as i32 + 10, &BIG, FG) + 10;
    if checked_in {
        y = checked_in_banner(s, y) + 10;
    }
    let txn = c.txn.as_deref().map(|t| abbreviate(t, columns(&BODY)));
    let rows = [
        ("ON BEHALF OF", Some(c.email.as_deref().unwrap_or(&c.user_sub))),
        ("USER'S IdP", Some(without_scheme(&c.user_iss))),
        ("ACTOR (THIS DEVICE)", Some(c.actor.as_str())),
        ("TXN", txn.as_deref()),
    ];
    for (label, value) in rows {
        let Some(value) = value else { continue };
        y = paragraph(s, label, y, DIM, Alignment::Left) + 1;
        y = paragraph(s, value, y, FG, Alignment::Left) + 7;
    }
    y = paragraph(s, "EXPIRES", y, DIM, Alignment::Left) + 1;
    let bottom = paragraph(s, &format!("in {}", countdown(c.exp - now)), y, FG, Alignment::Left);
    centered(s, "tap to reset", FOOTER_TOP, &BODY, DIM);
    (y, bottom)
}

/// A check mark beside "checked in", centered at `y`. Returns the y below it.
fn checked_in_banner(s: &mut Strip, y: i32) -> i32 {
    const LABEL: &str = "checked in";
    const MARK_W: i32 = 18;
    let width = MARK_W + LABEL.len() as i32 * HEADING.character_size.width as i32;
    let left = CENTER_X - width / 2;
    step_mark(s, Step::Done, Point::new(left, y + 1));
    text(s, LABEL, Point::new(left + MARK_W, y), &HEADING, OK, Alignment::Left);
    y + HEADING.character_size.height as i32
}

fn progress(s: &mut Strip, p: &Progress, attestor: &str) {
    let mut y = centered(s, "Checking in...", BAR_H as i32 + 20, &HEADING, FG) + 20;
    let rows = [
        Some((p.attested, "device attested", attestor)),
        Some((p.signed_in, "user signed in", "ID token from IdP")),
        Some((p.got_svid, "got JWT-SVID", "serverless API")),
        Some((p.exchanged, "token exchange", "RFC 8693 -> OBO SVID")),
        p.checked_in.map(|step| (step, "checked in", "OBO -> check-in API")),
    ];
    for (step, label, caption) in rows.into_iter().flatten() {
        let label_color = if step == Step::Pending { DIM } else { FG };
        step_mark(s, step, Point::new(MARGIN + 2, y + 1));
        text(s, label, Point::new(MARGIN + 22, y), &HEADING, label_color, Alignment::Left);
        text(s, caption, Point::new(MARGIN + 22, y + 15), &BODY, DIM, Alignment::Left);
        y += 44;
    }
}

/// A check for done, an ellipsis for active, a hollow dot for pending. Drawn
/// as shapes because the fonts have no ✓ or …
fn step_mark(s: &mut Strip, step: Step, at: Point) {
    match step {
        Step::Done => {
            let points = [at + Point::new(0, 6), at + Point::new(4, 10), at + Point::new(11, 1)];
            let _ = Polyline::new(&points).into_styled(PrimitiveStyle::with_stroke(OK, 2)).draw(s);
        }
        Step::Active => {
            for i in 0..3 {
                let _ = Circle::new(at + Point::new(i * 4, 8), 3).into_styled(PrimitiveStyle::with_fill(WARN)).draw(s);
            }
        }
        Step::Pending => {
            let _ = Circle::new(at + Point::new(1, 2), 9).into_styled(PrimitiveStyle::with_stroke(DIM, 1)).draw(s);
        }
    }
}

/// A centered heading, plus an optional detail paragraph under it.
fn message(s: &mut Strip, heading: &str, detail: Option<&str>) {
    let color = if detail.is_some() { WARN } else { FG };
    let mut y = centered(s, heading, 120, &HEADING, color) + 10;
    if let Some(detail) = detail {
        for line in wrap_at_most(detail, columns(&BODY), MAX_DETAIL_LINES) {
            y = centered(s, &line, y, &BODY, FG);
        }
        centered(s, "tap to start over", FOOTER_TOP, &BODY, DIM);
    }
}

/// Draws `str` centered and wrapped to the content width, returning the y
/// below it.
fn centered(s: &mut Strip, str: &str, y: i32, font: &MonoFont, color: Rgb565) -> i32 {
    lines(s, str, y, font, color, Alignment::Center)
}

fn paragraph(s: &mut Strip, str: &str, y: i32, color: Rgb565, alignment: Alignment) -> i32 {
    lines(s, str, y, &BODY, color, alignment)
}

fn lines(s: &mut Strip, str: &str, mut y: i32, font: &MonoFont, color: Rgb565, alignment: Alignment) -> i32 {
    let x = if alignment == Alignment::Center { CENTER_X } else { MARGIN };
    for line in wrap(str, columns(font)) {
        text(s, &line, Point::new(x, y), font, color, alignment);
        y += font.character_size.height as i32 + 1;
    }
    y
}

fn columns(font: &MonoFont) -> usize {
    (CONTENT_W / (font.character_size.width + font.character_spacing) as i32) as usize
}

fn text(s: &mut Strip, str: &str, at: Point, font: &MonoFont, color: Rgb565, alignment: Alignment) {
    let style = TextStyleBuilder::new().alignment(alignment).baseline(Baseline::Top).build();
    let _ = Text::with_text_style(str, at, MonoTextStyle::new(font, color), style).draw(s);
}

fn fill(s: &mut Strip, area: Rectangle, color: Rgb565) {
    let _ = area.into_styled(PrimitiveStyle::with_fill(color)).draw(s);
}

/// `fg` drawn at `alpha` opacity over `bg`.
fn blend(fg: Rgb565, bg: Rgb565, alpha: f32) -> Rgb565 {
    let mix = |f: u8, b: u8| (b as f32 + (f as f32 - b as f32) * alpha).round() as u8;
    Rgb565::new(mix(fg.r(), bg.r()), mix(fg.g(), bg.g()), mix(fg.b(), bg.b()))
}

const fn rgb(hex: u32) -> Rgb565 {
    Rgb565::new((hex >> 19) as u8 & 0x1F, (hex >> 10) as u8 & 0x3F, (hex >> 3) as u8 & 0x1F)
}
