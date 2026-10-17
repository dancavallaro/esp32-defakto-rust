//! Draws the demo's screens on the LCD, following the approved mockups.

mod logo;

use std::f32::consts::TAU;
use std::ops::Range;
use std::time::Instant;

use anyhow::Result;
use demo::app::{Screen, Status};
use embedded_graphics::mono_font::iso_8859_1::{FONT_10X20, FONT_6X10};
use embedded_graphics::mono_font::{MonoFont, MonoTextStyle};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{Circle, PrimitiveStyle, Rectangle};
use embedded_graphics::text::{Alignment, Baseline, Text, TextStyleBuilder};

use crate::display::{Display, Strip, HEIGHT, WIDTH};

const BG: Rgb565 = rgb(0x0c0816);
const BAR_BG: Rgb565 = rgb(0x160f26);
const FG: Rgb565 = rgb(0xe9e4f5);
const PURPLE: Rgb565 = rgb(0xa07cff);
const DIM: Rgb565 = rgb(0x7d7690);
const OK: Rgb565 = rgb(0x5ee3a1);

const BODY: MonoFont = FONT_6X10;
const WORDMARK: MonoFont = MonoFont { character_spacing: 2, ..FONT_10X20 };

const CENTER_X: i32 = WIDTH as i32 / 2;
const BAR_H: u32 = 20;
/// The panel's corners are rounded, so the bar's text keeps clear of them.
const BAR_INSET: Point = Point::new(12, 6);
const LOGO_TOP: i32 = 64;
const TAP_TOP: u16 = 280;
const TAP_ROWS: Range<u16> = TAP_TOP..TAP_TOP + 10;
const FOOTER_TOP: i32 = 302;
const PULSE_SECS: f32 = 1.6;

pub struct Ui {
    display: Display,
    epoch: Instant,
}

impl Ui {
    pub fn new(display: Display) -> Self {
        Self { display, epoch: Instant::now() }
    }

    pub fn render(&mut self, screen: &Screen, status: &Status) -> Result<()> {
        let pulse = self.pulse();
        self.display.draw(0..HEIGHT, |s| draw(s, screen, status, pulse))
    }

    /// Redraws only what moves on `screen`, cheaply enough to call every frame.
    pub fn animate(&mut self, screen: &Screen, status: &Status) -> Result<()> {
        if *screen == Screen::Idle {
            let pulse = self.pulse();
            self.display.draw(TAP_ROWS, |s| draw(s, screen, status, pulse))?;
        }
        Ok(())
    }

    /// Opacity of the tap prompt, easing between 1.0 and 0.35.
    fn pulse(&self) -> f32 {
        let phase = self.epoch.elapsed().as_secs_f32() / PULSE_SECS;
        0.675 + 0.325 * (TAU * phase).cos()
    }
}

fn draw(s: &mut Strip, screen: &Screen, status: &Status, pulse: f32) {
    let _ = s.clear(BG);
    status_bar(s, status);
    match screen {
        Screen::Idle => idle(s, status, pulse),
        other => text(s, placeholder(other), Point::new(CENTER_X, 150), &BODY, FG, Alignment::Center),
    }
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
    text(s, "[ tap to sign in ]", Point::new(CENTER_X, TAP_TOP as i32), &BODY, tap, Alignment::Center);
    let footer = if status.svid { format!("attested via {}", status.attestor) } else { "not attested".into() };
    text(s, &footer, Point::new(CENTER_X, FOOTER_TOP), &BODY, DIM, Alignment::Center);
}

fn placeholder(screen: &Screen) -> &'static str {
    match screen {
        Screen::Idle => "",
        Screen::Starting => "Contacting the IdP...",
        Screen::Qr { .. } => "QR code",
        Screen::Progress(_) => "Signing in...",
        Screen::Result(_) => "Signed in",
        Screen::Error(_) => "Error",
    }
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
