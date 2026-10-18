//! Renders the device's screens to PNGs with the firmware's own drawing code,
//! from made-up sample data, for slides and docs. Every name, URL and ID is an
//! example value, so nothing real ends up on a slide.

use std::convert::Infallible;
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::Path;

use anyhow::{Context, Result};
use demo::app::{Progress, Screen, Status, Step};
use demo::claims::DisplayClaims;
use embedded_graphics::pixelcolor::{Rgb565, Rgb888};
use embedded_graphics::prelude::*;
use screens::{qr, Frame, HEIGHT, WIDTH};

/// Approximates the panel's rounded corners, in panel pixels.
const CORNER_RADIUS: f32 = 20.0;
const NOW: i64 = 1_792_287_400;
const IDP: &str = "https://id.example.com";
const SIGN_IN_URI: &str = "https://id.example.com/device";
const USER_CODE: &str = "Q4TM7XKB";

pub fn render_all(out: &Path, scale: u32) -> Result<()> {
    fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    let status = Status { wifi: true, svid: true, attestor: "ESP-TEE".into(), switching: false };
    for (name, screen) in samples() {
        let path = out.join(format!("{name}.png"));
        write_png(&path, &render(&screen, &status), scale)?;
        println!("{}", path.display());
    }
    Ok(())
}

fn samples() -> Vec<(&'static str, Screen)> {
    let done = Step::Done;
    vec![
        ("idle", Screen::Idle),
        (
            "qr",
            Screen::Qr {
                uri: format!("{SIGN_IN_URI}?code={USER_CODE}"),
                verification_uri: SIGN_IN_URI.into(),
                user_code: USER_CODE.into(),
                issued_at: NOW - 23,
                expires_at: NOW - 23 + 300,
            },
        ),
        (
            "progress",
            Screen::Progress(Progress {
                attested: done,
                signed_in: done,
                got_svid: done,
                exchanged: done,
                checked_in: Some(Step::Active),
            }),
        ),
        ("receipt", Screen::Result { claims: alice(), checked_in: true }),
        ("error", Screen::Error("check-in refused: HTTP 403".into())),
    ]
}

fn alice() -> DisplayClaims {
    DisplayClaims {
        greeting: "Hi, Alice!".into(),
        email: Some("alice@example.com".into()),
        user_sub: "3f6c1a2e-8b4d-4e9a-9c1f-7d2b5e0a4c93".into(),
        user_iss: IDP.into(),
        actor: "spiffe://example.org/iot/badge-reader".into(),
        txn: Some("9b2e4f7a1c3d5e6f8a0b2c4d6e8f0a1b".into()),
        exp: NOW + 4 * 60 + 48,
    }
}

fn render(screen: &Screen, status: &Status) -> Canvas {
    let code = match screen {
        Screen::Qr { uri, .. } => qr::encode(uri),
        _ => None,
    };
    let mut canvas = Canvas(vec![Rgb565::BLACK; WIDTH as usize * HEIGHT as usize]);
    screens::draw(&mut canvas, &Frame { screen, status, now: NOW, pulse: 1.0, qr: code.as_ref() });
    canvas
}

/// The whole panel in memory.
struct Canvas(Vec<Rgb565>);

impl OriginDimensions for Canvas {
    fn size(&self) -> Size {
        Size::new(WIDTH.into(), HEIGHT.into())
    }
}

impl DrawTarget for Canvas {
    type Color = Rgb565;
    type Error = Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Infallible>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        let bounds = self.bounding_box();
        for Pixel(p, color) in pixels {
            if bounds.contains(p) {
                self.0[p.y as usize * WIDTH as usize + p.x as usize] = color;
            }
        }
        Ok(())
    }
}

/// Scales each panel pixel up to a `scale`-wide square, so the bitmap fonts
/// stay crisp, and fades the corners out to transparent.
fn write_png(path: &Path, canvas: &Canvas, scale: u32) -> Result<()> {
    let (w, h) = (WIDTH as u32 * scale, HEIGHT as u32 * scale);
    let mut rgba = Vec::with_capacity((w * h * 4) as usize);
    for y in 0..h {
        for x in 0..w {
            let c = Rgb888::from(canvas.0[(y / scale * WIDTH as u32 + x / scale) as usize]);
            let alpha = corner_alpha(x, y, w, h, CORNER_RADIUS * scale as f32);
            rgba.extend([c.r(), c.g(), c.b(), (alpha * 255.0).round() as u8]);
        }
    }
    let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut png = png::Encoder::new(BufWriter::new(file), w, h);
    png.set_color(png::ColorType::Rgba);
    png.set_depth(png::BitDepth::Eight);
    png.write_header()?.write_image_data(&rgba)?;
    Ok(())
}

/// Coverage of pixel `(x, y)` by a `w`×`h` rectangle with corners of radius `r`.
fn corner_alpha(x: u32, y: u32, w: u32, h: u32, r: f32) -> f32 {
    let (px, py) = (x as f32 + 0.5, y as f32 + 0.5);
    let dx = (r - px).max(px - (w as f32 - r)).max(0.0);
    let dy = (r - py).max(py - (h as f32 - r)).max(0.0);
    if dx == 0.0 || dy == 0.0 {
        return 1.0;
    }
    (r - dx.hypot(dy) + 0.5).clamp(0.0, 1.0)
}
