//! The sign-in QR code, drawn dark-on-white with a quiet zone so phone
//! cameras read it.

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{PrimitiveStyle, Rectangle};
use qrcodegen::{QrCode, QrCodeEcc};

use crate::display::Strip;

const QUIET_ZONE: i32 = 2;
const MAX_PX: i32 = 150;

pub fn encode(uri: &str) -> Option<QrCode> {
    QrCode::encode_text(uri, QrCodeEcc::Low).ok()
}

/// The code's width and height in pixels, quiet zone included.
pub fn size(qr: &QrCode) -> i32 {
    let modules = qr.size() + 2 * QUIET_ZONE;
    modules * (MAX_PX / modules)
}

pub fn draw(s: &mut Strip, qr: &QrCode, top_left: Point) {
    let modules = qr.size() + 2 * QUIET_ZONE;
    let scale = MAX_PX / modules;
    let mut square = |x: i32, y: i32, w: i32, color| {
        let rect = Rectangle::new(top_left + Point::new(x, y), Size::new(w as u32, w as u32));
        let _ = rect.into_styled(PrimitiveStyle::with_fill(color)).draw(s);
    };
    square(0, 0, size(qr), Rgb565::WHITE);
    for y in 0..qr.size() {
        for x in 0..qr.size() {
            if qr.get_module(x, y) {
                square((x + QUIET_ZONE) * scale, (y + QUIET_ZONE) * scale, scale, Rgb565::BLACK);
            }
        }
    }
}
