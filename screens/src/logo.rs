//! The ASCII-art "D". The bitmap fonts have no box-drawing characters, so
//! each character cell is drawn as rectangles.

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{PrimitiveStyle, Rectangle};

use crate::Target;

const ART: [&str; 6] = ["██████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "];

const CELL_W: i32 = 10;
const CELL_H: i32 = 12;
pub const SIZE: Size = Size::new(8 * CELL_W as u32, ART.len() as u32 * CELL_H as u32);

pub fn draw(target: &mut impl Target, top_left: Point, color: Rgb565) {
    for (row, line) in ART.iter().enumerate() {
        for (col, ch) in line.chars().enumerate() {
            let origin = top_left + Point::new(col as i32 * CELL_W, row as i32 * CELL_H);
            for (x, y, w, h) in strokes(ch) {
                let rect = Rectangle::new(origin + Point::new(x, y), Size::new(w as u32, h as u32));
                let _ = rect.into_styled(PrimitiveStyle::with_fill(color)).draw(target);
            }
        }
    }
}

/// The `(x, y, w, h)` rectangles that make up `ch` within its cell.
fn strokes(ch: char) -> Vec<(i32, i32, i32, i32)> {
    const W: i32 = CELL_W;
    const H: i32 = CELL_H;
    // The double lines: verticals at x = L and R, horizontals at y = T and B.
    const L: i32 = W / 2 - 2;
    const R: i32 = W / 2 + 1;
    const T: i32 = H / 2 - 2;
    const B: i32 = H / 2 + 1;
    let h = |y, x0, x1| (x0, y, x1 - x0, 1);
    let v = |x, y0, y1| (x, y0, 1, y1 - y0);
    match ch {
        '█' => vec![(0, 0, W, H)],
        '═' => vec![h(T, 0, W), h(B, 0, W)],
        '║' => vec![v(L, 0, H), v(R, 0, H)],
        '╗' => vec![h(T, 0, R + 1), v(R, T, H), h(B, 0, L + 1), v(L, B, H)],
        '╔' => vec![h(T, L, W), v(L, T, H), h(B, R, W), v(R, B, H)],
        '╝' => vec![h(B, 0, R + 1), v(R, 0, B + 1), h(T, 0, L + 1), v(L, 0, T + 1)],
        '╚' => vec![h(B, L, W), v(L, 0, B + 1), h(T, R, W), v(R, 0, T + 1)],
        _ => vec![],
    }
}
