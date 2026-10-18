//! The 172×320 LCD. Screens are drawn one horizontal strip at a time, so a
//! redraw needs an 11 KB buffer instead of a 110 KB framebuffer, which would
//! crowd out TLS.

mod jd9853;

use std::convert::Infallible;
use std::ops::Range;

use anyhow::Result;
use embedded_graphics::pixelcolor::raw::RawU16;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::Rectangle;
use esp_idf_svc::hal::gpio::{Gpio1, Gpio14, Gpio15, Gpio2, Gpio22, Gpio23, PinDriver};
use esp_idf_svc::hal::ledc::{config::TimerConfig, LedcDriver, LedcTimerDriver, LowSpeed, CHANNEL0, TIMER0};
use esp_idf_svc::hal::spi::{config, Dma, SpiDeviceDriver, SpiDriver, SPI2};
use esp_idf_svc::hal::units::Hertz;

use screens::{HEIGHT, WIDTH};

const STRIP_ROWS: u16 = 32;
const STRIP_BYTES: usize = WIDTH as usize * STRIP_ROWS as usize * 2;
const BRIGHTNESS_PERCENT: u32 = 80;

pub struct Pins {
    pub sclk: Gpio1<'static>,
    pub mosi: Gpio2<'static>,
    pub cs: Gpio14<'static>,
    pub dc: Gpio15<'static>,
    pub rst: Gpio22<'static>,
    pub backlight: Gpio23<'static>,
}

pub struct Display {
    panel: jd9853::Panel,
    strip: Strip,
    _backlight: (LedcTimerDriver<'static, LowSpeed>, LedcDriver<'static>),
}

impl Display {
    pub fn new(spi: SPI2<'static>, pins: Pins, timer: TIMER0<'static>, channel: CHANNEL0<'static>) -> Result<Self> {
        // No DMA: ESP-TEE resets the whole GDMA block whenever it uses its crypto DMA
        // (WiFi and TLS do), which silently wipes any channel the app holds.
        let bus = config::DriverConfig::new().dma(Dma::Disabled);
        let device = config::Config::new().baudrate(Hertz(40_000_000)).write_only(true);
        let spi = SpiDeviceDriver::new(
            SpiDriver::new(spi, pins.sclk, pins.mosi, None::<esp_idf_svc::hal::gpio::AnyIOPin>, &bus)?,
            Some(pins.cs),
            &device,
        )?;
        let panel = jd9853::Panel::new(spi, PinDriver::output(pins.dc)?, PinDriver::output(pins.rst)?)?;

        let timer = LedcTimerDriver::new(timer, &TimerConfig::new().frequency(Hertz(5_000)))?;
        let mut backlight = LedcDriver::new(channel, &timer, pins.backlight)?;
        backlight.set_duty(backlight.get_max_duty() * BRIGHTNESS_PERCENT / 100)?;

        Ok(Self { panel, strip: Strip::new(), _backlight: (timer, backlight) })
    }

    /// Redraws `rows` of the screen. `draw` runs once per strip and should
    /// draw the whole screen; each strip keeps only the pixels inside it.
    pub fn draw(&mut self, rows: Range<u16>, draw: impl Fn(&mut Strip)) -> Result<()> {
        let mut top = rows.start;
        while top < rows.end {
            let bottom = (top + STRIP_ROWS).min(rows.end);
            self.strip.top = top as i32;
            self.strip.rows = (bottom - top) as i32;
            draw(&mut self.strip);
            let len = WIDTH as usize * (bottom - top) as usize * 2;
            self.panel.write_pixels(0, top, WIDTH - 1, bottom - 1, &self.strip.buf[..len])?;
            top = bottom;
        }
        Ok(())
    }
}

/// A horizontal band of the screen that the screen's drawing code renders into.
pub struct Strip {
    top: i32,
    rows: i32,
    buf: Vec<u8>,
}

impl Strip {
    fn new() -> Self {
        Self { top: 0, rows: STRIP_ROWS as i32, buf: vec![0; STRIP_BYTES] }
    }

    fn put(&mut self, x: i32, y: i32, color: Rgb565) {
        let i = ((y - self.top) * WIDTH as i32 + x) as usize * 2;
        self.buf[i..i + 2].copy_from_slice(&RawU16::from(color).into_inner().to_be_bytes());
    }

    fn bounds(&self) -> Rectangle {
        Rectangle::new(Point::new(0, self.top), Size::new(WIDTH as u32, self.rows as u32))
    }
}

impl OriginDimensions for Strip {
    fn size(&self) -> Size {
        Size::new(WIDTH as u32, HEIGHT as u32)
    }
}

impl DrawTarget for Strip {
    type Color = Rgb565;
    type Error = Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Infallible>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        let bounds = self.bounds();
        for Pixel(p, color) in pixels {
            if bounds.contains(p) {
                self.put(p.x, p.y, color);
            }
        }
        Ok(())
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Rgb565) -> Result<(), Infallible> {
        let area = area.intersection(&self.bounds());
        let Some(bottom_right) = area.bottom_right() else { return Ok(()) };
        for y in area.top_left.y..=bottom_right.y {
            for x in area.top_left.x..=bottom_right.x {
                self.put(x, y, color);
            }
        }
        Ok(())
    }
}
