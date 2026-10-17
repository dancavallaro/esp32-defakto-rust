//! JD9853 panel commands. The init sequence is Waveshare's
//! (`esp_lcd_jd9853.c` in their ESP32-C6-Touch-LCD-1.47 demo).

use std::thread::sleep;
use std::time::Duration;

use anyhow::Result;
use esp_idf_svc::hal::gpio::{Output, PinDriver};
use esp_idf_svc::hal::spi::{SpiDeviceDriver, SpiDriver};

/// The panel's 172 columns start at column 34 of the controller's 240.
const COLUMN_OFFSET: u16 = 34;

const SLPOUT: u8 = 0x11;
const INVON: u8 = 0x21;
const DISPON: u8 = 0x29;
const CASET: u8 = 0x2A;
const RASET: u8 = 0x2B;
const RAMWR: u8 = 0x2C;
const MADCTL: u8 = 0x36;
const COLMOD: u8 = 0x3A;

/// `(command, parameters, delay after in ms)`.
const VENDOR_INIT: &[(u8, &[u8], u64)] = &[
    (SLPOUT, &[], 120),
    (0xDF, &[0x98, 0x53], 0),
    (0xDF, &[0x98, 0x53], 0),
    (0xB2, &[0x23], 0),
    (0xB7, &[0x00, 0x47, 0x00, 0x6F], 0),
    (0xBB, &[0x1C, 0x1A, 0x55, 0x73, 0x63, 0xF0], 0),
    (0xC0, &[0x44, 0xA4], 0),
    (0xC1, &[0x16], 0),
    (0xC3, &[0x7D, 0x07, 0x14, 0x06, 0xCF, 0x71, 0x72, 0x77], 0),
    (0xC4, &[0x00, 0x00, 0xA0, 0x79, 0x0B, 0x0A, 0x16, 0x79, 0x0B, 0x0A, 0x16, 0x82], 0),
    (
        0xC8,
        &[
            0x3F, 0x32, 0x29, 0x29, 0x27, 0x2B, 0x27, 0x28, 0x28, 0x26, 0x25, 0x17, 0x12, 0x0D, 0x04, 0x00, 0x3F,
            0x32, 0x29, 0x29, 0x27, 0x2B, 0x27, 0x28, 0x28, 0x26, 0x25, 0x17, 0x12, 0x0D, 0x04, 0x00,
        ],
        0,
    ),
    (0xD0, &[0x04, 0x06, 0x6B, 0x0F, 0x00], 0),
    (0xD7, &[0x00, 0x30], 0),
    (0xE6, &[0x14], 0),
    (0xDE, &[0x01], 0),
    (0xB7, &[0x03, 0x13, 0xEF, 0x35, 0x35], 0),
    (0xC1, &[0x14, 0x15, 0xC0], 0),
    (0xC2, &[0x06, 0x3A], 0),
    (0xC4, &[0x72, 0x12], 0),
    (0xBE, &[0x00], 0),
    (0xDE, &[0x02], 0),
    (0xE5, &[0x00, 0x02, 0x00], 0),
    (0xE5, &[0x01, 0x02, 0x00], 0),
    (0xDE, &[0x00], 0),
    (0x35, &[0x00], 0),
    (COLMOD, &[0x05], 0), // RGB565
    (CASET, &[0x00, 0x22, 0x00, 0xCD], 0),
    (RASET, &[0x00, 0x00, 0x01, 0x3F], 0),
    (0xDE, &[0x02], 0),
    (0xE5, &[0x00, 0x02, 0x00], 0),
    (0xDE, &[0x00], 0),
    (DISPON, &[], 0),
];

pub struct Panel {
    spi: SpiDeviceDriver<'static, SpiDriver<'static>>,
    dc: PinDriver<'static, Output>,
    _rst: PinDriver<'static, Output>,
}

impl Panel {
    pub fn new(
        spi: SpiDeviceDriver<'static, SpiDriver<'static>>,
        dc: PinDriver<'static, Output>,
        mut rst: PinDriver<'static, Output>,
    ) -> Result<Self> {
        rst.set_low()?;
        sleep(Duration::from_millis(10));
        rst.set_high()?;
        sleep(Duration::from_millis(10));

        let mut panel = Self { spi, dc, _rst: rst };
        panel.command(SLPOUT, &[])?;
        sleep(Duration::from_millis(100));
        panel.command(MADCTL, &[0x00])?; // RGB order, no mirroring
        for &(cmd, params, delay) in VENDOR_INIT {
            panel.command(cmd, params)?;
            sleep(Duration::from_millis(delay));
        }
        panel.command(INVON, &[])?;
        Ok(panel)
    }

    /// Writes RGB565 big-endian pixels into the window `x0..=x1`, `y0..=y1`.
    pub fn write_pixels(&mut self, x0: u16, y0: u16, x1: u16, y1: u16, pixels: &[u8]) -> Result<()> {
        let (x0, x1) = (x0 + COLUMN_OFFSET, x1 + COLUMN_OFFSET);
        self.command(CASET, &[(x0 >> 8) as u8, x0 as u8, (x1 >> 8) as u8, x1 as u8])?;
        self.command(RASET, &[(y0 >> 8) as u8, y0 as u8, (y1 >> 8) as u8, y1 as u8])?;
        self.command(RAMWR, pixels)
    }

    fn command(&mut self, cmd: u8, params: &[u8]) -> Result<()> {
        self.dc.set_low()?;
        self.spi.write(&[cmd])?;
        if !params.is_empty() {
            self.dc.set_high()?;
            self.spi.write(params)?;
        }
        Ok(())
    }
}
