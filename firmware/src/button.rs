//! The BOOT button (GPIO9 on both boards) as the "tap" until touch works.

use anyhow::Result;
use esp_idf_svc::hal::gpio::{Gpio9, Input, PinDriver, Pull};

pub struct Button {
    pin: PinDriver<'static, Input>,
    was_down: bool,
}

impl Button {
    pub fn new(pin: Gpio9<'static>) -> Result<Self> {
        Ok(Self { pin: PinDriver::input(pin, Pull::Up)?, was_down: false })
    }

    /// True once per press; poll it every few tens of milliseconds, which also
    /// debounces it.
    pub fn pressed(&mut self) -> bool {
        let down = self.pin.is_low();
        let pressed = down && !self.was_down;
        self.was_down = down;
        pressed
    }
}
