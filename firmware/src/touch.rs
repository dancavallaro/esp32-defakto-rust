//! The AXS5106L touch controller, polled over I2C. The whole screen is one
//! button, so only whether a finger is down matters, not where.

use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::Result;
use demo::gesture::{Detector, Gesture};
use esp_idf_svc::hal::delay::TickType;
use esp_idf_svc::hal::gpio::{Gpio18, Gpio19, Gpio20, Output, PinDriver};
use esp_idf_svc::hal::i2c::{I2cConfig, I2cDriver, I2C0};
use esp_idf_svc::hal::units::Hertz;
use log::info;

const ADDRESS: u8 = 0x63;
const TOUCH_POINTS_REG: u8 = 0x01;
const ID_REG: u8 = 0x08;
const TIMEOUT: TickType = TickType::new_millis(50);

pub struct Touch {
    i2c: I2cDriver<'static>,
    _rst: PinDriver<'static, Output>,
    detector: Detector,
    epoch: Instant,
}

impl Touch {
    pub fn new(i2c: I2C0<'static>, sda: Gpio18<'static>, scl: Gpio19<'static>, rst: Gpio20<'static>) -> Result<Self> {
        let config = I2cConfig::new().baudrate(Hertz(400_000)).sda_enable_pullup(true).scl_enable_pullup(true);
        let i2c = I2cDriver::new(i2c, sda, scl, &config)?;
        let mut rst = PinDriver::output(rst)?;
        rst.set_low()?;
        sleep(Duration::from_millis(200));
        rst.set_high()?;
        sleep(Duration::from_millis(300));

        let mut touch = Self { i2c, _rst: rst, detector: Detector::default(), epoch: Instant::now() };
        let mut id = [0u8; 3];
        touch.read(ID_REG, &mut id)?;
        info!("touch controller id {id:02x?}");
        Ok(touch)
    }

    pub fn poll(&mut self) -> Result<Option<Gesture>> {
        let down = self.is_down()?;
        Ok(self.detector.update(down, self.epoch.elapsed()))
    }

    pub fn is_down(&mut self) -> Result<bool> {
        let mut data = [0u8; 14];
        self.read(TOUCH_POINTS_REG, &mut data)?;
        Ok(data[1] & 0x0F != 0)
    }

    /// The controller wants a stop between the register write and the read,
    /// not a repeated start.
    fn read(&mut self, reg: u8, buf: &mut [u8]) -> Result<()> {
        self.i2c.write(ADDRESS, &[reg], TIMEOUT.ticks())?;
        self.i2c.read(ADDRESS, buf, TIMEOUT.ticks())?;
        Ok(())
    }
}
