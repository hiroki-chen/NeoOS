//! Real-Time Clocks. The information is stored in CMOS.
//! After RTC is available, you can read accurate system time!
//! The 2 IO ports used for the RTC and CMOS are 0x70 and 0x71. Port 0x70 is used to specify an index or
//! "register number", and to disable NMI. Port 0x71 is used to read or write from/to that byte of CMOS
//! configuration space.

use core::time::Duration;

use alloc::sync::Arc;
use x86_64::instructions::{interrupts::without_interrupts, port::Port};

use crate::error::{Errno, KResult};

use super::{Driver, Type, RTC_DRIVERS, RTC_UUID};

const CMOS_ADDR: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

pub trait ClockDriver: Driver {
    /// Reads the timepoint from the hardware.
    unsafe fn read_clock_raw(&self) -> u64;

    /// Reads the timepoint and convert into `Duration`.
    fn read_clock(&self) -> Duration;
}

pub fn read_rtc(reg: u8) -> u8 {
    let mut addr = Port::<u8>::new(CMOS_ADDR);
    let mut data = Port::<u8>::new(CMOS_DATA);

    unsafe {
        addr.write(reg);
        data.read()
    }
}

/// Converts a BCD numebr into binary.
#[inline(always)]
fn decode_bcd(num: u64) -> u64 {
    (num & 0x0f) + (num >> 4) * 10
}

#[derive(Debug)]
pub struct RealTimeClock;

impl ClockDriver for RealTimeClock {
    // FIXME: Multiple cores cannot read the correct value.
    unsafe fn read_clock_raw(&self) -> u64 {
        without_interrupts(|| {
            // 0A  RTC Status register A:
            // 	|7|6|5|4|3|2|1|0|  RTC Status Register A
            //  | | | | `---------- rate selection Bits for divider output
            //  | | | |		 frequency (set to 0110 = 1.024kHz, 976.562æs)
            //  | `-------------- 22 stage divider, time base being used;
            //  |			  (initialized to 010 = 32.768kHz)
            //  `-------------- 1=time update in progress, 0=time/date available

            // Read all the times.
            let mut second = read_rtc(0x00) as u64;
            let mut minute = read_rtc(0x02) as u64;
            let mut hour = read_rtc(0x04) as u64;
            let mut day = read_rtc(0x07) as u64;
            let mut month = read_rtc(0x08) as u64;
            let mut year = read_rtc(0x09) as u64;

            // Binary Coded Decimal, or BCD, is another process for converting decimal numbers into their binary equivalents.
            if read_rtc(0x0b) & (1 << 2) == 0 {
                second = decode_bcd(second);
                minute = decode_bcd(minute);
                hour = decode_bcd(hour);
                day = decode_bcd(day);
                month = decode_bcd(month);
                year = decode_bcd(year);
            }

            year += 2000;

            if month <= 2 {
                month += 10;
                year -= 1;
            } else {
                month -= 2;
            }

            let mut timepoint = 0u64;
            timepoint +=
                (year / 4 - year / 100 + year / 400 + 367 * month / 12 + day) + year * 365 - 719499;
            timepoint = timepoint * 24 + hour;
            timepoint = timepoint * 60 + minute;
            timepoint = timepoint * 60 + second;

            timepoint
        })
    }

    fn read_clock(&self) -> Duration {
        Duration::from_secs(unsafe { self.read_clock_raw() })
    }
}

impl Driver for RealTimeClock {
    fn dispatch(&self, _irq: Option<u64>) -> bool {
        false
    }

    fn ty(&self) -> Type {
        Type::Rtc
    }

    fn uuid(&self) -> &'static str {
        RTC_UUID
    }
}

pub fn init_rtc() {
    let rtc = Arc::new(RealTimeClock {});
    RTC_DRIVERS.write().push(rtc);
}

pub fn read_clock() -> KResult<Duration> {
    match RTC_DRIVERS.read().first() {
        Some(rtc) => Ok(rtc.read_clock()),
        None => Err(Errno::EEXIST),
    }
}

pub fn read_clock_raw() -> KResult<u64> {
    match RTC_DRIVERS.read().first() {
        Some(rtc) => Ok(unsafe { rtc.read_clock_raw() }),
        None => Err(Errno::EEXIST),
    }
}
