//! The Programmable Interval Timer (PIT) chip (Intel 8253/8254) basically consists of an oscillator, a prescaler
//! and 3 independent frequency dividers. Each frequency divider has an output, which is used to allow the timer
//! to control external circuitry (for example, IRQ 0).

use lazy_static::lazy_static;
use spin::RwLock;
use x86_64::instructions::port::Port;

use crate::error::KResult;

use super::apic::enable_irq;

// 1 / (1.193182 MHz) = 838,095,110 femtoseconds ~= 838.095 ns
pub const PERIOD_FS: u128 = 838_095_110;
// 11931 / (1.193182 MHz) ~= 10.0 ms
pub const CHAN0_DIVISOR: u16 = 11931;
pub const RATE: u128 = (CHAN0_DIVISOR as u128 * PERIOD_FS) / 1_000_000;

const SELECT_CHAN0: u8 = 0b00 << 6;
const ACCESS_LATCH: u8 = 0b00 << 4;
const ACCESS_LOHI: u8 = 0b11 << 4;
const MODE_2: u8 = 0b110;

lazy_static! {
    pub static ref PIT: RwLock<Pit> = RwLock::new(Pit::new());
}

pub struct Pit {
    chan0: Port<u8>,
    #[allow(unused)]
    chan1: Port<u8>,
    #[allow(unused)]
    chan2: Port<u8>,
    command: Port<u8>,
}

impl Pit {
    pub const fn new() -> Self {
        Self {
            chan0: Port::new(0x40),
            chan1: Port::new(0x41),
            chan2: Port::new(0x42),
            command: Port::new(0x43),
        }
    }

    pub fn read(&mut self) -> u16 {
        unsafe {
            self.command.write(SELECT_CHAN0 | ACCESS_LATCH);
            let low = self.chan0.read();
            let high = self.chan0.read();
            let counter = ((high as u16) << 8) | (low as u16);

            // Counter is inverted, subtract from CHAN0_DIVISOR
            CHAN0_DIVISOR.saturating_sub(counter)
        }
    }
}

pub fn init_pit() -> KResult<()> {
    let mut pit = PIT.write();
    unsafe {
        pit.command.write(SELECT_CHAN0 | ACCESS_LOHI | MODE_2);
        pit.chan0.write(CHAN0_DIVISOR as u8 & 0xff);
        pit.chan0.write((CHAN0_DIVISOR >> 8) as u8 & 0xff);
    }

    // Enable PIT IRQ.
    enable_irq(0x0);

    Ok(())
}
