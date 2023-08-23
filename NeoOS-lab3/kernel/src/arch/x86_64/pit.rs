//! The Programmable Interval Timer (PIT) chip (Intel 8253/8254) basically consists of an oscillator, a prescaler
//! and 3 independent frequency dividers. Each frequency divider has an output, which is used to allow the timer
//! to control external circuitry (for example, IRQ 0).

use lazy_static::lazy_static;
use log::error;
use spin::RwLock;
use x86_64::instructions::port::Port;

use crate::error::KResult;

use super::apic::enable_irq;

// 1 / (1.193182 MHz) = 838,095,110 femtoseconds ~= 838.095 ns
pub const PERIOD_FS: u128 = 838_095_110;
pub const PIT_FREQ: u32 = 1_193_182;
// 11931 / (1.193182 MHz) ~= 10.0 ms
pub const CHAN0_DIVISOR: u16 = 11931;
pub const RATE: u128 = (CHAN0_DIVISOR as u128 * PERIOD_FS) / 1_000_000;

const SELECT_CHAN0: u8 = 0b00 << 6;
const SELECT_CHAN2: u8 = 0b10;
const ACCESS_LATCH: u8 = 0b00 << 4;
const ACCESS_LOHI: u8 = 0b11 << 4;
const MODE_1: u8 = 0b001;
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

pub fn disable_pit() {
    let mut pit = PIT.write();

    unsafe {
        pit.command.write(SELECT_CHAN2 | ACCESS_LOHI | MODE_1);
    }
}

/// Reference:https://github.com/theseus-os/Theseus/blob/a0d7090ec7e2d3d183f1c80f81f45cfdadd5928a/kernel/pit_clock_basic/src/lib.rs
///
/// # Note
/// If you enabled IRQ0 when this functon is called, then you may need to execute `countdown` in an interrupt
/// free envrionment to prevent inaccuracy.
pub fn countdown(microseconds: u32) {
    let divisor = PIT_FREQ / (1_000_000 / microseconds);
    if divisor > u16::max_value() as u32 {
        error!("countdown(): integer overflow! Try smaller ones!");
        return;
    }

    let mut pit = PIT.write();
    let mut port_60 = Port::<u8>::new(0x60);
    let mut port_61 = Port::<u8>::new(0x61);

    unsafe {
        // see code example: https://wiki.osdev.org/APIC_timer
        let port_61_val = port_61.read();
        port_61.write(port_61_val & 0xFD | 0x1); // sets the speaker channel 2 to be controlled by PIT hardware
        pit.command.write(0b10110010); // channel 2, access mode: lobyte/hibyte, hardware-retriggerable one shot mode, 16-bit binary (not BCD)

        // set frequency; must write the low byte first and then the high byte
        pit.chan2.write(divisor as u8);
        // read from PS/2 port 0x60, which acts as a short delay and acknowledges the status register
        let _: u8 = port_60.read();
        pit.chan2.write((divisor >> 8) as u8);

        // reset PIT one-shot counter
        let port_61_val = port_61.read() & 0xFE;
        port_61.write(port_61_val); // clear bit 0
        port_61.write(port_61_val | 0x1); // set bit 0
                                          // here, PIT channel 2 timer has started counting
                                          // wait for PIT timer to reach 0, which is tested by checking bit 5
        while port_61.read() & 0x20 != 0 {}
    }
}
