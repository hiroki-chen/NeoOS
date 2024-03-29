//! Extended APIC module.
//!
//! If x2APIC is enabled for the kernel and there CPU does no support it (usually when you are using macOS's HVF accelerator),
//! the kernel will fallback to this controller.

use bit_field::BitField;

use crate::error::KResult;

use super::{ApicInfo, ApicSupport, ApicType};

pub const LAPIC_ADDR: usize = 0xfee00000;

const CMOS_PORT: u16 = 0x70;
const CMOS_RETURN: u16 = 0x71;
const ID: u32 = 0x0020; // ID
const VER: u32 = 0x0030; // Version
const TPR: u32 = 0x0080; // Task Priority
const EOI: u32 = 0x00B0; // EOI
const SVR: u32 = 0x00F0; // Spurious Interrupt Vector
const ENABLE: u32 = 0x00000100; // Unit Enable
const ESR: u32 = 0x0280; // Error Status
const ICRLO: u32 = 0x0300; // Interrupt Command
const INIT: u32 = 0x00000500; // INIT/RESET
const STARTUP: u32 = 0x00000600; // Startup IPI
const DELIVS: u32 = 0x00001000; // Delivery status
const ASSERT: u32 = 0x00004000; // Assert interrupt (vs deassert)
const DEASSERT: u32 = 0x00000000;
const LEVEL: u32 = 0x00008000; // Level triggered
const BCAST: u32 = 0x00080000; // Send to all APICs, including self.
const BUSY: u32 = 0x00001000;
const FIXED: u32 = 0x00000000;
const ICRHI: u32 = 0x0310; // Interrupt Command [63:32]
const TIMER: u32 = 0x0320; // Local Vector Table 0 (TIMER)
const X1: u32 = 0x0000000B; // divide counts by 1
const PERIODIC: u32 = 0x00020000; // Periodic
const PCINT: u32 = 0x0340; // Performance Counter LVT
const LINT0: u32 = 0x0350; // Local Vector Table 1 (LINT0)
const LINT1: u32 = 0x0360; // Local Vector Table 2 (LINT1)
const ERROR: u32 = 0x0370; // Local Vector Table 3 (ERROR)
const MASKED: u32 = 0x00010000; // Interrupt masked
const TICR: u32 = 0x0380; // Timer Initial Count
const TCCR: u32 = 0x0390; // Timer Current Count
const TDCR: u32 = 0x03E0; // Timer Divide Configuration

const T_IRQ0: u32 = 32; // IRQ 0 corresponds to int T_IRQ
const IRQ_TIMER: u32 = 0;
const IRQ_KBD: u32 = 1;
const IRQ_COM1: u32 = 4;
const IRQ_IDE: u32 = 14;
const IRQ_ERROR: u32 = 19;
const IRQ_SPURIOUS: u32 = 31;

/// The extended APIC instance with a base IO/Mapped address of the control register. This I/O mapped address, however,
/// must be correctly mapped into the kernel virtual address.
pub struct XApic(u64);

impl ApicSupport for XApic {
    fn init(&self) {
        unsafe {
            // Enable local APIC; set spurious interrupt vector.
            self.write(SVR, ENABLE | (T_IRQ0 + IRQ_SPURIOUS));

            // The timer repeatedly counts down at bus frequency
            // from lapic[TICR] and then issues an interrupt.
            // If xv6 cared more about precise timekeeping,
            // TICR would be calibrated using an external time source.
            self.write(TDCR, X1);
            self.write(TIMER, PERIODIC | (T_IRQ0 + IRQ_TIMER));
            self.write(TICR, 10000000);

            // Disable logical interrupt lines.
            self.write(LINT0, MASKED);
            self.write(LINT1, MASKED);

            // Disable performance counter overflow interrupts
            // on machines that provide that interrupt entry.
            if (self.read(VER) >> 16 & 0xFF) >= 4 {
                self.write(PCINT, MASKED);
            }

            // Map error interrupt to IRQ_ERROR.
            self.write(ERROR, T_IRQ0 + IRQ_ERROR);

            // Clear error status register (requires back-to-back writes).
            self.write(ESR, 0);
            self.write(ESR, 0);

            // Ack any outstanding interrupts.
            self.write(EOI, 0);

            // Send an Init Level De-Assert to synchronise arbitration ID's.
            self.write(ICRHI, 0);
            self.write(ICRLO, BCAST | INIT | LEVEL);
            while self.read(ICRLO) & DELIVS != 0 {}

            // Enable interrupts on the APIC (but not on the processor).
            self.write(TPR, 0);
        }
    }

    fn get_info(&self) -> ApicInfo {
        unsafe {
            let id = self.read(ID) >> 24;
            let version = self.read(VER);

            ApicInfo { id, version }
        }
    }

    fn eoi(&self) {
        unsafe {
            self.write(EOI, 0);
        }
    }

    fn set_icr(&self, icr: u64) {
        unsafe {
            while self.read(ICRLO).get_bit(12) {
                core::hint::spin_loop();
            }

            self.write(ICRHI, (icr >> 32) as u32);
            self.write(ICRLO, icr as u32);

            while self.read(ICRLO).get_bit(12) {
                core::hint::spin_loop();
            }
        }
    }

    fn send_ipi(&self, target: u8, val: u8) {
        self.set_icr((target as u64) << 56 | val as u64);
    }

    fn ty(&self) -> ApicType {
        ApicType::XApic
    }

    // TODO: Implement me.
    fn init_timer(&self) -> KResult<()> {
        Ok(())
    }
}

impl XApic {
    pub fn new(base: u64) -> Self {
        Self(base)
    }

    /// Writes something to the target register.
    pub unsafe fn write(&self, reg: u32, data: u32) {
        core::ptr::write_volatile((self.0 + reg as u64) as *mut u32, data);
        self.read(0x20);
    }

    /// Reads something from the target register.
    pub unsafe fn read(&self, reg: u32) -> u32 {
        core::ptr::read_volatile((self.0 + reg as u64) as *const u32)
    }
}
