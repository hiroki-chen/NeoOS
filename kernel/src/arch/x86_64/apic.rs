//! Some helper functions for hanlding x2APIC, xAPIC, as well as IOAPIC.

use apic::{IoApic, X2Apic, XApic};

use crate::memory::phys_to_virt;

use super::{cpu::cpu_feature_info, interrupt::IRQ_MIN};

pub const IOAPIC_ADDR: u64 = 0xfec0_0000;

pub trait AcpiSupport {
    /// Checks if CPU supports the target feature.
    fn does_cpu_support() -> bool;
}

impl AcpiSupport for X2Apic {
    fn does_cpu_support() -> bool {
        cpu_feature_info()
            .expect("does_cpu_support(): failed to fetch CPU feature information")
            .has_x2apic()
    }
}

impl AcpiSupport for XApic {
    fn does_cpu_support() -> bool {
        cpu_feature_info()
            .expect("does_cpu_support(): failed to fetch CPU feature information")
            .has_apic()
    }
}

/// Registers the interrupt request into IOAPIC.
#[inline(always)]
pub fn enable_irq(irq: u64) {
    let mut ioapic = unsafe { IoApic::new(phys_to_virt(IOAPIC_ADDR) as usize) };
    ioapic.set_irq_vector(irq as u8, (IRQ_MIN + irq as usize) as u8);
    ioapic.enable(irq as u8, 0);
}
