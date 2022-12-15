//! Some helper functions for hanlding x2APIC, xAPIC, as well as IOAPIC.

use x86::apic::{ioapic::IoApic, x2apic::X2APIC, xapic::XAPIC};

use crate::memory::phys_to_virt;

use super::cpu::cpu_feature_info;

pub const IOAPIC_ADDR: u64 = 0xfec0_0000;

pub trait AcpiSupport {
    /// Checks if CPU supports the target feature.
    fn does_cpu_support() -> bool;
}

impl AcpiSupport for X2APIC {
    fn does_cpu_support() -> bool {
        cpu_feature_info()
            .expect("does_cpu_support(): failed to fetch CPU feature information")
            .has_x2apic()
    }
}

impl AcpiSupport for XAPIC {
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

    ioapic.enable(irq as u8, 0);
}
