//! Some helper functions for hanlding x2APIC, xAPIC, as well as IOAPIC.

use apic::{IoApic, X2Apic, XApic, IOAPIC_ADDR};
use log::info;

use crate::{arch::interrupt::ISA_TO_GSI, memory::phys_to_virt};

use super::{cpu::cpu_feature_info, interrupt::IRQ_MIN};

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

pub fn get_gsi(irq: u64) -> u8 {
    let mapping = ISA_TO_GSI.read();

    match mapping.get(&(irq as u8)) {
        None => irq as u8,
        Some(&pin) => pin as u8,
    }
}

/// Registers the interrupt request into IOAPIC.
pub fn enable_irq(irq: u64) {
    info!("enable_irq(): enabling {irq}");

    let mut ioapic = unsafe { IoApic::new(phys_to_virt(IOAPIC_ADDR as u64) as usize) };
    let apic_pin = get_gsi(irq);
    ioapic.set_irq_vector(apic_pin as u8, (IRQ_MIN + irq as usize) as u8);
    ioapic.enable(apic_pin as u8, 0);
}

pub fn disable_irq(irq: u64) {
    let mut ioapic = unsafe { IoApic::new(phys_to_virt(IOAPIC_ADDR as u64) as usize) };
    let apic_pin = get_gsi(irq);
    ioapic.disable(apic_pin);
}
