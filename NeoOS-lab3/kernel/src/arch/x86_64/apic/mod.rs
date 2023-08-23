pub mod ioapic;

#[cfg(feature = "multiprocessor")]
pub mod ap;

cfg_if::cfg_if! {
    if #[cfg(feature = "x2apic")] {
        pub mod x2apic;
        pub use x2apic::*;
    } else {
        pub mod xapic;
        pub use xapic::*;
    }
}

use log::info;

use crate::{
    arch::{
        apic::ioapic::{IoApic, DEFAULT_IOAPIC_ADDR},
        interrupt::ISA_TO_GSI,
    },
    memory::phys_to_virt,
};

use super::interrupt::IRQ_MIN;

pub trait AcpiSupport {
    /// Checks if CPU supports the target feature.
    fn does_cpu_support() -> bool;
}

#[derive(Debug)]
pub struct ApicInfo {
    id: u32,
    version: u32,
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

    let ioapic = IoApic::new(phys_to_virt(DEFAULT_IOAPIC_ADDR));
    let apic_pin = get_gsi(irq);
    ioapic.set_irq_vector(apic_pin, (IRQ_MIN + irq as usize) as u8);
    ioapic.enable_irq(apic_pin, 0);
}

pub fn disable_irq(irq: u64) {
    info!("disable_irq(): disabling {irq}");

    let ioapic = IoApic::new(phys_to_virt(DEFAULT_IOAPIC_ADDR));
    let apic_pin = get_gsi(irq);
    ioapic.set_irq_vector(apic_pin, (IRQ_MIN + irq as usize) as u8);
    ioapic.disable_irq(apic_pin);
}
