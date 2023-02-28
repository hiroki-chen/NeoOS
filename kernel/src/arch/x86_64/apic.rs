//! Some helper functions for hanlding x2APIC, xAPIC, as well as IOAPIC.

#[cfg(feature = "multiprocessor")]
use acpi::{madt::Madt, AcpiHandler, PhysicalMapping};

use apic::{IoApic, X2Apic, XApic, IOAPIC_ADDR};
use log::info;

use crate::{arch::interrupt::ISA_TO_GSI, error::KResult, memory::phys_to_virt};

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

#[cfg(feature = "multiprocessor")]
#[allow(unused_variables)]
pub fn init_aps<H>(madt: &PhysicalMapping<H, Madt>) -> KResult<()>
where
    H: AcpiHandler,
{
    use crate::arch::acpi::{AP_TRAMPOLINE, AP_TRAMPOLINE_CODE};

    info!("init_aps(): initializing APs.");

    let ap_trampoline_addr = phys_to_virt(AP_TRAMPOLINE);
    // Fill data into that address.
    unsafe {
        // FIXME: Why this causes segfault?
        // Possible reasons:
        // * The address is not correctly mapped.
        // * There are some other kernel components using the physical address, they will probably
        //   access the corrupted data (not likely).
        //
        // When followed by a `loop {}`, this operation causes no segfault, and the memory address stores
        // the correcct instructions => really weird.
        //
        // We currently disable this operation...
        if false {
            AP_TRAMPOLINE_CODE.iter().enumerate().for_each(|(idx, d)| {
                core::intrinsics::atomic_store_seqcst((ap_trampoline_addr as *mut u8).add(idx), *d);
            })
        }
    }
    info!("init_aps(): successfully initialized APs.");

    Ok(())
}
