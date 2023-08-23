use alloc::{boxed::Box, collections::BTreeMap};
use lazy_static::lazy_static;
use spin::RwLock;

use crate::{
    arch::{
        apic::ioapic::{IoApic, DEFAULT_IOAPIC_ADDR},
        interrupt::ISA_TO_GSI,
    },
    error::{Errno, KResult},
    memory::phys_to_virt,
};

use super::{
    cpu::{cpu_id, cpuid},
    interrupt::IRQ_MIN,
};

pub mod ioapic;

#[cfg(feature = "multiprocessor")]
pub mod ap;

cfg_if::cfg_if! {
    if #[cfg(feature = "x2apic")] {
        pub mod x2apic;
        pub use x2apic::*;
    }
}

pub mod xapic;
pub use xapic::*;

lazy_static! {
    pub static ref LOCAL_APIC: RwLock<BTreeMap<usize, Box<dyn ApicSupport>>> =
        RwLock::new(BTreeMap::new());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApicType {
    X2Apic,
    XApic,
    None,
}

pub trait ApicSupport: Send + Sync {
    /// Initializes the Local APIC on the target CPU.
    fn init(&self);

    /// Gets the apic information.
    fn get_info(&self) -> ApicInfo;

    /// Sends end of interrupt signal to the APIC.
    fn eoi(&self);

    /// Sets the interrupt control register.
    fn set_icr(&self, icr: u64);

    /// Sends the inter-processor interrupt.
    fn send_ipi(&self, target: u8, val: u8);

    /// Gets the type.
    fn ty(&self) -> ApicType;

    /// Initializes the timer source.
    fn init_timer(&self) -> KResult<()>;
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
    kinfo!("enable_irq(): enabling {irq}");

    let ioapic = IoApic::new(phys_to_virt(DEFAULT_IOAPIC_ADDR));
    let apic_pin = get_gsi(irq);
    ioapic.set_irq_vector(apic_pin, (IRQ_MIN + irq as usize) as u8);
    ioapic.enable_irq(apic_pin, 0);
}

pub fn disable_irq(irq: u64) {
    kinfo!("disable_irq(): disabling {irq}");

    let ioapic = IoApic::new(phys_to_virt(DEFAULT_IOAPIC_ADDR));
    let apic_pin = get_gsi(irq);
    ioapic.set_irq_vector(apic_pin, (IRQ_MIN + irq as usize) as u8);
    ioapic.disable_irq(apic_pin);
}

/// Initializes the local APIC.
pub fn init_apic() -> KResult<()> {
    let feature = cpuid().get_feature_info().ok_or(Errno::EINVAL)?;
    let (has_x2apic, has_xapic) = (feature.has_x2apic(), feature.has_apic());
    if let (false, false) = (has_x2apic, has_xapic) {
        kerror!("both x2APIC and xAPIC are not supported on this platform!");
        return Err(Errno::ENODEV);
    }

    #[cfg(feature = "x2apic")]
    {
        let apic: Box<dyn ApicSupport> = match has_x2apic {
            true => Box::new(X2Apic),
            false => match cfg!(feature = "xapic") {
                true => Box::new(XApic::new(phys_to_virt(LAPIC_ADDR as _))),
                false => return Err(Errno::ENODEV),
            },
        };

        apic.init();
        // Push it to the btreemap.
        LOCAL_APIC.write().insert(cpu_id(), apic);
        kinfo!("APIC initialized as x2APIC.");
    }
    #[cfg(not(feature = "x2apic"))]
    {
        let apic = match has_xapic {
            true => Box::new(XApic::new(phys_to_virt(LAPIC_ADDR as _))),
            false => return Err(Errno::ENODEV),
        };

        apic.init();
        // Push it to the btreemap.
        LOCAL_APIC.write().insert(cpu_id(), apic);
        kinfo!("APIC initialized as xAPIC.");
    }

    Ok(())
}
