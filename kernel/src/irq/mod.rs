//! An IRQ is an interrupt request from a device. Currently they can come in over a pin, or over a packet.
//! Several devices may be connected to the same pin thus sharing an IRQ.
//! The generic interrupt handling layer is designed to provide a complete abstraction of interrupt handling for
//! device drivers. It is able to handle all the different types of interrupt controller hardware. Device drivers
//! use generic API functions to request, enable, disable and free interrupts. The drivers do not have to know
//! anything about interrupt hardware details, so they can be used on different platforms without code changes.
//!
//! In Rust, these 'generic' behaviors can be implemented by trait. Any devices must implement `Driver` and derive
//! traits! So we can manage the device tree conveniently.
//!

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use atomic_enum::atomic_enum;

use crate::{
    arch::apic::enable_irq,
    drivers::Driver,
    error::{Errno, KResult},
};

pub static IRQ_TYPE: AtomicIrqType = AtomicIrqType::new(IrqType::Pic);

#[repr(u8)]
#[derive(Eq, PartialEq, PartialOrd, Ord)]
#[atomic_enum]
pub enum IrqType {
    Pic = 0,
    Apic = 1,
}

pub struct IrqManager {
    is_root: bool,
    /// Indicates the devices that handle a certain IRQ.
    irq_devices: BTreeMap<u64, Vec<Arc<dyn Driver>>>,
    /// Devices that can handle all IRQs.
    irq_all: Vec<Arc<dyn Driver>>,
}

impl IrqManager {
    pub fn new(is_root: bool) -> Self {
        Self {
            is_root,
            irq_devices: BTreeMap::new(),
            irq_all: Vec::new(),
        }
    }

    /// Registers a given interrupt request driver into `IrqManager`.
    pub fn register_irq(&mut self, irq: u64, driver: Arc<dyn Driver>, all: bool) {
        // Root manager should enable IRQ.
        if self.is_root {
            enable_irq(irq);
        }

        if all {
            self.irq_all.push(driver.clone());
        } else {
            self.irq_devices.entry(irq).or_default().push(driver);
        }
    }

    pub fn remove_irq(&mut self, irq: u64, driver: Arc<dyn Driver>, all: bool) {
        match all {
            true => self.irq_all.retain(|x| x.uuid() != driver.uuid()),
            false => {
                if self.irq_devices.contains_key(&irq) {
                    self.irq_devices
                        .entry(irq)
                        .and_modify(|v| v.retain(|x| x.uuid() != driver.uuid()));
                }
            }
        }
    }

    /// Dispatches the IRQ to the corresponding controller.
    pub fn dispatch_irq(&self, irq: u64) -> KResult<()> {
        // Check unique handler.
        if self.irq_devices.contains_key(&irq) {
            if let Some(drivers) = self.irq_devices.get(&irq) {
                // Try to handle it.
                for d in drivers.iter() {
                    if d.dispatch(Some(irq)) {
                        return Ok(());
                    }
                }
            }
        }

        // Tries to iterate all.
        for d in self.irq_all.iter() {
            if d.dispatch(Some(irq)) {
                return Ok(());
            }
        }

        // No handler at all!
        Err(Errno::ENODEV)
    }
}
