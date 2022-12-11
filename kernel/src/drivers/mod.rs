pub mod serial;

use alloc::sync::Arc;
use alloc::vec::Vec;
use lazy_static::lazy_static;
use serial::SerialDriver;
use spin::RwLock;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Type {
    SERIAL,
}

/// A driver must implement it.
pub trait Driver: Send + Sync {
    /// Handles device-specific interrupts.
    fn dispatch(&self, irq: Option<u64>) -> bool;
    /// Returns the device type.
    fn ty(&self) -> Type;
}

lazy_static! {
    /// All the abstract devices.
    pub static ref DRIVERS: RwLock<Vec<Arc<dyn Driver>>> = RwLock::new(Vec::new());
    /// Mainly 0x3f8 and 0x2f8 ports. A thread-safe reference-counting pointer
    pub static ref SERIAL_DRIVERS: RwLock<Vec<Arc<dyn SerialDriver>>> = RwLock::new(Vec::new());
}
