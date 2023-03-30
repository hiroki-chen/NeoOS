pub mod block;
pub mod intel_e1000;
pub mod keyboard;
pub mod pci_bus;
pub mod rtc;
pub mod serial;

mod isomorphic_drivers;

use crate::sync::mutex::SpinLock as Mutex;

use alloc::vec::Vec;
use alloc::{collections::BTreeMap, sync::Arc};
use lazy_static::lazy_static;
use serial::SerialDriver;
use spin::RwLock;

use crate::{drivers::rtc::ClockDriver, irq::IrqManager};

use self::block::BlockDriver;
use self::intel_e1000::NetworkDriver;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Type {
    Net,
    Serial,
    Keyboard,
    Rtc,
    Block,
}

pub const SERIAL_COM_0_UUID: &str = "097e522c-6380-417d-9077-5b76565ba5be";
pub const SERIAL_COM_1_UUID: &str = "a7e92bf8-5991-45cf-b38a-7b3c8255cb14";
pub const RTC_UUID: &str = "4e5a153a-feba-42b0-83c0-be82048d0cfd";
pub const KEYBOARD_UUID: &str = "320a2453-56a7-4ee7-9e1f-ed7c7203cf91";
pub const AHCI_UUID: &str = "bc2403fe-de27-4d14-ba44-156255240df3";
pub const NETWORK_UUID: &str = "85c8f606-cc80-11ed-afa1-0242ac120002";

/// A driver must implement it.
pub trait Driver: Send + Sync {
    /// Handles device-specific interrupts.
    fn dispatch(&self, irq: Option<u64>) -> bool;
    /// Returns the device type.
    fn ty(&self) -> Type;
    /// Returns UUID of the driver.
    fn uuid(&self) -> &'static str;
}

lazy_static! {
    /// All the abstract devices.
    pub static ref DRIVERS: RwLock<Vec<Arc<dyn Driver>>> = RwLock::new(Vec::new());
    /// Mainly 0x3f8 and 0x2f8 ports + keyboard. A thread-safe reference-counting pointer
    pub static ref SERIAL_DRIVERS: RwLock<Vec<Arc<dyn SerialDriver>>> = RwLock::new(Vec::new());
    pub static ref RTC_DRIVERS: RwLock<Vec<Arc<dyn ClockDriver>>> = RwLock::new(Vec::new());
    /// IRQ manager.
    pub static ref IRQ_MANAGER: RwLock<IrqManager> = RwLock::new(IrqManager::new(true));
    /// PCI
    pub static ref PCI_DRIVERS: Mutex<BTreeMap<pci::Location, Arc<dyn Driver>>> = Mutex::new(BTreeMap::new());
    /// Block driver.
    pub static ref BLOCK_DRIVERS: RwLock<Vec<Arc<dyn BlockDriver>>> = RwLock::new(Vec::new());
    /// Network driver.
    pub static ref NETWORK_DRIVERS: RwLock<Vec<Arc<dyn NetworkDriver>>> = RwLock::new(Vec::new());
}
