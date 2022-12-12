use alloc::sync::Arc;
use uart_16550::SerialPort;

use crate::{arch::cpu::cpu_halt, sync::mutex::SpinLockNoInterrupt as Mutex};

use super::{Driver, DRIVERS, SERIAL_DRIVERS};

pub const COM0_ADDR: u16 = 0x3f8;
pub const COM1_ADDR: u16 = 0x2f8;

/// Initialize the COM ports.
pub fn init_all_serial_ports() {
    let com0 = Arc::new(ComPort::new(COM0_ADDR));
    let com1 = Arc::new(ComPort::new(COM1_ADDR));

    // Push to the driver.
    DRIVERS.write().push(com0.clone());
    DRIVERS.write().push(com1.clone());
    // Push to the serial driver.
    SERIAL_DRIVERS.write().push(com0.clone());
    SERIAL_DRIVERS.write().push(com1.clone());
    // TODO: IRQ manager.
}

/// Driver for the serial ports. We use it to mainly print logs.
/// This trait should be driver-specific since some devices cannot be read / written.
pub trait SerialDriver: Driver {
    /// Reads a byte from the driver.
    fn read(&self) -> u8;

    /// Writes a byte array into the driver.
    fn write(&self, bytes: &[u8]);
}

/// COM (communication port)[1][2] is the original, yet still common, name of the serial port interface on PC-compatible
/// computers. It can refer not only to physical ports, but also to emulated ports, such as ports created by Bluetooth or
/// USB adapters.
pub struct ComPort {
    serial_port: Mutex<SerialPort>,
    /// Base address: 0x*f8.
    addr: u16,
}

impl ComPort {
    pub fn new(addr: u16) -> Self {
        let serial_port = Mutex::new(unsafe { SerialPort::new(addr) });
        serial_port.lock().init();
        Self { serial_port, addr }
    }

    pub fn get_addr(&self) -> u16 {
        self.addr
    }
}

impl Driver for ComPort {
    fn dispatch(&self, irq: Option<u64>) -> bool {
        true
    }

    fn ty(&self) -> super::Type {
        super::Type::SERIAL
    }
}

impl SerialDriver for ComPort {
    fn read(&self) -> u8 {
        self.serial_port.lock().receive()
    }

    fn write(&self, bytes: &[u8]) {
        for byte in bytes.iter() {
            self.serial_port.lock().send(*byte);
        }
    }
}
