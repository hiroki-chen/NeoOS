use alloc::sync::Arc;
use uart_16550::SerialPort;
use x86_64::instructions::{interrupts::without_interrupts, port::Port};

use crate::{fs::devfs::tty::TTY, function, ktrace, sync::mutex::SpinLockNoInterrupt as Mutex};

use super::{Driver, DRIVERS, IRQ_MANAGER, SERIAL_COM_0_UUID, SERIAL_COM_1_UUID, SERIAL_DRIVERS};

pub const COM0_ADDR: u16 = 0x3f8;
pub const COM1_ADDR: u16 = 0x2f8;

/// Initialize the COM ports.
pub fn init_all_serial_ports() {
    let com0 = Arc::new(ComPort::new(COM0_ADDR, SERIAL_COM_0_UUID));
    let com1 = Arc::new(ComPort::new(COM1_ADDR, SERIAL_COM_1_UUID));

    // Push to the driver.
    DRIVERS.write().push(com0.clone());
    DRIVERS.write().push(com1.clone());
    // Push to the serial driver.
    SERIAL_DRIVERS.write().push(com0.clone());
    SERIAL_DRIVERS.write().push(com1.clone());
    // Push to the IRQ.
    IRQ_MANAGER.write().register_irq(0x4, com0, false);
    IRQ_MANAGER.write().register_irq(0x3, com1, false);
}

/// Driver for the serial ports. We use it to mainly print logs.
/// This trait should be driver-specific since some devices cannot be read / written.
pub trait SerialDriver: Driver {
    /// Reads a byte from the driver.
    fn read(&self) -> u8;

    /// Writes a byte array into the driver.
    fn write(&self, bytes: &[u8]);

    /// Enable the interrupt request.
    fn enable_irq(&self);
}

/// COM (communication port)[1][2] is the original, yet still common, name of the serial port interface on PC-compatible
/// computers. It can refer not only to physical ports, but also to emulated ports, such as ports created by Bluetooth or
/// USB adapters.
pub struct ComPort {
    serial_port: Mutex<SerialPort>,
    /// Base address: 0x*f8.
    addr: u16,
    /// UUID.
    uuid: &'static str,
}

impl ComPort {
    pub fn new(addr: u16, uuid: &'static str) -> Self {
        let serial_port = Mutex::new(unsafe { SerialPort::new(addr) });
        serial_port.lock().init();
        Self {
            serial_port,
            addr,
            uuid,
        }
    }

    pub fn get_addr(&self) -> u16 {
        self.addr
    }
}

impl Driver for ComPort {
    fn dispatch(&self, irq: Option<u64>) -> bool {
        ktrace!("serial::dispatch(): received IRQ {:#x?}", irq);

        let read_byte = {
            let read_byte = self.read();
            // Convert '\r' to '\n'.
            if read_byte == 0xd {
                0xa
            } else {
                read_byte
            }
        };

        // Send this key to the teleprinter device so that the application can read it.
        TTY.write_byte(read_byte);

        true
    }

    fn ty(&self) -> super::Type {
        super::Type::Serial
    }

    fn uuid(&self) -> &'static str {
        self.uuid
    }
}

impl SerialDriver for ComPort {
    fn read(&self) -> u8 {
        // Because sometimes we do not have a physical keyboard, we may need to use the serial port
        // to get some input. All the serial ports can be controlled by IRQ 3 - 4.
        self.serial_port.lock().receive()
    }

    fn write(&self, bytes: &[u8]) {
        without_interrupts(|| {
            for byte in bytes.iter() {
                self.serial_port.lock().send(*byte);
            }
        });
    }

    fn enable_irq(&self) {
        let addr = self.addr;
        // Interrupt enable register.
        let mut ier = Port::<u8>::new(addr + 0x1);
        unsafe {
            ier.write(0x07);
        }
    }
}
