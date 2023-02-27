//! This module implements IO related operations. Especially print.

use core::fmt::Arguments;

use alloc::string::ToString;
use x86_64::instructions::interrupts::without_interrupts;

use crate::drivers::SERIAL_DRIVERS;

pub fn writefmt(arg: Arguments) {
    // Default to serial port.
    // RwLock<Vec<Arc<dyn SerialDriver>>>
    // To ensure printing can proceed, we need to prevent timer interrupt so that the lock can be properly
    // dropped; otherwise, if we do something in the handler that requries the logger, read/write causes
    // deadlock, and it never ends.
    without_interrupts(|| {
        SERIAL_DRIVERS
            .read()
            .first()
            .unwrap()
            .write(arg.to_string().as_bytes());
    })
}
