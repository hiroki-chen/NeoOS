//! This module implements IO related operations. Especially print.

use core::fmt::Arguments;

use alloc::string::ToString;

use crate::drivers::SERIAL_DRIVERS;

pub fn writefmt(arg: Arguments) {
    // Default to serial port.
    // RwLock<Vec<Arc<dyn SerialDriver>>>
    let mut serial_port_driver = SERIAL_DRIVERS.write();
    serial_port_driver
        .first_mut()
        .unwrap()
        .write(arg.to_string().as_bytes());
}
