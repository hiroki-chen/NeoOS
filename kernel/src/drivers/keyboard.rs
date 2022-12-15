//! A simple driver for handling PC keyboards, with both Scancode Set 1 (when running
//! on a PC) and Scancode Set 2 support (when reading a PS/2 keyboard output directly).

use alloc::sync::Arc;
use pc_keyboard::{layouts::Us104Key, HandleControl, Keyboard, ScancodeSet1};

use crate::sync::mutex::SpinLockNoInterrupt as Mutex;

use super::{serial::SerialDriver, Driver, Type, DRIVERS, KEYBOARD_UUID, SERIAL_DRIVERS};

/// Represents an abstract "Keyboard".
pub struct SystemKeyboard {
    keyboard: Mutex<Keyboard<Us104Key, ScancodeSet1>>,
    uuid: &'static str,
}

impl SystemKeyboard {
    pub fn new() -> Self {
        Self {
            keyboard: Mutex::new(Keyboard::new(HandleControl::Ignore)),
            uuid: KEYBOARD_UUID,
        }
    }
}

impl Driver for SystemKeyboard {
    fn dispatch(&self, irq: Option<u64>) -> bool {
        true
    }

    fn ty(&self) -> Type {
        Type::KEYBOARD
    }

    fn uuid(&self) -> &'static str {
        self.uuid
    }
}

impl SerialDriver for SystemKeyboard {
    fn read(&self) -> u8 {
        // Do nothing!
        panic!("Cannot attempt to read from keyboard! Should be handled by interrupt!");
    }

    fn write(&self, _bytes: &[u8]) {
        // Do nothing!
        panic!("Write to keyboard is meaningless!");
    }
}

pub fn init_keyboard() {
    let keyboard = Arc::new(SystemKeyboard::new());
    DRIVERS.write().push(keyboard.clone());
    SERIAL_DRIVERS.write().push(keyboard);
}
