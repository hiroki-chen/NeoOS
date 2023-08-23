//! A simple driver for handling PC keyboards, with both Scancode Set 1 (when running
//! on a PC) and Scancode Set 2 support (when reading a PS/2 keyboard output directly).

use alloc::sync::Arc;
use pc_keyboard::{layouts::Us104Key, DecodedKey, HandleControl, KeyCode, Keyboard, ScancodeSet1};
use x86_64::instructions::port::Port;

use crate::sync::mutex::SpinLockNoInterrupt as Mutex;

use super::{
    serial::SerialDriver, Driver, Type, DRIVERS, IRQ_MANAGER, KEYBOARD_UUID, SERIAL_DRIVERS,
};

/// Represents an abstract "Keyboard".
pub struct SystemKeyboard {
    keyboard: Mutex<Keyboard<Us104Key, ScancodeSet1>>,
}

impl SystemKeyboard {
    pub fn new() -> Self {
        Self {
            keyboard: Mutex::new(Keyboard::new(HandleControl::Ignore)),
        }
    }

    pub fn handle_keys(&self, key: DecodedKey) {
        match key {
            DecodedKey::Unicode(code) => {
                let mut code_buf = [0u8; 0x4];
                let utf8 = code.encode_utf8(&mut code_buf);
                // Handle it.
                // TODO: This is be printed to TTY.
                self.write(utf8.as_bytes());
            }
            DecodedKey::RawKey(code) => {
                let s = match code {
                    // We do not have cursors, perhaps.
                    KeyCode::ArrowUp => "\u{1b}[A",
                    KeyCode::ArrowDown => "\u{1b}[B",
                    KeyCode::ArrowRight => "\u{1b}[C",
                    KeyCode::ArrowLeft => "\u{1b}[D",
                    _ => "",
                };

                // TODO: This is be printed to TTY.
                self.write(s.as_bytes());
            }
        }
    }
}

impl Driver for SystemKeyboard {
    /// Handles keyboard input events.
    fn dispatch(&self, _irq: Option<u64>) -> bool {
        let mut keyboard = self.keyboard.lock();
        // The "8042" PS/2 Controller or its predecessors, dealing with keyboards and mice.
        let mut data_port = Port::<u8>::new(0x60);
        let mut st_port = Port::<u8>::new(0x64);

        let data = unsafe { st_port.read() };
        // Arrival.
        if data & 1 != 0 {
            let input = unsafe { data_port.read() };

            if let Ok(Some(e)) = keyboard.add_byte(input) {
                if let Some(key) = keyboard.process_keyevent(e) {
                    self.handle_keys(key);
                }
            }
        }

        true
    }

    fn ty(&self) -> Type {
        Type::Keyboard
    }

    fn uuid(&self) -> &'static str {
        KEYBOARD_UUID
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

    fn enable_irq(&self) {
        panic!("Should not call me!");
    }
}

pub fn init_keyboard() {
    let keyboard = Arc::new(SystemKeyboard::new());
    DRIVERS.write().push(keyboard.clone());
    SERIAL_DRIVERS.write().push(keyboard.clone());
    IRQ_MANAGER.write().register_irq(0x1, keyboard, false);
}
