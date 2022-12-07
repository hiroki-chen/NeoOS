#![no_std]
#![feature(lang_items)]

use core::panic::PanicInfo;

pub mod logging;
pub mod sync;

#[lang = "eh_personality"]
extern "C" fn eh_personality() {}

/// Handles the panic within the kernel.
/// If we disable standard library, we must implement it manually to properly make
/// `eh_personality` work.
#[panic_handler]
pub fn panic_unwrap(info: &PanicInfo) -> ! {
  todo!()
}
