//! Starts the kernel.

use boot::header::Header;
use core::arch::asm;

/// The entry point of kernel
#[no_mangle]
pub unsafe extern "C" fn _start(header: &Header) -> ! {
    // Test if this works!

    loop {
      asm!("mov rdx, {}", in(reg) header.version as u64);
    }
}
