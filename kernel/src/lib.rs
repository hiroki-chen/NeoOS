#![no_std]
#![no_main]
#![feature(abi_efiapi)]
#![feature(exclusive_range_pattern)]
#![feature(lang_items)]
#![feature(allocator_api)]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::panic::PanicInfo;
use mem::buddy_allocator::BuddyAllocator;

use log::error;

pub mod error;
pub mod logging;
pub mod sync;

// We currently only support x86_64
#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/mod.rs"]
pub mod arch;

/// The global allocator for the heap memory.
#[global_allocator]
static ALLOCATOR: BuddyAllocator = BuddyAllocator {};

/// `#![no_std]` is a crate level attribute that indicates that the crate will link to the core crate instead of the std crate,
/// but what does this mean for applications?
///
/// The `std` crate is Rust's standard library. It contains functionality that assumes that the program will run on an operating
/// system rather than directly on the metal. std also assumes that the operating system is a general purpose operating system,
/// like the ones one would find in servers and desktops. For this reason, std provides a standard API over functionality one
/// usually finds in such operating systems: Threads, files, sockets, a filesystem, processes, etc.
#[lang = "eh_personality"]
extern "C" fn eh_personality() {}

/// Handles the panic within the kernel.
/// If we disable standard library, we must implement it manually to properly make
/// `eh_personality` work.
#[panic_handler]
pub fn panic_unwrap(info: &PanicInfo<'_>) -> ! {
    error!("{}", info);
    loop {
        unsafe {
            core::arch::asm!("cli; hlt");
        }
    }
}

#[alloc_error_handler]
pub fn alloc_error(layout: alloc::alloc::Layout) -> ! {
    error!("buddy_allocator: allocation failed in {:?}", layout);
    loop {
        unsafe {
            core::arch::asm!("cli; hlt");
        }
    }
}
