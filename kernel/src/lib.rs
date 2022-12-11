#![no_std]
#![no_main]
#![feature(abi_efiapi)]
#![feature(exclusive_range_pattern)]
#![feature(lang_items)]
#![feature(allocator_api)]
#![feature(alloc_error_handler)]

extern crate alloc;

pub mod error;
pub mod logging;
pub mod memory;
pub mod sync;
pub mod drivers;

use core::panic::PanicInfo;
use log::error;
// We do not want OOM to cause kernel crash.
use buddy_system_allocator::LockedHeapWithRescue;

pub const LOG_LEVEL: &'static str = "info";

// We currently only support x86_64
#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/mod.rs"]
pub mod arch;

/// Kernel main. It mainly performs CPU idle to wait for scheduling, if any.
pub fn kmain() -> ! {
    loop {
        // TODO.
    }
}

/// The global allocator for the heap memory.
/// Note that we use the on-the-shelf implementation for the heap allocator with kernel-level.
/// spin lock `SpinLockNoInterrupt` and a heap grow utility function to rescue us from OOM.
/// Before oom, the allocator will try to call rescue function and try for one more time. 
#[global_allocator]
static ALLOCATOR: LockedHeapWithRescue<32> = LockedHeapWithRescue::new(memory::grow_heap_on_oom);

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
