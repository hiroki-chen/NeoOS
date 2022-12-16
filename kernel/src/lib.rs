#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::uninit_assumed_init)]
#![allow(clippy::new_without_default)]
#![allow(clippy::fn_to_numeric_cast)]
#![feature(abi_efiapi)]
#![feature(allocator_api)]
#![feature(alloc_error_handler)]
#![feature(exclusive_range_pattern)]
#![feature(lang_items)]

extern crate alloc;

pub mod debug;
pub mod drivers;
pub mod error;
pub mod irq;
pub mod logging;
pub mod memory;
pub mod mm;
pub mod process;
pub mod sync;
pub mod time;

use alloc::string::String;
use core::panic::PanicInfo;
use lazy_static::lazy_static;
use log::error;
// We do not want OOM to cause kernel crash.
use buddy_system_allocator::LockedHeapWithRescue;

use crate::debug::{Frame, UNWIND_DEPTH};

lazy_static! {
    pub static ref LOG_LEVEL: String = option_env!("OS_LOG_LEVEL").unwrap_or("info").to_lowercase();
}

// We currently only support x86_64
#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/mod.rs"]
pub mod arch;

extern "C" {
    /// A guard symbol for locating the top of the code segment.
    pub fn __guard_top();
    /// A guard symbol for locating the bottom of the code segment.
    pub fn __guard_bottom();
}

/// Kernel main. It mainly performs CPU idle to wait for scheduling, if any.
pub fn kmain() -> ! {
    loop {
        // todo
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
pub fn panic_unwind(info: &PanicInfo<'_>) -> ! {
    error!("{}", info);
    let frame = Frame::new();
    frame.unwind(*UNWIND_DEPTH);
    loop {
        unsafe {
            core::arch::asm!("cli; hlt");
        }
    }
}

#[alloc_error_handler]
pub fn alloc_error(layout: alloc::alloc::Layout) -> ! {
    error!("allocator: allocation failed in {:?}", layout);
    loop {
        unsafe {
            core::arch::asm!("cli; hlt");
        }
    }
}
