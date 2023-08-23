#![cfg_attr(not(test), no_std)]
#![no_main]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::uninit_assumed_init)]
#![allow(clippy::new_without_default)]
#![allow(clippy::fn_to_numeric_cast)]
#![allow(clippy::empty_loop)]
#![allow(clippy::identity_op)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::declare_interior_mutable_const)]
#![allow(unused_variables)]
#![allow(unreachable_code)]
#![allow(dead_code)]
#![feature(addr_parse_ascii)]
#![feature(ip_in_core)]
#![feature(atomic_from_mut)]
#![feature(naked_functions)]
#![feature(c_size_t)]
#![feature(linkage)]
#![feature(allocator_api)]
#![feature(core_intrinsics)]
#![feature(rustc_attrs)]
#![feature(alloc_error_handler)]
#![feature(exclusive_range_pattern)]
#![feature(inline_const)]
#![feature(format_args_nl)]
#![feature(lang_items)]

extern crate alloc;

pub mod debug;
pub mod drivers;
pub mod elf;
pub mod fs;
pub mod irq;
pub mod net;
pub mod sys;

#[macro_use]
pub mod error;
#[macro_use]
pub mod logging;
#[macro_use]
pub mod memory;

pub mod mm;
pub mod process;
pub mod signal;
pub mod sync;
pub mod syscall;
pub mod time;
pub mod trigger;
pub mod utils;

#[cfg(target_arch = "x86_64")]
pub mod f32;
#[cfg(target_arch = "x86_64")]
pub mod f64;

use alloc::string::String;
use core::panic::PanicInfo;
use lazy_static::lazy_static;
use process::scheduler::FIFO_SCHEDULER;
// We do not want OOM to cause kernel crash.
use buddy_system_allocator::LockedHeapWithRescue;

use crate::{
    arch::cpu::{cpu_id, BSP_ID},
    debug::{Frame, UNWIND_DEPTH},
    logging::print_banner,
};

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
    if cpu_id() == BSP_ID.get().copied().unwrap() as usize {
        kinfo!("kmain(): kernel main procedure started.");
        print_banner();
    }

    cpu_idle();
}

pub fn cpu_idle() -> ! {
    loop {
        FIFO_SCHEDULER.start_schedule();
        x86_64::instructions::interrupts::enable_and_hlt();
    }
}

/// The global allocator for the heap memory.
///
/// Note that we use the on-the-shelf implementation for the heap allocator with kernel-level.
/// spin lock [`mutex::SpinLockNoInterrupt`] and a heap grow utility function to rescue us from OOM.
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
    // TODO: Make backtrace more meaningful.
    kerror!("{}", info);
    let frame = Frame::new();
    frame.unwind(*UNWIND_DEPTH);
    arch::cpu::die();
}

#[alloc_error_handler]
pub fn alloc_error(layout: alloc::alloc::Layout) -> ! {
    kerror!("allocator: allocation failed in {:?}", layout);
    arch::cpu::die();
}

/// Panics when stack smash is detected (to prevent ROPs)
pub extern "C" fn __stack_chk_fail() -> ! {
    panic!("__stack_chk_fail(): Stack smashing detected!");
}
