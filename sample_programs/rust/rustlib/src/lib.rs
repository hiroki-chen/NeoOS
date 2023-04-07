//! A `no_std` library for our operating system. This library partially rewrites the std library of Rust.

#![no_std]
#![allow(unused)]
#![feature(lang_items)]
#![feature(linkage)]
#![feature(start)]
#![feature(format_args_nl)]

extern crate alloc;

use core::{alloc::Layout, panic::PanicInfo};

use buddy_system_allocator::LockedHeap;
use io::init_logger;
use sys::sys_exit;

#[macro_use]
pub mod io;

pub mod sys;
pub mod fs;

#[lang = "eh_personality"]
fn eh_personality() {}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // println!("program panicked: {}", info);
    loop {}
}

// Linked when loading.
#[linkage = "weak"]
#[no_mangle]
fn main() {
    panic!("No main() found.");
}

/// Called before `main`. The workflow is: kernel loader --> _start() -> linked main() --> _start() quit.
#[no_mangle]
pub unsafe extern "C" fn _start(_argc: isize, _argv: *const *const u8) {
    heap_init();
    init_logger();
    main();
    sys_exit(0);
}

fn heap_init() {
    static mut INIT_HEAP: [u8; 0x1000] = [0u8; 0x1000];
    unsafe {
        ALLOCATOR
            .lock()
            .init(INIT_HEAP.as_mut_ptr() as _, INIT_HEAP.len());
    }
}

#[global_allocator]
static ALLOCATOR: LockedHeap<32> = LockedHeap::new();
