//! A `no_std` library for our operating system. This library partially rewrites the std library of Rust.

#![no_std]
#![feature(lang_items)]

use core::panic::PanicInfo;

pub mod io;

#[lang = "eh_personality"]
fn eh_personality() {}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // println!("\n\n{}", info);
    loop {}
}
