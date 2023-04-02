#![no_std]
#![no_main]

#[macro_use]
extern crate neo_std as std;

use log::info;

/// Must be `no_mangle` to ensure that our standard library can find this symbol.
#[no_mangle]
pub fn main() {
    info!("[Rust] This is from rust application.");
}
