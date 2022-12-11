//! Starts the kernel.

use boot_header::Header;
use core::{
    hint::spin_loop,
    sync::atomic::{AtomicBool, Ordering},
};
use log::warn;

use crate::{
    drivers::serial::init_all_serial_ports, kmain, logging::init_env_logger, memory::init_heap,
};

use super::cpu::{self, start_core};

static OK_THIS_CORE: AtomicBool = AtomicBool::new(false);

/// The entry point of kernel
#[no_mangle]
pub unsafe extern "C" fn _start(header: &'static Header) -> ! {
    let cpu_id = cpu::cpu_id();
    // Prevent multiple cores.
    if cpu_id != 0 {
        while OK_THIS_CORE.load(Ordering::Relaxed) != true {
            spin_loop();
        }
        // Start other cores.
        start_core();
    }

    // Initialize the heap.
    init_heap();
    // Initialize logging on the fly.
    // This operation is safe as long as the macro is not called.
    init_env_logger().unwrap();
    // Initialize the serial port for logging.
    init_all_serial_ports();

    warn!("Env logger started!");
    // Step into the kernel main function.
    OK_THIS_CORE.store(true, Ordering::Relaxed);
    kmain();
}
