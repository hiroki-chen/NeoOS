//! Starts the kernel.

use boot_header::Header;
use core::{
    hint::spin_loop,
    sync::atomic::{AtomicBool, Ordering},
};
use log::{error, info, warn};

use crate::{
    arch::{acpi::init_acpi, interrupt::init_interrupt_all, mm::init_mm},
    drivers::serial::init_all_serial_ports,
    kmain,
    logging::init_env_logger,
    memory::init_heap,
    LOG_LEVEL,
};

use super::cpu::{self, start_core};

static OK_THIS_CORE: AtomicBool = AtomicBool::new(false);

/// The entry point of kernel
#[no_mangle]
pub unsafe extern "C" fn _start(header: &'static Header) -> ! {
    let cpu_id = cpu::cpu_id();
    // Prevent multiple cores.
    if cpu_id != 0 {
        while !OK_THIS_CORE.load(Ordering::Relaxed) {
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

    warn!("_start(): logger started!");
    info!("_Start(): logging level is {}", *LOG_LEVEL);

    // Print boot header.
    info!("_start(): boot header:\n{:#x?}", header);
    // Initialize the memory management (paging).
    if let Err(errno) = init_mm(header) {
        error!(
            "init_mem(): failed to initialize the memory management module! Errno: {:?}",
            errno
        );
    }
    info!("_start(): initialized memory management.");

    // Initialize the interrupt-related data structures and handlers.
    if let Err(errno) = init_interrupt_all() {
        error!(
            "init_interrupt_all(): failed to initialize the interrupt! Errno: {:?}",
            errno
        );
    }
    info!("_start(): initialized traps, syscalls and interrupts.");

    if let Err(errno) = init_acpi(header) {
        error!(
            "init_acpi(): failed to initialize the ACPI table! Errno: {:?}",
            errno
        );
    }
    info!("init_acpi(): initialized ACPI.");
    
    // Step into the kernel main function.
    OK_THIS_CORE.store(true, Ordering::Relaxed);

    kmain();
}
