//! Starts the kernel.

use boot_header::Header;
use core::{
    hint::spin_loop,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    arch::{
        acpi::init_acpi,
        cpu::{cpu_id, init_cpu, measure_frequency, print_cpu_topology, AP_UP_NUM, CPU_NUM},
        interrupt::init_interrupt_all,
        mm::paging::{init_kernel_page_table, init_mm},
        timer::{init_apic_timer, TimerSource, TIMER_SOURCE},
    },
    drivers::{
        keyboard::init_keyboard, pci_bus::init_pci, rtc::init_rtc, serial::init_all_serial_ports,
    },
    kmain,
    logging::init_env_logger,
    memory::init_heap,
    LOG_LEVEL,
};

use super::cpu::ApHeader;

// Indicates whether the bootstrap processor has initialized.
pub static AP_CAN_INIT: AtomicBool = AtomicBool::new(false);
/// The entry point of kernel
#[no_mangle]
pub unsafe extern "C" fn _start(header: &'static Header) -> ! {
    // Initialize the heap.
    let heap = init_heap();

    // Initialize RTC for read.
    init_rtc();

    // Initialize logging on the fly.
    // This operation is safe as long as the macro is not called.
    init_env_logger().unwrap();
    // Initialize the serial port for logging.
    init_all_serial_ports();

    kwarn!("_start(): logger started!");
    kinfo!("_start(): logging level is {}", *LOG_LEVEL);
    kinfo!("_start(): heap starts at {:#x}", heap);

    if let Err(errno) = init_kernel_page_table() {
        panic!(
            "_start(): failed to initialize kernel page tables! Errno: {:?}",
            errno
        );
    }
    kinfo!("_start(): initialized kernel page tables");

    // Print boot header.
    kinfo!("_start(): boot header:\n{:#x?}", header);
    // Initialize the memory management (paging).
    if let Err(errno) = init_mm(header) {
        panic!(
            "init_mem(): failed to initialize the memory management module! Errno: {:?}",
            errno
        );
    }
    kinfo!("_start(): initialized memory management.");

    // Initialize the interrupt-related data structures and handlers.
    if let Err(errno) = init_interrupt_all() {
        panic!(
            "init_interrupt_all(): failed to initialize the interrupt! Errno: {:?}",
            errno
        );
    }
    kinfo!("_start(): initialized traps, syscalls and interrupts.");

    if let Err(errno) = init_cpu() {
        panic!("_start(): failed to initialize CPU #0. Errno: {:?}", errno);
    }
    kinfo!("_start(): initialized x2APIC.");

    print_cpu_topology();

    if let Err(errno) = init_pci() {
        panic!("_start(): failed to initialize PCI. Errno: {:?}", errno);
    }
    kinfo!("_start(): initialized PCI devices.");

    init_keyboard();
    kinfo!("_start(): initialized keyboard.");

    if let Err(errno) = init_acpi(header) {
        panic!(
            "_start(): failed to initialize the ACPI table! Errno: {:?}",
            errno
        );
    }
    kinfo!("_start(): initialized ACPI.");

    measure_frequency();

    if TIMER_SOURCE.load(Ordering::Relaxed) != TimerSource::Hpet {
        if let Err(errno) = init_apic_timer() {
            panic!(
                "_start(): failed to initialize the APIC timer due to {:?}",
                errno
            );
        }
    }

    // Step into the kernel main function.
    AP_CAN_INIT.store(true, Ordering::Relaxed);

    // Wait for all APs.
    while AP_UP_NUM.load(Ordering::Relaxed) != *CPU_NUM.get().unwrap() - 1 {
        spin_loop();
    }

    kmain();
}

/// The entry function for the application processors. If the `ap_trampoline.S` file is written correctly,
/// then the AP should be able to call `_start_ap` (which is loaded into rax).
#[no_mangle]
pub unsafe extern "C" fn _start_ap(ap_header: *mut ApHeader) -> ! {
    // Wait for BSP.
    while !AP_CAN_INIT.load(Ordering::Relaxed) {
        spin_loop();
    }

    let header = ApHeader::from_raw(ap_header);
    kinfo!("_start_ap(): reading header: {:#x?}", header);

    // Setup interrupt and related data structures.
    if let Err(errno) = init_interrupt_all() {
        panic!(
            "init_interrupt_all(): failed to initialize the interrupt! Errno: {:?}",
            errno
        );
    }
    kinfo!("_start(): initialized traps, syscalls and interrupts.");

    if let Err(errno) = init_cpu() {
        let cpu_id = cpu_id();
        panic!(
            "init_cpu(): failed to initialize CPU #{:#x}. Errno: {:?}",
            cpu_id, errno
        );
    }

    AP_UP_NUM.fetch_add(0x1, Ordering::Relaxed);

    // Jump into the main routine.
    kmain();
}
