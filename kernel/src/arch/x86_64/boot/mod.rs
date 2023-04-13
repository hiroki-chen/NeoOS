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
    memory::{init_heap, phys_to_virt},
    process::scheduler::FIFO_SCHEDULER,
    LOG_LEVEL,
};

use super::cpu::ApHeader;

// Indicates whether the bootstrap processor has initialized.
pub static AP_CAN_INIT: AtomicBool = AtomicBool::new(false);
/// The entry point of kernel
#[no_mangle]
pub unsafe extern "C" fn _start(header: *const Header) -> ! {
    let header = unsafe { &*(header) };
    // Initialize the heap.
    let heap = init_heap();

    // Initialize RTC for read.
    init_rtc();

    // Initialize logging on the fly.
    // This operation is safe as long as the macro is not called.
    init_env_logger().unwrap();
    // Initialize the serial port for logging.
    init_all_serial_ports();

    kwarn!("logger started!");
    kinfo!("logging level is {}", *LOG_LEVEL);
    kinfo!("heap starts at {:#x}", heap);

    if let Err(errno) = init_kernel_page_table() {
        panic!(
            "failed to initialize kernel page tables! Errno: {:?}",
            errno
        );
    }
    kinfo!("initialized kernel page tables");

    // Print boot header.
    kdebug!("boot header:\n{:#x?}", header);
    // Initialize the memory management (paging).
    if let Err(errno) = init_mm(header) {
        panic!(
            "init_mem(): failed to initialize the memory management module! Errno: {:?}",
            errno
        );
    }
    kinfo!("initialized memory management.");

    // Initialize the interrupt-related data structures and handlers.
    if let Err(errno) = init_interrupt_all() {
        panic!(
            "init_interrupt_all(): failed to initialize the interrupt! Errno: {:?}",
            errno
        );
    }
    kinfo!("initialized traps, syscalls and interrupts.");

    if let Err(errno) = init_cpu() {
        panic!("failed to initialize CPU #0. Errno: {:?}", errno);
    }
    kinfo!("initialized xAPIC/x2APIC.");

    print_cpu_topology();

    if let Err(errno) = init_pci() {
        panic!("failed to initialize PCI. Errno: {:?}", errno);
    }
    kinfo!("initialized PCI devices.");

    init_keyboard();
    kinfo!("initialized keyboard.");

    if let Err(errno) = init_acpi(header) {
        panic!("failed to initialize the ACPI table! Errno: {:?}", errno);
    }
    kinfo!("initialized ACPI.");

    measure_frequency();

    if TIMER_SOURCE.load(Ordering::Relaxed) != TimerSource::Hpet {
        if let Err(errno) = init_apic_timer() {
            panic!("failed to initialize the APIC timer due to {:?}", errno);
        }
    }
    kinfo!("initialized APIC timer");

    let first_proc = unsafe {
        core::slice::from_raw_parts(
            phys_to_virt(header.first_proc as u64) as *const u8,
            header.first_proc_len as usize,
        )
    };
    let args = unsafe {
        core::slice::from_raw_parts(
            phys_to_virt(header.args as u64) as *const u8,
            header.args_len as usize,
        )
    };
    let first_proc = core::str::from_utf8(first_proc).unwrap_or_default();
    let args = core::str::from_utf8(args).unwrap_or_default();
    FIFO_SCHEDULER.init();
    crate::process::thread::init_ash(first_proc, args);

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
    kdebug!("reading header: {:#x?}", header);

    // Setup interrupt and related data structures.
    if let Err(errno) = init_interrupt_all() {
        panic!(
            "init_interrupt_all(): failed to initialize the interrupt! Errno: {:?}",
            errno
        );
    }
    kinfo!("initialized traps, syscalls and interrupts.");

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
