//! In computing, an inter-processor interrupt (IPI), also known as a shoulder tap, is a special type of interrupt
//! by which one processor may interrupt another processor in a multiprocessor system if the interrupting
//! processor requires action from the other processor. Actions that might be requested include:
//! * flushes of memory management unit caches, such as translation lookaside buffers, on other processors when
//!   memory mappings are changed by one processor;
//! * stopping when the system is being shut down by one processor.
//! * Notify a processor that higher priority work is available.
//! * Notify a processor of work that cannot be done on all processors due to, e.g.,
//! * asymmetric access to I/O channels[1] special features on some processors

use apic::{LocalApic, X2Apic};
use log::debug;

use crate::arch::acpi::{AP_STARTUP, AP_TRAMPOLINE};

/// This function deals with sending the initial IPI to the corresponding APs to indicate that they should be awaken.
///
/// In general; INIT IPI is like a soft reset for the (logical) CPU, that puts it into a "wait for SIPI state".
/// The Intel manuals have a table showing the default values of various registers after power on, after reset
/// and after INIT IPI.
///
/// # References
/// * https://stackoverflow.com/questions/40083533/what-is-the-effect-of-startup-ipi-on-application-processor
pub fn send_init_ipi(dst: u64) {
    debug!("send_init_ipi(): sending INIT IPI to {:#x}...", dst);
    // Select IPI.
    let icr = 0x4500 | dst << 32;
    // By default, we use x2APIC.
    let mut lapic = X2Apic {};
    lapic.set_icr(icr);
}

/// This function deals with sending the startup IPI to the corresponding APs to indicate that they could start
/// executing the `AP_TRAMPOLINE_CODE` assembly code and jumps to protected mode.
///
/// The Startup IPI is a way to tell the CPU to start executing at a certain address (an address derived from the
/// "vector field" of the Startup IPI) before a usable IDT can be set up. This also bumps the CPU out of the "wait
/// for SIPI state". Some (most) CPUs will respond to a Startup IPI when they aren't in the "wait for SIPI state",
/// but without a previous INIT IPI you can't expect the CPU to be in a known/safe state at the time.
pub fn send_startup_ipi(dst: u64) {
    debug!("send_startup_ipi(): sending startup IPI to {:#x}...", dst);
    // Start at 0x1000:0000 => 0x10000.
    let ap_segment = (AP_STARTUP >> 12) & 0xff;
    let icr = 0x4600 | dst << 32 | ap_segment;
    // By default, we use x2APIC.
    let mut lapic = X2Apic {};
    lapic.set_icr(icr);
}
