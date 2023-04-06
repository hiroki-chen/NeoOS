//! In computing, an inter-processor interrupt (IPI), also known as a shoulder tap, is a special type of interrupt
//! by which one processor may interrupt another processor in a multiprocessor system if the interrupting
//! processor requires action from the other processor. Actions that might be requested include:
//! * flushes of memory management unit caches, such as translation lookaside buffers, on other processors when
//!   memory mappings are changed by one processor;
//! * stopping when the system is being shut down by one processor.
//! * Notify a processor that higher priority work is available.
//! * Notify a processor of work that cannot be done on all processors due to, e.g.,
//! * asymmetric access to I/O channels[1] special features on some processors

use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicUsize, Ordering};
use num_enum::TryFromPrimitive;

use crate::arch::{
    acpi::AP_STARTUP,
    apic::{ApicType, LOCAL_APIC},
    cpu::{cpu_id, CPUS, CPU_NUM},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, TryFromPrimitive)]
#[repr(u8)]
pub enum IpiType {
    /// Indicates that the target CPU(s) should flush the TLB (Translation Looka-side Buffer).
    TlbFlush = 0x40,
    /// Indicates that the target CPU(s) should be woken up.
    WakeUp = 0x41,
    /// The SCHED IPI used to notify the target core that it needs to migrate its runqueue.
    Sched = 0x42,
    /// Other Ipi types. This carries a callback for the target CPU to be exeucted.
    Others = 0x43,
}

/// This function deals with sending the initial IPI to the corresponding APs to indicate that they should be awaken.
///
/// In general; INIT IPI is like a soft reset for the (logical) CPU, that puts it into a "wait for SIPI state".
/// The Intel manuals have a table showing the default values of various registers after power on, after reset
/// and after INIT IPI.
///
/// # References
/// * https://stackoverflow.com/questions/40083533/what-is-the-effect-of-startup-ipi-on-application-processor
pub fn send_init_ipi(dst: u64) {
    kinfo!("sending INIT IPI to {:#x}...", dst);

    let lock = LOCAL_APIC.read();
    let lapic = lock.get(&cpu_id()).unwrap();
    // Select IPI.
    let icr = match lapic.ty() {
        ApicType::X2Apic => 0x4500 | dst << 32,
        ApicType::XApic => 0x4500 | dst << 56,
        ApicType::None => panic!("invalid APIC"),
    };

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
    kinfo!("sending startup IPI to {:#x}...", dst);
    // Start at 0x1000:0000 => 0x10000.
    let ap_segment = (AP_STARTUP >> 12) & 0xff;

    let lock = LOCAL_APIC.read();
    let lapic = lock.get(&cpu_id()).unwrap();
    // Select IPI.
    let icr = match lapic.ty() {
        ApicType::X2Apic => 0x4600 | ap_segment | dst << 32,
        ApicType::XApic => 0x4600 | ap_segment | dst << 56,
        ApicType::None => panic!("invalid APIC"),
    };

    lapic.set_icr(icr);
}

/// This function sends the callback `cb` to `target` if `target` is not [`None`]; otherwise, all cores will receive an
/// IPI. Also, `sync` denotes whether we should wait all cores to finish their IPI jobs. If so, we give a hint
/// [`core::hint::spin_loop`] to the invoker and put it to wait state.
///
/// # Note
///
/// The function/closure must implement [`core::marker::Send`] and [`core::marker::Sync`] so that is can be safely shared
/// across different threads. Rust automatically implements these two traits for closures. One should also note that the
/// function [`apic::LocalApic::send_ipi`] for [`apic::X2Apic`] is wrong.
pub fn send_ipi<T>(cb: T, target: Option<u8>, sync: bool, ipi_type: IpiType)
where
    T: Fn() + Send + Sync + 'static,
{
    let this_cpu = cpu_id();
    let lock = LOCAL_APIC.read();
    let lapic = lock.get(&cpu_id()).unwrap();
    let cb = Arc::new(cb);
    let finished = Arc::new(AtomicUsize::new(0x0));

    let cpu_num = match target {
        Some(_) => 0x1,
        None => *CPU_NUM.get().unwrap(),
    };

    match target {
        Some(target) => unsafe {
            let finished_cloned = finished.clone();

            if ipi_type == IpiType::Others {
                CPUS.get(target as usize)
                    .unwrap()
                    .get()
                    .unwrap()
                    .push_event(Box::new(move || {
                        cb.clone()();
                        finished_cloned.fetch_add(0x1, Ordering::Relaxed);
                    }));
            }

            // Send IPI via icr. Note that the offset for X2Apic is 32.
            lapic.send_ipi(target, ipi_type as _);
        },
        None => {
            // Invoke all!
            for cpu in unsafe {
                CPUS.iter().filter(|cpu| {
                    if let Some(cpu) = cpu.get() {
                        cpu.cpu_id != this_cpu
                    } else {
                        false
                    }
                })
            } {
                let cpu = cpu.get().unwrap();
                let cb_cloned = cb.clone();
                let finished_cloned = finished.clone();

                if ipi_type == IpiType::Others {
                    cpu.push_event(Box::new(move || {
                        cb_cloned();
                        finished_cloned.fetch_add(0x1, Ordering::Relaxed);
                    }));
                }
                lapic.send_ipi(cpu.cpu_id as _, ipi_type as _);
            }
        }
    }

    while sync && finished.load(Ordering::Relaxed) != cpu_num {
        core::hint::spin_loop();
    }
}
