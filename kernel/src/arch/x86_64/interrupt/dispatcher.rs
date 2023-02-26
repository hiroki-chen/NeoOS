//! This module implementes the interrupt handlers.

use log::{debug, error, info, trace};

use crate::{
    arch::{
        self,
        interrupt::{
            eoi, timer::handle_timer, BREAKPOINT_INTERRUPT, DOUBLE_FAULT_INTERRUPT, IRQ_MAX,
            IRQ_MIN, PAGE_FAULT_INTERRUPT, TIMER_INTERRUPT,
        },
        mm::pretty_interpret,
    },
    drivers::IRQ_MANAGER,
    process::thread::current,
};

use super::TrapFrame;

/// Defines how the kernel handles the interrupt / exceptions when the control is passed to it.
#[no_mangle]
pub extern "C" fn __trap_dispatcher(tf: &mut TrapFrame) {
    // Dispatch based on tf.trap_num.
    match tf.trap_num {
        BREAKPOINT_INTERRUPT => dump_all(tf),
        PAGE_FAULT_INTERRUPT => page_fault(tf),
        DOUBLE_FAULT_INTERRUPT => {
            error!("__trap_dispatcher(): interrupt cannot be handled! CPU is dead.");
            arch::cpu::die()
        }
        IRQ_MIN..=IRQ_MAX => {
            eoi(tf.trap_num as u8);

            let irq = tf.trap_num - IRQ_MIN;
            if irq == TIMER_INTERRUPT {
                // Prevent logging when timer interrupt occurs because the previous contexts may hold
                // the lock so that the whole program hangs due to deadlock.
                handle_timer();
            } else {
                // Dispatch.
                if let Err(errno) = IRQ_MANAGER.read().dispatch_irq(irq as u64) {
                    error!("__trap_dispatcher(): IRQ manager returned {:?}", errno);
                } else {
                    trace!("__trap_dispatcher() IRQ handled.");
                }
            }
        }

        _ => panic!(
            "__trap_dispatcher(): unrecognized type {:#x?}!",
            tf.trap_num
        ),
    }
}

/// Simply dumps the tf.
#[inline(always)]
fn dump_all(tf: &mut TrapFrame) {
    info!("dump_all(): dumped tf (Not TensorFlow :)) as\n{:#x?}", tf);
}

/// Handles page fault.
fn page_fault(tf: &mut TrapFrame) {
    let pf_addr = arch::mm::paging::get_pf_addr();
    debug!(
        "page_fault(): detected page fault interrupt @ {:#x}. Layout:",
        pf_addr
    );

    pretty_interpret(tf.error_code);

    let thread = match current() {
        Ok(t) => t,
        Err(errno) => {
            error!(
                "page_fault(): no current thread running! Errno: {:?}",
                errno
            );
            arch::cpu::die();
        }
    };

    let mut vm = thread.vm.lock();
    if !vm.handle_page_fault(pf_addr) {
        error!("page_fault(): this thread cannot handle page fault!");
        arch::cpu::die();
    }
}
