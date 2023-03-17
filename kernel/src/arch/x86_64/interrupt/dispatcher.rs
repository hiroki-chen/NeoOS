//! This module implementes the interrupt handlers.

use alloc::sync::Arc;
use x86_64::instructions::tlb::flush_all;

use crate::{
    arch::{
        self,
        cpu::AbstractCpu,
        interrupt::{
            eoi, ipi::IpiType, timer::handle_timer, BREAKPOINT_INTERRUPT, DOUBLE_FAULT_INTERRUPT,
            GENERAL_PROTECTION_INTERRUPT, IRQ_MAX, IRQ_MIN, PAGE_FAULT_INTERRUPT, TIMER_INTERRUPT,
        },
        mm::{
            paging::{get_pf_addr, handle_page_fault},
            pretty_interpret,
        },
    },
    drivers::IRQ_MANAGER,
    process::thread::{current, Thread, ThreadContext},
    syscall::handle_syscall,
};

use super::{TrapFrame, INVALID_OPCODE_INTERRUPT, SYSCALL};

/// Defines how the kernel handles the interrupt / exceptions when the control is passed to it.
#[no_mangle]
pub extern "C" fn __trap_dispatcher(tf: &mut TrapFrame) {
    ktrace!(
        "__trap_dispatcher(): trap frame number: {:#x?}",
        tf.trap_num
    );

    // Dispatch based on tf.trap_num.
    match tf.trap_num {
        BREAKPOINT_INTERRUPT => dump_all(tf),
        GENERAL_PROTECTION_INTERRUPT => {
            kerror!("__trap_dispatcher(): segmentation fault!");
            arch::cpu::die()
        }
        PAGE_FAULT_INTERRUPT => page_fault(tf),
        DOUBLE_FAULT_INTERRUPT => {
            kerror!("__trap_dispatcher(): interrupt cannot be handled! CPU is dead.");
            arch::cpu::die()
        }
        IRQ_MIN..=IRQ_MAX => {
            handle_irq(tf.trap_num as _, false, None);
        }
        ipi => {
            if (IpiType::TlbFlush as u8..=IpiType::Others as u8).contains(&(ipi as u8)) {
                handle_ipi(ipi as _);
            } else {
                panic!(
                    "__trap_dispatcher(): unrecognized type {:#x?}!",
                    tf.trap_num
                )
            }
        }
    }
}

/// The interrupt handler for user-space applications. The return value indicates whether the application can be resumed.
/// If so, resume the context; otherwise, abort the application due to some unrecoverable errors.
pub async fn trap_dispatcher_user(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    should_yield: &mut bool,
) -> bool {
    let tf = ctx.get_trapno();
    match tf {
        BREAKPOINT_INTERRUPT => {
            kinfo!("spawn(): breakpoint!");
            true
        }

        INVALID_OPCODE_INTERRUPT => {
            kerror!("spawn(): invalid opcode.");
            false
        }
        GENERAL_PROTECTION_INTERRUPT => {
            kerror!("spawn(): illegal instruction.");
            false
        }
        PAGE_FAULT_INTERRUPT => {
            let cr2 = get_pf_addr();
            kinfo!(
                "spawn(): thread {:#x} triggered page fault @ {:#x}",
                thread.id,
                cr2
            );

            if !handle_page_fault(cr2) {
                // Report SEGSEV.
                panic!("spawn(): Segmentation fault.");
                false
            } else {
                true
            }
        }
        IRQ_MIN..IRQ_MAX => handle_irq(tf as _, true, Some(should_yield)),
        SYSCALL => handle_syscall(thread, ctx).await,
        tf => {
            kerror!("spawn(): not supported {:#x}.", tf);
            false
        }
    }
}

/// Handle an interrupt.
///
/// This function takes an interrupt number as an argument, acknowledges the interrupt using EOI
/// (end of interrupt), and dispatches the interrupt to the appropriate handler. If the interrupt
/// is the timer interrupt, it invokes `handle_timer` function to prevent logging when timer interrupt
/// occurs. Otherwise, it calls the `dispatch_irq` method of the `IRQ_MANAGER` to dispatch the interrupt
/// to the appropriate handler. If the `dispatch_irq` method returns an error, it logs the error and returns
/// `false`, otherwise it returns `true`.
///
/// This functions also takes as input the value `user` indicating whether the kernel is dealing with user interrupt
/// and a callback `cb` to be invoked later.
fn handle_irq(trapno: u8, user: bool, should_yield: Option<&mut bool>) -> bool {
    eoi(trapno);

    // Must check before we handle the IRQ.
    assert!(
        !user || matches!(should_yield, Some(_)),
        "handle_irq(): user IRQ must be installed with a callback!"
    );

    let irq = trapno - IRQ_MIN as u8;
    if irq == TIMER_INTERRUPT as u8 {
        if user {
            *should_yield.unwrap() = true;
        }
        // Prevent logging when timer interrupt occurs because the previous contexts may hold
        // the lock so that the whole program hangs due to deadlock.
        handle_timer();
        true
    } else {
        // Dispatch.
        if let Err(errno) = IRQ_MANAGER.read().dispatch_irq(irq as u64) {
            kerror!("__trap_dispatcher(): IRQ manager returned {:?}", errno);
            false
        } else {
            ktrace!("__trap_dispatcher() IRQ handled.");
            true
        }
    }
}

/// Handle an inter-processor interrupt (IPI).
///
/// This function takes an inter-processor interrupt number as an argument, acknowledges the interrupt using
/// EOI (end of interrupt), and dispatches the interrupt to the appropriate handler. It matches the interrupt number
/// with an `IpiType` using `transmute` function. If the interrupt is `TlbFlush`, it calls `flush_all` function to flush
/// the TLB entries. If the interrupt is `WakeUp`, it does nothing. If the interrupt is `Others`, it pops the event from the
/// current CPU's event queue using `pop_event` method of the `AbstractCpu`. Finally, it returns `true`.
fn handle_ipi(ipi: u8) -> bool {
    eoi(ipi - IRQ_MIN as u8);

    match unsafe { core::mem::transmute::<u8, IpiType>(ipi as _) } {
        IpiType::TlbFlush => flush_all(),
        // Does nothing.
        IpiType::WakeUp => (),
        IpiType::Others => AbstractCpu::current().unwrap().pop_event(),
    }

    true
}

/// Simply dumps the tf.
#[inline(always)]
fn dump_all(tf: &mut TrapFrame) {
    kinfo!("dump_all(): dumped tf (Not TensorFlow :)) as\n{:#x?}", tf);
}

/// Handles page fault.
fn page_fault(tf: &mut TrapFrame) {
    let pf_addr = arch::mm::paging::get_pf_addr();
    kdebug!(
        "page_fault(): detected page fault interrupt @ {:#x}. Layout:",
        pf_addr
    );

    pretty_interpret(tf.error_code);

    let thread = match current() {
        Ok(t) => t,
        Err(errno) => {
            kerror!(
                "page_fault(): no current thread running! Errno: {:?}",
                errno
            );
            arch::cpu::die();
        }
    };

    let mut vm = thread.vm.lock();
    if !vm.handle_page_fault(pf_addr) {
        kerror!("page_fault(): this thread cannot handle page fault!");
        arch::cpu::die();
    }
}
