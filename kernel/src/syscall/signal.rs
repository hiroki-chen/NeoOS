use alloc::sync::Arc;

use crate::{
    arch::{interrupt::SYSCALL_REGS_NUM, signal::SigContext},
    error::{Errno, KResult},
    memory::{copy_from_user, copy_to_user},
    process::thread::{Thread, ThreadContext},
    signal::{SigAction, SigFrame, SigSet, Signal},
};

const NON_MASKABLE_SIGNALS: &[Signal; 3] = &[Signal::SIGSTOP, Signal::SIGKILL, Signal::SIGABRT];

/// The sigaction() system call is used to change the action taken by a process on receipt of a specific signal.
/// (See signal(7) for an overview of signals.)
///
/// signum specifies the signal and can be any valid signal except [`Signal::SIGSTOP`], [`Signal::SIGKILL`], and
/// [`Signal::SIGABRT`].
///
/// * If `act` is non-NULL, the new action for signal signum is installed from `act`.
/// * If `oldact` is non-NULL, the previous action is saved in `oldact`.
pub fn sys_rt_sigaction(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<u64> {
    // Explanation:
    //
    // rdi: int signal
    // rsi: const struct sigaction* act
    // rdx: struct sigaction* oldact
    // r10: size_t sigsetsize
    let signal = unsafe { core::mem::transmute::<u64, Signal>(syscall_registers[0]) };
    let action = syscall_registers[1];
    let old_action = syscall_registers[2];
    let size = syscall_registers[3] as usize;

    kdebug!(
        "sys_rt_sigaction: signal = {:?}, action = {:#x}, oldaction = {:#x}, size = {:#x}",
        signal,
        action,
        old_action,
        size
    );

    // Check if the given signal can be set with a custom signal action.
    if NON_MASKABLE_SIGNALS.iter().any(|e| matches!(e, signal)) {
        kerror!("cannot mask these signals: {:?}", NON_MASKABLE_SIGNALS);
        return Err(Errno::EINVAL);
    }

    // Check sigset size.
    if size != core::mem::size_of::<SigSet>() {
        kerror!(
            "sigset size invalid: expected {:#x}, got {:#x}.",
            core::mem::size_of::<SigSet>(),
            size
        );
        return Err(Errno::EINVAL);
    }

    let mut process = thread.parent.lock();

    // Check if oldact is null.
    if !old_action == 0 {
        // Copy to user.
        if let Err(errno) = unsafe {
            copy_to_user(
                &process.actions[signal as usize] as *const SigAction,
                old_action as *mut SigAction,
            )
        } {
            kerror!("cannot set the oldact pointer. Errno: {:?}", errno);
            return Err(errno);
        }
    }

    // Check if act is null.
    if !action == 0 {
        let newact = match unsafe { copy_from_user(action as *const SigAction) } {
            Ok(newact) => newact,
            Err(errno) => {
                kerror!("cannot read from user's act!");
                return Err(errno);
            }
        };
        process.actions[signal as usize] = newact;
    }

    Ok(0)
}

pub fn sys_rt_sigreturn(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<u64> {
    // Copy the pointer from the user space into the kernel.
    let sig_frame_ptr =
        (ctx.get_user_context().get_rsp() - core::mem::size_of::<u64>() as u64) as *const SigFrame;
    let mut sig_frame = match unsafe { copy_from_user(sig_frame_ptr) } {
        Ok(sig_frame) => sig_frame,
        Err(errno) => {
            kerror!("cannot copy from the user space! Errno: {:?}", errno);
            return Err(errno);
        }
    };

    // Process the signal on the alternative stack.
    kdebug!("handling `sys_ret_sigreturn`");
    {
        thread.inner.lock().sigaltstack = sig_frame.ucontext.uc_stack;
    }

    // Restore the context and resume it. ThreadContext -> User Context -> Signal Frame
    sig_frame.ucontext.uc_context = SigContext::from_uctx(ctx.get_user_context());
    Ok(ctx.get_user_context().regs.rax)
}
