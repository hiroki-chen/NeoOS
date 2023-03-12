use alloc::sync::Arc;

use crate::{
    arch::{interrupt::SYSCALL_REGS_NUM, signal::SigContext},
    error::{Errno, KResult},
    memory::copy_from_user,
    process::thread::{Thread, ThreadContext},
    signal::{SigFrame, Signal},
};

const NON_MASKABLE_SIGNALS: &[Signal; 3] = &[Signal::SIGSTOP, Signal::SIGKILL, Signal::SIGABRT];

pub fn sys_rt_sigaction(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<u64> {
    // Explanation:
    //
    // rdi: int signal
    // rsi: const struct sigaction* action
    // rdx: struct sigaction* oldaction
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

    // Prepare the registers.

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
