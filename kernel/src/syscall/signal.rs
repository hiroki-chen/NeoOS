use alloc::sync::Arc;

use crate::{
    arch::{interrupt::SYSCALL_REGS_NUM, signal::SigContext, QWORD_LEN},
    error::{Errno, KResult},
    memory::{copy_from_user, copy_to_user},
    process::{
        search_by_id, search_by_thread,
        thread::{Thread, ThreadContext},
    },
    signal::{send_signal, SiFields, SigAction, SigFrame, SigInfo, SigSet, Signal},
    sys::{SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK},
};

use super::SYS_TKILL;

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
) -> KResult<usize> {
    // Explanation:
    //
    // rdi: int signal
    // rsi: const struct sigaction* act
    // rdx: struct sigaction* oldact
    // r10: size_t sigsetsize
    let signal = Signal::from(syscall_registers[0]);
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
    if NON_MASKABLE_SIGNALS.contains(&signal) {
        kerror!(
            "cannot mask these signals: {:?}; got {signal:?}",
            NON_MASKABLE_SIGNALS
        );
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
) -> KResult<usize> {
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
    Ok(ctx.get_user_context().regs.rax as _)
}

/// The kill() system call can be used to send any signal to any process group or process.
pub fn sys_kill(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let pid = syscall_registers[0] as i64;
    let sig = syscall_registers[1];
    let signal = Signal::from(sig);

    // If pid is positive, then signal sig is sent to the process with
    // the ID specified by pid; otherwise, broadcast is needed.
    let killall = !pid.is_positive();
    let siginfo = SigInfo {
        signo: sig as _,
        code: 0,
        errno: 0,
        sifields: SiFields::default(),
    };

    if !killall {
        let current_process = search_by_id(pid as _)?;
        send_signal(current_process, -1, siginfo);
    } else {
        // Need to extract pid again.
    }

    Ok(0)
}

/// sigprocmask() is used to fetch and/or change the signal mask of the calling thread. The signal mask is the set of
/// signals whose delivery is currently blocked for the caller (see also signal(7) for more details).
pub fn sys_rt_sigprocmask(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    // const sigset_t *restrict set, sigset_t *restrict oldset
    let how = syscall_registers[0];
    let set = syscall_registers[1];
    let oldset = syscall_registers[2];
    let sigsetsize = syscall_registers[3];

    if sigsetsize != QWORD_LEN as u64 {
        return Err(Errno::EINVAL);
    }

    let vm = thread.vm.lock();
    let set = vm.get_ptr(set)?;
    let oldset = vm.get_mut_ptr(oldset)?;

    if !oldset.is_null() {
        unsafe {
            oldset.write(SigSet(thread.inner.lock().sigmask.0 as _))?;
        }
    }

    if !set.is_null() {
        let set = unsafe { set.read() }?;
        let mut thread_inner = thread.inner.lock();
        match how {
            SIG_BLOCK => thread_inner.sigmask.add_sigset(set),
            SIG_UNBLOCK => thread_inner.sigmask.remove_set(set),
            SIG_SETMASK => thread_inner.sigmask = set,
            _ => return Err(Errno::EINVAL),
        }
    }

    Ok(0)
}

/// tgkill() sends the signal sig to the thread with the thread ID tid in the thread group tgid.
pub fn sys_tkill(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let tid = syscall_registers[0];
    let sig = syscall_registers[1];

    let target = search_by_thread(tid)?;

    send_signal(
        target,
        tid as _,
        SigInfo {
            signo: sig as _,
            code: SYS_TKILL as _,
            errno: 0,
            sifields: SiFields::default(),
        },
    );

    Ok(0)
}
