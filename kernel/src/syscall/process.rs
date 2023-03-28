//! Syscall interfaces for process and thread.

use alloc::sync::Arc;

use crate::{
    arch::interrupt::SYSCALL_REGS_NUM,
    error::KResult,
    process::{
        search_by_group_id,
        thread::{Thread, ThreadContext},
    },
    sync::futex::Futex,
    utils::ptr::Ptr,
};

use super::PROC_EXITED;

/// The system call set_tid_address() sets the clear_child_tid value for the calling thread to tidptr.
pub fn sys_set_tid_address(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let tidptr = syscall_registers[0];

    thread.inner.lock().clear_child_tid = tidptr;

    Ok(0)
}

/// Tells the kernel that the current process ends.
pub fn sys_exit(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let error_code = syscall_registers[0];

    // Exit the current thread.
    let mut proc = thread.parent.lock();
    proc.threads.retain(|&t| t != thread.id);

    if proc.threads.is_empty() {
        proc.exit(error_code as _);
    }

    // When a thread whose clear_child_tid is not NULL terminates, then,
    // if the thread is sharing memory with other threads, then 0 is
    // written at the address specified in clear_child_tid and the
    // kernel performs the following operation:
    //      futex(clear_child_tid, FUTEX_WAKE, 1, NULL, NULL, 0);
    // The effect of this operation is to wake a single thread that is
    // performing a futex wait on the memory location.  Errors from the
    // futex wake operation are ignored.
    let clear_child_tid = thread.inner.lock().clear_child_tid;
    if clear_child_tid != 0 {
        let ptr = Ptr::new(clear_child_tid as *mut u32);
        if let Ok(tid) = thread.vm.lock().check_write_array(&ptr, 1) {
            unsafe {
                ptr.write(0)?;
            }

            // Get the fast userspace mutex lock.
            let futex = proc
                .futexes
                .entry(clear_child_tid)
                .or_insert(Arc::new(Futex::new(0)));
            futex.futex_wake(1);
        }
    }

    drop(proc);
    *PROC_EXITED.write().entry(thread.id).or_insert(true) = true;

    Ok(0)
}

/// Tells the kernel that the current process exits all the groups.
pub fn sys_exit_group(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let error_code = syscall_registers[0];

    let mut proc = thread.parent.lock();
    proc.exit(error_code as _);

    let gid = proc.process_group_id;
    // Invoke all other threads with the same group id.
    let procs = search_by_group_id(gid);

    drop(proc);
    *PROC_EXITED.write().entry(thread.id).or_insert(true) = true;

    Ok(0)
}

pub fn sys_getpid(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    Ok(thread.id as _)
}

/// sched_yield() causes the calling thread to relinquish the CPU. The thread is moved to the end of the queue for its static
/// priority and a new thread gets to run.
pub fn sys_sched_yield(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    Ok(0)
}
