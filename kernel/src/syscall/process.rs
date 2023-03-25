//! Syscall interfaces for process and thread.

use alloc::sync::Arc;

use crate::{
    arch::interrupt::SYSCALL_REGS_NUM,
    error::KResult,
    process::thread::{Thread, ThreadContext},
};

/// The system call set_tid_address() sets the clear_child_tid value for the calling thread to tidptr.
pub fn sys_set_tid_address(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let tidptr = syscall_registers[0];

    thread.inner.lock().clear_child_td = tidptr;

    Ok(0)
}

/// Tells the kernel that the current process ends.
pub fn sys_exit(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let error_code = syscall_registers[0];

    Ok(0)
}

/// Tells the kernel that the current process exits all the groups.
pub fn sys_exit_group(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    Ok(0)
}
