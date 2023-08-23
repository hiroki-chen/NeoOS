//! Syscall interfaces for `setuid`, `setgid`, etc.

use alloc::sync::Arc;

use crate::{
    arch::interrupt::SYSCALL_REGS_NUM,
    error::KResult,
    process::thread::{Thread, ThreadContext},
};

/// Should always returns 0 as the initial one.
pub fn sys_geteuid(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    Ok(0)
}

/// Should always returns 0 as the initial one.
pub fn sys_getuid(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    Ok(0)
}

/// Should always returns 0 as the initial one.
pub fn sys_getegid(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    Ok(0)
}

/// Should always returns 0 as the initial one.
pub fn sys_getgid(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    Ok(0)
}
