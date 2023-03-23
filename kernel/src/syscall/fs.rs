//! Filesystem related system calls.
//!
//! Note however, that any operations that cause filesystem write is dangerous if you are working with apfs.

use alloc::sync::Arc;
use bitflags::bitflags;

use crate::{
    arch::interrupt::SYSCALL_REGS_NUM,
    error::KResult,
    process::thread::{Thread, ThreadContext},
    utils::{ptr::Ptr, read_user_string, split_path},
};

bitflags! {
    #[derive(Default)]
    pub struct Oflags: u64 {
        const O_RDONLY = 0x0;
        const O_WRONLY = 0x1;
        const O_RDWR   = 0x2;
        const O_CREATE = 1 << 6;
        /// error if CREATE and the file exists
        const EXCLUSIVE = 1 << 7;
        /// truncate file upon open
        const TRUNCATE = 1 << 9;
        /// append on each write
        const APPEND = 1 << 10;
        /// close on exec
        const CLOEXEC = 1 << 19;
    }
}

pub fn sys_open(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    // Add an open option.
    let mut regs = [0u64; SYSCALL_REGS_NUM];
    // DT_ATCWD.
    regs[0] = -100isize as u64;
    regs[1..4].copy_from_slice(&syscall_registers[..3]);
    sys_openat(thread, ctx, regs)
}

pub fn sys_openat(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    // Get the syscall arguments.
    let dir_fd = syscall_registers[0];
    let path = syscall_registers[1] as *const u8;
    let flags = syscall_registers[2];
    let mode = syscall_registers[3];

    kdebug!(
        "syscall parameters: dir_fd: {}, path: {:x}, flags: {:x}, mode: {:x}",
        dir_fd,
        path as u64,
        flags,
        mode
    );

    // Open the directory.
    let mut proc = thread.parent.lock();
    let path = read_user_string(path)?;
    let oflags = Oflags::from_bits_truncate(flags);

    kinfo!("opening {path} with open flags {:?}", oflags);

    if oflags.contains(Oflags::O_CREATE) {
        let (directory, filename) = split_path(&path)?;
    }

    Ok(0)
}

pub fn sys_ioctl(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let file_fd = syscall_registers[0];
    let cmd = syscall_registers[1];
    let arg1 = syscall_registers[2];
    let arg2 = syscall_registers[3];
    let arg3 = syscall_registers[4];

    kdebug!(
        "syscall parameters: file_fd: {}, cmd: {}, args: {}, {}, {}",
        file_fd,
        cmd,
        arg1,
        arg2,
        arg3,
    );

    let mut proc = thread.parent.lock();
    let file = proc.get_fd(file_fd)?;
    file.ioctl(cmd, [arg1, arg2, arg3])
}

pub fn sys_write(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let file_fd = syscall_registers[0];
    let buf = unsafe { Ptr::new_with_const(syscall_registers[1] as *const u8) };
    let len = syscall_registers[2] as usize;

    let mut proc = thread.parent.lock();
    // Currently assume this is valid.
    let slice = unsafe { core::slice::from_raw_parts(buf.as_ptr(), len) };
    let file = proc.get_fd(file_fd)?;
    let len = file.write(slice)?;

    Ok(len)
}

pub async fn sys_read(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let file_fd = syscall_registers[0];
    let buf = Ptr::new(syscall_registers[1] as *mut u8);
    let len = syscall_registers[2] as usize;

    let mut proc = thread.parent.lock();
    let file = proc.get_fd(file_fd)?;
    let slice = unsafe { core::slice::from_raw_parts_mut(buf.as_ptr(), len) };
    let len = file.read(slice).await?;

    Ok(0)
}
