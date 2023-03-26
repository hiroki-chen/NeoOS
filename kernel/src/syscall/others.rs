//! Syscalls that cannot be categorized.

use alloc::sync::Arc;

use crate::{
    arch::interrupt::SYSCALL_REGS_NUM,
    error::{Errno, KResult},
    process::thread::{Thread, ThreadContext},
    sys::Utsname,
    utils::ptr::Ptr,
};

const ARCH_SET_GS: u64 = 0x1001;
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const ARCH_GET_GS: u64 = 0x1004;

/// arch_prctl - set architecture-specific thread state
///
/// ```c
/// int syscall(SYS_arch_prctl, int code, unsigned long addr);
/// int syscall(SYS_arch_prctl, int code, unsigned long *addr);
/// ```
pub fn sys_arch_prctl(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    #[cfg(not(target_arch = "x86_64"))]
    compile_error!("arch_prctl cannot be implemented on other platforms.");

    let code = syscall_registers[0];
    let addr = syscall_registers[1];

    match code {
        ARCH_SET_FS => {
            ctx.get_user_context().regs.fs = addr;
            Ok(0)
        }
        ARCH_SET_GS => {
            ctx.get_user_context().regs.gs = addr;
            Ok(0)
        }
        ARCH_GET_FS => {
            let ptr = Ptr::new(addr as *mut u64);
            unsafe {
                ptr.write(ctx.get_user_context().regs.fs)?;
            }
            Ok(0)
        }
        ARCH_GET_GS => {
            let ptr = Ptr::new(addr as *mut u64);
            unsafe {
                ptr.write(ctx.get_user_context().regs.gs)?;
            }
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// uname() returns system information in the structure pointed to by buf.
/// The utsname struct is defined in <sys/utsname.h>.
pub fn sys_uname(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let buf = syscall_registers[0];

    let buf_ptr = Ptr::new(buf as *mut Utsname);
    thread.vm.lock().check_write_array(&buf_ptr, 1)?;

    unsafe {
        buf_ptr.write(Utsname::default_uname())?;
    }

    Ok(0)
}
