//! Syscalls that cannot be categorized.

use alloc::sync::Arc;

use crate::{
    arch::interrupt::SYSCALL_REGS_NUM,
    dummy_impl,
    error::{Errno, KResult},
    process::thread::{Thread, ThreadContext},
    sys::{Time, Timespec, Timeval, Timezone, Utsname},
    time::{SystemTime, UNIX_EPOCH},
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
    let vm = thread.vm.lock();

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
            let ptr = vm.get_mut_ptr(addr)?;
            unsafe {
                ptr.write(ctx.get_user_context().regs.fs)?;
            }
            Ok(0)
        }
        ARCH_GET_GS => {
            let ptr = vm.get_mut_ptr(addr)?;
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

    let buf_ptr = thread.vm.lock().get_mut_ptr(buf)?;

    unsafe {
        buf_ptr.write(Utsname::default_uname())?;
    }

    Ok(0)
}

/// The functions gettimeofday() and settimeofday() can get and set the time as well as a timezone.
pub fn sys_gettimeofday(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let tv = syscall_registers[0];
    let tz = syscall_registers[1];

    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Errno::EINVAL)?;

    let vm = thread.vm.lock();
    let p_tv = vm.get_mut_ptr(tv)?;
    // The use of the timezone structure is obsolete; the tz argument should normally be specified as NULL.
    let p_tz = vm.get_mut_ptr::<Timezone>(tz)?;
    if !p_tz.is_null() {
        return Err(Errno::EINVAL);
    }

    unsafe {
        p_tv.write(Timeval {
            tv_sec: time.as_secs() as _,
            tv_usec: time.as_micros() as _,
        })
        .map(|_| 0)
    }
}

/// time() returns the time as the number of seconds since the Epoch, 1970-01-01 00:00:00 +0000 (UTC).
///
/// If tloc is non-NULL, the return value is also stored in the memory pointed to by tloc.
pub fn sys_time(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Errno::EINVAL)?;

    let tloc = syscall_registers[0];
    let p_tloc = thread.vm.lock().get_mut_ptr(tloc)?;
    unsafe {
        p_tloc.write(Time {
            time: time.as_secs() as _,
        })?;
    }

    Ok(time.as_secs() as _)
}

/// getgroups() returns the supplementary group IDs of the calling process in list. The argument size should be set to the
/// maximum number of items that can be stored in the buffer pointed to by list.
pub fn sys_getgroups(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let size = syscall_registers[0];
    let list = syscall_registers[1];

    let list = unsafe { core::slice::from_raw_parts_mut(list as *mut u64, size as _) };
    let gid = thread.parent.lock().process_group_id;

    list[0] = gid;
    Ok(1)
}

pub fn sys_clock_gettime(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    // We do not have clock id and always retrieve global clock.
    let _clock_id = syscall_registers[0];
    let tp = syscall_registers[1];

    let p_tp = thread.vm.lock().get_mut_ptr(tp)?;
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Errno::EINVAL)?;

    unsafe {
        p_tp.write(Timespec {
            tv_sec: time.as_secs(),
            tv_nsec: time.as_nanos() as _,
        })
        .map(|_| 0)
    }
}

/// The Linux-specific prlimit() system call combines and extends the functionality of setrlimit() and getrlimit().
/// It can be used to both set and get the resource limits of an arbitrary process.
pub fn sys_prlimit64(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let pid = syscall_registers[0];
    let resource = syscall_registers[1];
    let new_limit = syscall_registers[2];
    let old_limit = syscall_registers[3];

    // TODO: Implement me!

    Ok(0)
}

// To be implemented. These syscalls are sometimes needed by the application to perform timeout.
dummy_impl!(sys_getitimer, Ok(0));
dummy_impl!(sys_setitimer, Ok(0));
