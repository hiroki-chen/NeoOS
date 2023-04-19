//! Syscall interfaces for process and thread.

use alloc::{sync::Arc, vec::Vec};

use crate::{
    arch::interrupt::SYSCALL_REGS_NUM,
    error::{Errno, KResult},
    fs::file::FileObject,
    process::{
        event::{wait_for_event, Event},
        remove_by_id, search_by_group_id, search_by_id,
        thread::{spawn, Thread, ThreadContext},
        WaitType,
    },
    signal::SigAction,
    sync::futex::Futex,
    utils::{ptr::Ptr, split_path},
};

use super::PROC_EXITED;

/// fork() creates a new process by duplicating the calling process. The new process is referred to as the child process. The
/// calling process is referred to as the parent process. The return value is the pid of the forked process.
pub fn sys_fork(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let new_thread = thread.fork(&ctx.get_user_context());
    let new_pid = new_thread.parent.lock().process_id;
    spawn(new_thread)?;
    Ok(new_pid as _)
}

/// Waits for process to change state. On success, returns the process ID of the child whose state has changed.
pub async fn sys_wait4(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    // pid_t pid, int *wstatus, int options,
    // struct rusage *rusage/
    let pid = syscall_registers[0] as i64;
    let wstatus = syscall_registers[1];
    let options = syscall_registers[2];
    let rusage = syscall_registers[3];

    let wstatus = Ptr::<i32>::new(wstatus);

    let wait_type = match pid {
        -1 => WaitType::AnyChild,
        0 => WaitType::AnyChildInGroup,
        pid => {
            if pid.is_positive() {
                WaitType::Target(pid)
            } else {
                // Cannot wait for negative pids other than -1.
                return Err(Errno::EINVAL);
            }
        }
    };

    loop {
        let mut proc = thread.parent.lock();
        let child = match wait_type {
            WaitType::AnyChild | WaitType::AnyChildInGroup => {
                let found = proc.children.iter().find(|(pid, child)| {
                    if let Some(child) = child.upgrade() {
                        let lock = child.lock();
                        lock.exited()
                    } else {
                        false
                    }
                });
                if let Some(found) = found {
                    let child = found.1.upgrade().unwrap();
                    let lock = child.lock();
                    Some((lock.process_id, lock.exit_code))
                } else {
                    None
                }
            }

            WaitType::Target(pid) => match search_by_id(pid as _) {
                Ok(proc) => {
                    let lock = proc.lock();
                    match lock.exited() {
                        true => Some((lock.process_id, lock.exit_code)),
                        false => None,
                    }
                }
                Err(_) => None,
            },
        };

        match child {
            Some(child) => {
                if !wstatus.is_null() {
                    // Copy.
                    unsafe {
                        wstatus.write(child.1 as _)?;
                    }

                    // Remove the finished process.
                    remove_by_id(child.0);
                    proc.children.retain(|p| p.0 != child.0);
                    return Ok(child.0 as _);
                }
            }
            None => {
                // Block the calling process.
                let children = proc
                    .children
                    .iter()
                    .filter(|(pid, p)| p.upgrade().is_some())
                    .map(|(pid, _)| pid)
                    .copied()
                    .collect::<Vec<_>>();
                if children.is_empty() {
                    return Err(Errno::ECHILD);
                }

                if let WaitType::Target(pid) = wait_type {
                    if children
                        .iter()
                        .copied()
                        .find(|&id| id == pid as _)
                        .is_none()
                    {
                        return Err(Errno::ECHILD);
                    }
                }

                let eventbus = proc.event_bus.clone();
                drop(proc);
                wait_for_event(eventbus.clone(), Event::CHILD_PROCESS_QUIT).await;
                eventbus.lock().clear(Event::CHILD_PROCESS_QUIT);
            }
        }
    }
}

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
        if let Ok(tid) = thread.vm.lock().get_mut_slice(clear_child_tid, 1) {
            tid[0] = 0;

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

/// getppid() returns the process ID of the parent of the calling process.
pub fn sys_getppid(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    Ok(thread.parent.lock().process_id as _)
}

/// getpid() returns the process ID of the the calling process.
pub fn sys_getpid(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    Ok(thread.parent.lock().process_id as _)
}

/// gettid() returns the caller's thread ID (TID).
pub fn sys_gettid(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    Ok(thread.id as _)
}

/// getpgid() returns the PGID of the process specified by pid. If pid is zero, the process ID of the calling process is used.
pub fn sys_getpgid(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let pid = syscall_registers[0];
    let proc = thread.parent.lock();

    match pid {
        0 => Ok(proc.process_group_id as _),
        _ => {
            drop(proc);
            let proc = search_by_id(pid)?;
            let pid = proc.lock().process_group_id as usize;
            Ok(pid)
        }
    }
}

/// setpgid() sets the PGID of the process specified by pid to pgid.
pub fn sys_setpgid(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let pid = syscall_registers[0];
    let pgid = syscall_registers[1];

    let proc = search_by_id(pid)?;
    let mut proc = proc.lock();
    proc.process_group_id = pgid as _;

    Ok(0)
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

/// A thread's CPU affinity mask determines the set of CPUs on which it is eligible to run. On a multiprocessor system,
/// setting the CPU affinity mask can be used to obtain performance benefits. Since our kernel aims to implement the SMP
/// mechanism, this sycall and setaffinity is important for achieving a better performance.
pub fn sys_sched_getaffinity(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    Ok(0)
}

/// execve() executes the program referred to by pathname.  This causes the program that is currently being run by the calling
/// process to be replaced with a new program, with newly initialized stack, heap, and (initialized and uninitialized) data
/// segments. On success, execve() does not return.
///
/// This causes the program that is currently being run by the calling process to be replaced with a new program, with newly
/// initialized stack, heap, and (initialized and uninitialized) data segments.
pub fn sys_execve(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let pathname = syscall_registers[0];
    let argv = syscall_registers[1];
    let envp = syscall_registers[2];

    let pathname = Ptr::new(pathname).read_c_string().unwrap_or_default();
    let args = Ptr::new(argv).read_c_string_array()?;
    let envp = Ptr::new(envp).read_c_string_array()?;

    // Read the file from the disk.
    let mut proc = thread.parent.lock();
    let inode = proc.read_inode(&pathname)?;

    // Create a new thread with virtual memory copied.
    let mut vm = thread.vm.lock();
    let name = split_path(&pathname)?.1;
    let (stack_top, elf_entry) =
        Thread::create_memory(&inode, &pathname, name, args, envp, &mut vm)?;
    // Reset signal actions.
    proc.actions.iter_mut().for_each(|sigaction| {
        *sigaction = SigAction::default();
    });

    // Close files.
    proc.exec_path = pathname.clone();
    let should_close = proc
        .opened_files
        .iter()
        .filter(|&(fd, file)| {
            if let FileObject::File(file) = file {
                file.fd_cloexec
            } else {
                false
            }
        })
        .map(|item| item.0)
        .copied()
        .collect::<Vec<_>>();

    should_close.into_iter().for_each(|fd| {
        let _ = proc.remove_file(fd);
    });

    vm.validate();
    drop(vm);
    drop(proc);

    ctx.get_user_context().set_rip(elf_entry);
    ctx.get_user_context().set_rsp(stack_top);

    Ok(0)
}
