//! Filesystem related system calls.
//!
//! Note however, that any operations that cause filesystem write is dangerous if you are working with apfs.

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use bitflags::bitflags;
use rcore_fs::vfs::FsError;

use crate::{
    arch::{interrupt::SYSCALL_REGS_NUM, io::IoVec, QWORD_LEN},
    dummy_impl,
    error::{fserror_to_kerror, Errno, KResult},
    fs::{
        epoll::{EpollInstance, EPOLL_QUEUE},
        file::{do_dup, File, FileObject, FileOpenOption, FileType, Seek},
        InodeOpType, AT_FDCWD,
    },
    process::thread::{Thread, ThreadContext},
    sys::{
        Dirent, DirentType, EpollEvent, EpollFlags, EpollOp, PollEvents, Pollfd, Stat,
        AT_SYMLINK_NOFOLLOW, SEEK_CUR, SEEK_END, SEEK_SET,
    },
    utils::{ptr::Ptr, realpath, split_path, update_inode_time},
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

impl Oflags {
    pub fn to_open_options(&self) -> FileOpenOption {
        let mut file_option = FileOpenOption::default();

        if self.contains(Oflags::APPEND) {
            file_option |= FileOpenOption::APPEND;
        }

        // Check R/W
        if self.contains(Oflags::O_RDONLY) || self.contains(Oflags::O_RDWR) {
            file_option |= FileOpenOption::READ;
        }

        if self.contains(Oflags::O_WRONLY) || self.contains(Oflags::O_RDWR) {
            file_option |= FileOpenOption::WRITE;
        }

        file_option
    }
}

struct SysPoll<'a> {
    /// All file descriptors being monitored.
    fds: &'a mut [Pollfd],
    /// The caller's thread.
    thread: &'a Arc<Thread>,
}

impl<'a> Future for SysPoll<'a> {
    type Output = KResult<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut proc = self.thread.parent.lock();

        // Check each fd.
        let mut ready = 0;
        for fd in self.fds.iter_mut() {
            if let Ok(file) = proc.get_fd(fd.fd as _) {
                let mut file_poll = Box::pin(file.async_poll());
                if let Poll::Ready(poll) = file_poll.as_mut().poll(cx) {
                    let poll_status = match poll {
                        Ok(status) => status,
                        Err(errno) => return Poll::Ready(Err(errno)),
                    };

                    if poll_status.error {
                        fd.revents |= PollEvents::HUP.bits();
                        ready += 1;
                    }

                    if poll_status.read && fd.events & PollEvents::OUT.bits() != 0 {
                        fd.revents |= PollEvents::OUT.bits();
                        ready += 1;
                    }

                    if poll_status.write && fd.events & PollEvents::IN.bits() != 0 {
                        fd.revents |= PollEvents::IN.bits();
                        ready += 1;
                    }
                }
            } else {
                fd.revents |= PollEvents::ERR.bits();
                ready += 1;
            }
        }

        match ready {
            0 => Poll::Pending,
            _ => Poll::Ready(Ok(ready)),
        }
    }
}

/// Upon successful completion, lseek() returns the resulting offset location as measured in bytes from the beginning of the
/// file. On error, the value (off_t) -1 is returned and errno is set to indicate the error.
pub fn sys_lseek(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let fd = syscall_registers[0];
    let offset = syscall_registers[1];
    let whence = syscall_registers[2];

    let mut proc = thread.parent.lock();
    let file = proc.get_fd(fd)?;

    if let FileObject::File(file) = file {
        let position = match whence {
            // The file offset is set to `offset` bytes.
            SEEK_SET => Seek::Start(offset as _),
            // The file offset is set to its current location plus `offset` bytes.
            SEEK_CUR => Seek::Cur(offset as _),
            // The file offset is set to the size of the file plus `offset` bytes.
            SEEK_END => Seek::End(offset as _),
            _ => return Err(Errno::EINVAL),
        };

        file.seek(position)
    } else {
        Err(Errno::ESPIPE)
    }
}

/// The dup() system call allocates a new file descriptor that refers to the same open file description as the descriptor
/// oldfd
pub fn sys_dup2(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let oldfd = syscall_registers[0];
    let newfd = syscall_registers[1];

    do_dup(thread, oldfd, newfd, None)
}

pub fn sys_dup3(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let oldfd = syscall_registers[0];
    let newfd = syscall_registers[1];
    let flags = syscall_registers[2];

    if oldfd == newfd {
        return Err(Errno::EINVAL);
    }

    do_dup(thread, oldfd, newfd, Some(flags))
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
    let path = syscall_registers[1];
    let flags = syscall_registers[2];
    let mode = syscall_registers[3];

    // Open the directory.
    let mut proc = thread.parent.lock();
    let vm = thread.vm.lock();
    let p_path = vm.get_ptr(path)?;
    let path = p_path.read_c_string()?;
    let oflags = Oflags::from_bits_truncate(flags);

    let inode = if oflags.contains(Oflags::O_CREATE) {
        let (directory, filename) = split_path(&path)?;
        let dir_inode = proc.read_inode_at(dir_fd, directory, true)?;
        match dir_inode.find(filename) {
            Ok(file) => {
                if oflags.contains(Oflags::EXCLUSIVE) {
                    return Err(Errno::EEXIST);
                }

                file
            }

            Err(FsError::EntryNotFound) => {
                // Create a new file.
                let new_inode = dir_inode
                    .create(filename, rcore_fs::vfs::FileType::File, 0o777)
                    .map_err(fserror_to_kerror)?;
                update_inode_time(&new_inode, InodeOpType::all());
                update_inode_time(&dir_inode, InodeOpType::ACCESS | InodeOpType::MODIFY);

                new_inode
            }
            Err(errno) => {
                return Err(fserror_to_kerror(errno));
            }
        }
    } else {
        proc.read_inode_at(dir_fd, &path, true)?
    };

    let file = FileObject::File(File::new(
        inode,
        &path,
        false,
        oflags.to_open_options(),
        FileType::CONVENTIONAL,
    ));

    let fd = proc.add_file(file)?;
    Ok(fd as _)
}

pub fn sys_close(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let fd = syscall_registers[0];
    // Remove the file if opened.
    let mut proc = thread.parent.lock();
    proc.remove_file(fd).map(|_| 0)
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

    let mut proc = thread.parent.lock();
    let file = proc.get_fd(file_fd)?;
    file.ioctl(cmd, [arg1, arg2, arg3])
}

/// poll() performs a similar task to select(2): it waits for one of a set of file descriptors to become ready to perform I/O.
pub async fn sys_poll(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let fds = syscall_registers[0];
    let nfds = syscall_registers[1];
    // milliseconds
    let timeout = syscall_registers[2];

    let fds = unsafe { core::slice::from_raw_parts_mut(fds as *mut Pollfd, nfds as usize) };
    let timeout = Duration::from_millis(timeout as _);
    SysPoll { fds, thread }.await
}

pub async fn sys_read(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let file_fd = syscall_registers[0];
    let buf = syscall_registers[1];
    let len = syscall_registers[2] as usize;

    let mut proc = thread.parent.lock();
    // Currently assume this is valid.
    // let slice = proc.vm.lock().check_write_array(&buf, len)?;
    let slice = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };
    let file = proc.get_fd(file_fd)?;
    let len = file.read(slice).await?;

    Ok(len)
}

pub fn sys_write(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let file_fd = syscall_registers[0];
    let buf = syscall_registers[1];
    let len = syscall_registers[2] as usize;

    let mut proc = thread.parent.lock();
    let slice = proc.vm.lock().get_slice::<u8>(buf, len)?;
    let file = proc.get_fd(file_fd)?;
    let len = file.write(slice)?;

    Ok(len)
}

/// The readv() system call reads iovcnt buffers from the file associated with the file descriptor fd into the buffers
/// described by iov ("scatter input").
///
/// ```c
/// struct iovec {
///     void  *iov_base;    /* Starting address */
///     size_t iov_len;     /* Number of bytes to transfer */
/// };
/// ```
///
/// Musl invokes this syscall to do `__stdio_write`.
pub async fn sys_readv(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let fd = syscall_registers[0];
    let iov_addr = syscall_registers[1];
    let iov_count = syscall_registers[2];

    let mut proc = thread.parent.lock();
    let file = proc.get_fd(fd)?;
    let mut buf = [0u8; 4096];
    let len = file.read(&mut buf).await?;

    IoVec::write_all_iovecs(
        thread,
        iov_addr as *const IoVec,
        iov_count as _,
        &buf[..len],
    )
}

/// The writev() system call writes iovcnt buffers of data described by iov to the file associated with the file
/// descriptor fd. ("gather output"). The pointer iov points to an array of iovec structures, defined in <sys/uio.h>
/// as:
/// ```c
/// struct iovec {
///     void  *iov_base;    /* Starting address */
///     size_t iov_len;     /* Number of bytes to transfer */
/// };
/// ```
///
/// Musl invokes this syscall to do `__stdio_write`.
pub fn sys_writev(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let fd = syscall_registers[0];
    let iov_addr = syscall_registers[1];
    let iov_count = syscall_registers[2];

    let io_vectors = IoVec::get_all_iovecs(thread, iov_addr as *const IoVec, iov_count as _)?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    let mut proc = thread.parent.lock();
    let file = proc.get_fd(fd)?;
    let len = file.write(&io_vectors).unwrap();

    Ok(len)
}

/// Changes the current working directory.
pub fn sys_chdir(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let mut proc = thread.parent.lock();
    let vm = thread.vm.lock();

    let pathname = syscall_registers[0];
    let pathname = vm.get_ptr(pathname)?.read_c_string()?;
    // busybox shell will do this for us, but w.l.o.g. we should do this.
    let realpath = realpath(&pathname);

    let inode = proc.read_inode(&pathname)?;
    let metadata = inode.metadata().map_err(|_| Errno::EINVAL)?;

    if metadata.type_ != rcore_fs::vfs::FileType::Dir {
        return Err(Errno::ENOTDIR);
    }

    proc.cwd = realpath;
    Ok(0)
}

/// sendfile() copies data between one file descriptor and another and is more efficient than read and write bcause
/// the operation occurs in the kernel space.
pub async fn sys_sendfile(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    // int out_fd, int in_fd, off_t *offset, size_t count
    let out_fd = syscall_registers[0];
    let in_fd = syscall_registers[1];
    let offset = syscall_registers[2];
    let count = syscall_registers[3];

    let mut proc = thread.parent.lock();
    let vm = thread.vm.lock();
    // Since MIRI detects multiple mutable borrows from proc's opened files, we need to first copy
    // the content from the source file using a scope and then copy to the destination using another
    // scope to avoid race condition.
    let buf = {
        let src = proc.get_fd(in_fd)?;
        // If `offset` is not NULL, then we read from `offset`; otherwise, we read from the offset
        // stored in the source file object, and if it is non-NULL, we need to update this value.
        let offset = vm.get_mut_ptr::<u64>(offset)?;
        // Prepare a buffer.
        let mut buf = vec![0u8; count as usize];

        let len = if offset.is_null() {
            src.read(&mut buf).await?
        } else {
            // `read_at` will not adjust the file offset.
            unsafe { src.read_at(offset.read()? as _, &mut buf) }.await?
        };

        buf[..len].to_vec()
    };

    // Then copy the buffer to the destination file.
    let dst = proc.get_fd(out_fd)?;
    let len = dst.write(buf.as_slice())?;

    Ok(len)
}

pub fn sys_getcwd(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let buf = syscall_registers[0];
    let size = syscall_registers[1] as usize;

    let proc = thread.parent.lock();
    let cwd = proc.cwd.as_str();

    // If the length of the absolute pathname of the current working
    // directory, including the terminating null byte, exceeds size
    // bytes, NULL is returned, and errno is set to ERANGE; an
    // application should check for this error, and allocate a larger
    // buffer if necessary.
    if cwd.len() + 1 > size {
        // Insufficient buffer.
        return Err(Errno::ERANGE);
    }

    // Check the pointer before use.
    let buf_ptr = Ptr::<u8>::new(
        thread
            .vm
            .lock()
            .get_mut_slice::<u8>(buf, cwd.len() + 1)?
            .as_ptr() as u64,
    );

    unsafe {
        buf_ptr.write_c_string(cwd);
    }

    Ok(buf_ptr.as_ptr() as usize)
}

pub fn sys_lstat(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let pathname = syscall_registers[0];
    let statbuf = syscall_registers[1];

    let filename = thread.vm.lock().get_ptr(pathname)?.read_c_string()?;

    do_stat(
        thread,
        AT_FDCWD as _,
        filename,
        statbuf as _,
        AT_SYMLINK_NOFOLLOW,
    )
}

/// These functions return information about a file, in the buffer pointed to by `statbuf`. No permissions are required
/// on the file itself.
pub fn sys_newfstatat(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let dfd = syscall_registers[0];
    let filename = syscall_registers[1];
    let statbuf = syscall_registers[2];
    let flag = syscall_registers[3];

    let filename_ptr = thread.vm.lock().get_ptr(filename)?;
    let filename = filename_ptr.to_string();

    do_stat(thread, dfd, filename, statbuf as *mut Stat, flag)
}

pub fn sys_readlink(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let pathname = syscall_registers[0];
    let buf = syscall_registers[1];
    let bufsiz = syscall_registers[2];

    do_readlink(thread, AT_FDCWD as _, pathname as _, buf as _, bufsiz)
}

pub fn sys_readlinkat(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let dirfd = syscall_registers[0];
    let pathname = syscall_registers[1];
    let buf = syscall_registers[2];
    let bufsiz = syscall_registers[3];

    do_readlink(thread, dirfd, pathname as _, buf as _, bufsiz)
}

pub fn sys_stat(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let filename = syscall_registers[0];
    let statbuf = syscall_registers[1];

    let filename_ptr = thread.vm.lock().get_ptr(filename)?;
    let filename = filename_ptr.to_string();

    do_stat(thread, AT_FDCWD as _, filename, statbuf as *mut Stat, 0)
}

/// pread() reads up to count bytes from file descriptor fd at offset offset (from the start of the file) into the buffer
/// starting at buf. The file offset is not changed.
pub async fn sys_pread(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let fd = syscall_registers[0];
    let buf = syscall_registers[1];
    let count = syscall_registers[2];
    let offset = syscall_registers[3];

    let mut proc = thread.parent.lock();
    let file = proc.get_fd(fd)?;

    if let FileObject::File(file) = file {
        let p_buf = thread.vm.lock().get_ptr(buf)?;
        let filesz = file.metadata().unwrap().size;
        let offset = filesz.min(offset as usize);
        let mut buf = vec![0u8; count as usize];
        let len = file.read_at(offset, &mut buf).await?;

        unsafe {
            p_buf.write_slice(&buf);
        }

        Ok(len)
    } else {
        Err(Errno::EBADF)
    }
}

/// pwrite() writes up to count bytes from the buffer starting at buf to the file descriptor fd at offset offset. The file
/// offset is not changed.
pub fn sys_pwrite(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let fd = syscall_registers[0];
    let buf = syscall_registers[1];
    let count = syscall_registers[2];
    let offset = syscall_registers[3];

    let buf = unsafe { core::slice::from_raw_parts(buf as *const u8, count as _) };
    let mut proc = thread.parent.lock();
    let file = proc.get_fd(fd)?;

    if let FileObject::File(file) = file {
        let len = file.write_at(offset as _, buf).unwrap();

        Ok(len)
    } else {
        Err(Errno::EBADF)
    }
}

pub fn sys_fstat(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let fd = syscall_registers[0];
    let stat = syscall_registers[1];

    let mut proc = thread.parent.lock();
    let file = proc.get_fd(fd)?;

    if let FileObject::File(file) = file {
        let p_stat = thread.vm.lock().get_ptr(stat)?;
        unsafe {
            p_stat.write(Stat::from(file.metadata().unwrap()))?;
        }
        Ok(0)
    } else {
        Err(Errno::EBADF)
    }
}

/// This system call is used to add, modify, or remove entries in the interest list of the epoll(7) instance referred to by the file descriptor epfd. It requests that the operation op be performed for the target file descriptor, fd.
pub fn sys_epoll_ctl(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    // int epfd, int op, int fd, struct epoll_event *event
    let epfd = syscall_registers[0];
    let op = syscall_registers[1];
    let fd = syscall_registers[2];
    let event = syscall_registers[3];

    let mut proc = thread.parent.lock();
    if !proc.fd_exists(fd) {
        return Err(Errno::EPERM);
    }

    let epoll = proc.get_fd(epfd)?;

    if let FileObject::Epoll(epoll) = epoll {
        let event = unsafe { thread.vm.lock().get_ptr(event)?.read() }?;
        let op = EpollOp::try_from(op).map_err(|_| Errno::EINVAL)?;

        epoll.epoll_ctl(fd, op, event)
    } else {
        // Does not support epoll.
        Err(Errno::EPERM)
    }
}

/// The epoll_wait() system call waits for events on the epoll(7) instance referred to by the file descriptor epfd. The
/// buffer pointed to by events is used to return information from the ready list about file descriptors in the interest
/// list that have some events available.  Up to maxevents are returned by epoll_wait(). The maxevents argument must be
/// greater than zero.
///
/// FIXME: Still buggy.
pub fn sys_epoll_pwait(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let epfd = syscall_registers[0];
    let events = syscall_registers[1];
    let maxevents = syscall_registers[2];
    let timeout = syscall_registers[3];
    let sigmask = syscall_registers[4];

    let proc = thread.parent.lock();
    let epoll = proc.get_fd_ref(epfd)?;

    // Stores fds that should be unregistered.
    let mut should_remove = Vec::new();

    if let FileObject::Epoll(epoll) = epoll {
        epoll.clear_ready();

        let fds = epoll.events.lock().keys().copied().collect::<Vec<_>>();
        for (&fd, v) in epoll.events.lock().iter() {
            let epoll_flag = v.events;

            // Check if the monitoring fd exists.
            if let Ok(file) = proc.get_fd_ref(fd) {
                let status = file.poll()?;

                // Status is there.
                if status.error || status.write || status.read {
                    epoll.add_ready(fd);

                    // In Edge Triggered mode (EPOLLET), events are raised only after a significant change.
                    // It requires the process to keep track of what the last response for each monitored fd is.
                    //
                    // Level-triggered: as long as the event is here, we need to add the fd into the ready list.
                    // Edge-triggered: only when the event "changes", we need to add the fd into the ready list.
                    // That is to say, when a event occurs, the registered event will be removed from the epoll.
                    // FIXME: Lost?
                    if epoll_flag.contains(EpollFlags::EPOLLET) {
                        // SHould not remove... Need to notify again when the status *changed*.
                        // should_remove.push(fd);
                    }
                }
            }
        }

        let mut ready_num = 0;
        for fd in fds.into_iter() {
            let proc = thread.parent.lock();

            match proc.get_fd_ref(fd)? {
                // Now we only handle socket epoll.
                FileObject::Socket(socket) => {
                    // FIXME: Duplicate ?
                    EPOLL_QUEUE.register_epoll_event(thread.clone(), epfd, fd)
                }
                // Should not happen ?!
                _ => continue,
            }
        }
        drop(proc);
        {
            // Check the ready queue and try to notify the caller that some fds are ready for I/O.
            let mut proc = thread.parent.lock();
            let epoll = proc.get_fd(epfd)?;

            if let FileObject::Epoll(epoll) = epoll {
                // Cloned => prevent multiple mutable borrows.
                let ready_queue = epoll.ready.lock().clone();
                let all_events = epoll.events.lock().clone();
                for fd_ready_for_epoll in ready_queue.iter().copied() {
                    // Get the file and remove from the ready queue.
                    // kinfo!("fd_ready_for_epoll: {fd_ready_for_epoll:#x}");
                    let file = proc.get_fd_ref(fd_ready_for_epoll)?;
                    // Can be overwritten by a new status.
                    let status = file.poll()?;
                    let epoll_event_from_instance = all_events.get(&fd_ready_for_epoll).unwrap();
                    let epoll_event_flags = epoll_event_from_instance.events;

                    if status.read && epoll_event_flags.contains(EpollFlags::EPOLLIN) {
                        // Copy the data to the user space.
                        let event_ptr =
                            unsafe { &mut *((events as *mut EpollEvent).add(ready_num)) };
                        event_ptr.events = EpollFlags::EPOLLIN;
                        event_ptr.data = epoll_event_from_instance.data;
                        ready_num += 1;
                    }

                    if status.write && epoll_event_flags.contains(EpollFlags::EPOLLOUT) {
                        // Copy the data to the user space.
                        let event_ptr =
                            unsafe { &mut *((events as *mut EpollEvent).add(ready_num)) };
                        event_ptr.events = EpollFlags::EPOLLOUT;
                        event_ptr.data = epoll_event_from_instance.data;
                        ready_num += 1;
                    }

                    if status.error && epoll_event_flags.contains(EpollFlags::EPOLLERR) {
                        // Copy the data to the user space.
                        let event_ptr =
                            unsafe { &mut *((events as *mut EpollEvent).add(ready_num)) };
                        event_ptr.events = EpollFlags::EPOLLERR;
                        event_ptr.data = epoll_event_from_instance.data;
                        ready_num += 1;
                    }
                }
            } else {
                panic!("epoll corrupted");
            }
        }

        {
            // HACK: Very inelegant due to Rust's borrow checker.
            let proc = thread.parent.lock();
            if let Ok(FileObject::Epoll(epoll)) = proc.get_fd_ref(epfd) {
                epoll.clear_ready();

                should_remove.into_iter().for_each(|fd| {
                    epoll.events.lock().remove(&fd);
                });
            }
        }

        Ok(ready_num)
    } else {
        Err(Errno::EPERM)
    }
}

/// The system call getdents() reads several linux_dirent structures from the directory referred to by the open file
/// descriptor fd into the buffer pointed to by dirp. The argument count specifies the size of that buffer.
pub fn sys_getdents64(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let fd = syscall_registers[0];
    let mut dirp = syscall_registers[1];
    let count = syscall_registers[2];

    let mut proc = thread.parent.lock();
    if let Ok(FileObject::File(file)) = proc.get_fd(fd) {
        let mut written_size = 0;
        let hdr_len = core::mem::size_of::<Dirent>();

        // Iterate over the directory entries.
        loop {
            let (inode, dirent) = match file.entry_with_offset() {
                Ok(dirent) => dirent,
                Err(Errno::ENOENT) => break,
                Err(errno) => return Err(errno),
            };

            let metadata = file
                .inode
                .get_entry_with_metadata(inode)
                .map_err(fserror_to_kerror)?
                .0;

            // Determine the size of this directory entry.
            // d_ino + d_off + d_reclen + ty + char[name] (with '\0').
            let mut size = hdr_len + dirent.len() + 1;
            // Need to align to 8 bytes.
            if size % QWORD_LEN != 0 {
                size += QWORD_LEN - size % QWORD_LEN;
            }

            if size > count as usize {
                // Buffer is too small.
                return Err(Errno::EINVAL);
            }

            unsafe {
                (dirp as *mut Dirent).write(Dirent {
                    d_ino: inode as _,
                    d_off: 0,
                    d_reclen: size as _,
                    d_type: DirentType::from_type(&metadata.type_).bits(),
                });

                // Copy directory name.
                (dirp as *mut u8)
                    .add(hdr_len)
                    .copy_from(dirent.as_ptr(), dirent.len());
                (dirp as *mut u8).add(hdr_len + dirent.len()).write(0);
            }

            dirp += size as u64;
            written_size += size;
        }

        Ok(written_size)
    } else {
        Err(Errno::EBADF)
    }
}

/// epoll_create() returns a file descripto referring to the new epoll instance. This file descriptor is used for all the
/// subsequent calls to the epoll interface.
pub fn sys_epoll_create(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let size = syscall_registers[0] as isize;
    if size <= 0 {
        return Err(Errno::EINVAL);
    }

    // Size is ignored.
    do_epoll_create(thread, false)
}

/// If flags is 0, then, other than the fact that the obsolete size argument is dropped, epoll_create1() is the same as
/// epoll_create().  The following value can be included in flags to obtain different behavior:
pub fn sys_epoll_create1(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let flags = syscall_registers[0];

    do_epoll_create(thread, flags != 0)
}

/// symlink() creates a symbolic link named linkpath which contains the string target.
pub fn sys_symlink(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let target = syscall_registers[0];
    let linkpath = syscall_registers[1];

    do_symlink(thread, target as _, AT_FDCWD as _, linkpath as _)
}

pub fn sys_symlinkat(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let target = syscall_registers[0];
    let newdirfd = syscall_registers[1];
    let linkpath = syscall_registers[2];

    do_symlink(thread, target as _, newdirfd, linkpath as _)
}

/// mkdir() attempts to create a directory named pathname.
pub fn sys_mkdir(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let pathname = syscall_registers[0];
    let mode = syscall_registers[1];

    do_mkdir(thread, AT_FDCWD as _, pathname as _, mode)
}

/// The mkdirat() system call operates in exactly the same way as mkdir(), except for the differences described here. If
/// the pathname given in pathname is relative, then it is interpreted relative to the directory referred to by the file
/// descriptor dirfd (rather than relative to the current working directory of the calling process, as is done by mkdir()
/// for a relative pathname).
pub fn sys_mkdirat(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let dirfd = syscall_registers[0];
    let pathname = syscall_registers[1];
    let mode = syscall_registers[2];

    do_mkdir(thread, dirfd, pathname as _, mode)
}

/// fcntl() performs one of the operations on the open file descriptor fd. The operation is determined by cmd.
pub fn sys_fnctl(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let fd = syscall_registers[0];
    let cmd = syscall_registers[1];
    let arg = syscall_registers[2];

    let mut proc = thread.parent.lock();
    let file = proc.get_fd(fd)?;

    file.fcntl(thread, fd, cmd, arg)
}

fn do_symlink(
    thread: &Arc<Thread>,
    target: *const u8,
    newdirfd: u64,
    linkpath: *const u8,
) -> KResult<usize> {
    let vm = thread.vm.lock();

    let target = vm.get_ptr(target as _)?.read_c_string()?;
    let linkpath = vm.get_ptr(linkpath as _)?.read_c_string()?;

    let proc = thread.parent.lock();
    let (dirpath, filename) = split_path(&linkpath)?;
    let dir_inode = proc.read_inode_at(newdirfd, dirpath, true)?;

    match dir_inode.find(filename) {
        Err(FsError::EntryNotFound) => {
            // Only non-existing target can be created!
            let symlink = dir_inode
                // Mode is rwxrwxrwx, that is ok.
                .create(filename, rcore_fs::vfs::FileType::SymLink, 0o777)
                .map_err(fserror_to_kerror)?;
            symlink
                .write_at(0, target.as_bytes())
                .map_err(fserror_to_kerror)?;
            update_inode_time(&symlink, InodeOpType::all());
            update_inode_time(&dir_inode, InodeOpType::ACCESS | InodeOpType::MODIFY);
            Ok(0)
        }
        Ok(_) => Err(Errno::EEXIST),
        Err(errno) => Err(fserror_to_kerror(errno)),
    }
}

fn do_stat(
    thread: &Arc<Thread>,
    dfd: u64,
    filename: String,
    statbuf: *mut Stat,
    flag: u64,
) -> KResult<usize> {
    let follow_symlink = flag & AT_SYMLINK_NOFOLLOW != 0;
    let proc = thread.parent.lock();
    let inode = proc.read_inode_at(dfd, &filename, follow_symlink)?;
    let metadata = inode.metadata().map_err(fserror_to_kerror)?;

    unsafe {
        let stat = Stat::from(metadata.clone());
        statbuf.write(Stat::from(metadata));
    }

    Ok(0)
}

fn do_mkdir(thread: &Arc<Thread>, dirfd: u64, pathname: *const u8, mode: u64) -> KResult<usize> {
    // Already checked.
    let pathname = Ptr::new(pathname as _).read_c_string()?;

    let (dirname, filename) = split_path(&pathname)?;
    let proc = thread.parent.lock();

    let dir_inode = proc.read_inode_at(dirfd, dirname, true)?;
    if dir_inode.find(dirname).is_ok() {
        return Err(Errno::EEXIST);
    }

    let inode = dir_inode
        .create(filename, rcore_fs::vfs::FileType::Dir, mode as _)
        .map_err(fserror_to_kerror)?;
    // Update time.
    update_inode_time(&inode, InodeOpType::all());
    update_inode_time(&dir_inode, InodeOpType::ACCESS | InodeOpType::MODIFY);

    Ok(0)
}

fn do_epoll_create(thread: &Arc<Thread>, epoll_cloexec: bool) -> KResult<usize> {
    let mut proc = thread.parent.lock();
    let epoll = EpollInstance::new(epoll_cloexec);
    proc.add_file(FileObject::Epoll(epoll)).map(|fd| fd as _)
}

fn do_readlink(
    thread: &Arc<Thread>,
    dirfd: u64,
    pathname: *const u8,
    buf: *mut u8,
    bufsiz: u64,
) -> KResult<usize> {
    let pathname = Ptr::new(pathname as _).read_c_string()?;
    let proc = thread.parent.lock();
    let inode = proc.read_inode_at(dirfd, pathname.as_str(), false)?;
    if inode.metadata().map_err(|_| Errno::EINVAL)?.type_ == rcore_fs::vfs::FileType::SymLink {
        let buf = unsafe { core::slice::from_raw_parts_mut(buf, bufsiz as _) };
        let len = inode.read_at(0, buf).map_err(fserror_to_kerror)?;
        Ok(len)
    } else {
        Err(Errno::EINVAL)
    }
}

// Ignored. Permission check will be added in the future.
dummy_impl!(sys_chown, Ok(0));
dummy_impl!(sys_fchown, Ok(0));
dummy_impl!(sys_lchown, Ok(0));
dummy_impl!(sys_chmod, Ok(0));
dummy_impl!(sys_fchmod, Ok(0));
dummy_impl!(sys_dup, Ok(0));
dummy_impl!(sys_eventfd, Err(Errno::EACCES));
dummy_impl!(sys_eventfd2, Err(Errno::EACCES));
