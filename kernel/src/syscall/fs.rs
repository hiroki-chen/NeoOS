//! Filesystem related system calls.
//!
//! Note however, that any operations that cause filesystem write is dangerous if you are working with apfs.

use alloc::{sync::Arc, vec::Vec};
use bitflags::bitflags;
use rcore_fs::vfs::FsError;

use crate::{
    arch::{interrupt::SYSCALL_REGS_NUM, io::IoVec},
    error::{fserror_to_kerror, Errno, KResult},
    fs::file::{File, FileObject, FileOpenOption, FileType},
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
                todo!()
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
    proc.remove_file(fd)?;

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

pub async fn sys_read(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let file_fd = syscall_registers[0];
    let buf = unsafe { Ptr::new_with_const(syscall_registers[1] as *const u8) };
    let len = syscall_registers[2] as usize;

    let mut proc = thread.parent.lock();
    // Currently assume this is valid.
    let slice = proc.vm.lock().check_write_array(&buf, len)?;
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
    let buf = Ptr::new(syscall_registers[1] as *mut u8);
    let len = syscall_registers[2] as usize;

    let mut proc = thread.parent.lock();
    let slice = proc.vm.lock().check_read_array(&buf, len)?;
    let file = proc.get_fd(file_fd)?;
    let len = file.write(slice);

    Ok(0)
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

    let io_vectors = IoVec::get_all_iovecs(thread, iov_addr as *const IoVec, iov_count as _, true)?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    let mut proc = thread.parent.lock();
    let file = proc.get_fd(fd)?;
    let len = file.write(&io_vectors).unwrap();

    Ok(len)
}
