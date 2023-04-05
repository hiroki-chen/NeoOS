//! Filesystem related system calls.
//!
//! Note however, that any operations that cause filesystem write is dangerous if you are working with apfs.

use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use bitflags::bitflags;
use rcore_fs::vfs::FsError;

use crate::{
    arch::{interrupt::SYSCALL_REGS_NUM, io::IoVec},
    error::{fserror_to_kerror, Errno, KResult},
    fs::{
        file::{File, FileObject, FileOpenOption, FileType, Seek},
        AT_FDCWD,
    },
    process::thread::{Thread, ThreadContext},
    sys::{Stat, AT_SYMLINK_NOFOLLOW, SEEK_CUR, SEEK_END, SEEK_SET},
    utils::{ptr::Ptr, split_path},
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
        kinfo!("fd = {fd:#x}, offset = {offset:#x}, whence = {whence:#x}");

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
    let p_path = Ptr::new(path as *mut u8);
    let path = p_path.read_c_string()?;
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
    let buf_ptr = Ptr::new(buf as *mut u8);
    thread
        .vm
        .lock()
        .check_write_array(&buf_ptr, cwd.len() + 1)?;

    unsafe {
        buf_ptr.write_c_string(cwd);
    }

    Ok(0)
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

    let filename_ptr = Ptr::new(filename as *mut u8);
    let filename = filename_ptr.to_string();

    do_stat(thread, dfd, filename, statbuf as *mut Stat, flag)
}

pub fn sys_stat(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    let filename = syscall_registers[0];
    let statbuf = syscall_registers[1];

    let filename_ptr = Ptr::new(filename as *mut u8);
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
        let p_buf = Ptr::new(buf as *mut u8);
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
        let p_stat = Ptr::new(stat as *mut Stat);
        unsafe {
            kinfo!("returning {:x?}", file.metadata().unwrap());
            p_stat.write(Stat::from_metadata(&file.metadata().unwrap()))?;
        }
        Ok(0)
    } else {
        Err(Errno::EBADF)
    }
}

pub fn sys_epoll_create(
    thread: &Arc<Thread>,
    ctx: &mut ThreadContext,
    syscall_registers: [u64; SYSCALL_REGS_NUM],
) -> KResult<usize> {
    Ok(0)
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
    Ok(0)
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
    Ok(0)
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

    kinfo!("{fd:#x}, {cmd:#x}, {arg:#x}");

    let mut proc = thread.parent.lock();
    let file = proc.get_fd(fd)?;

    file.fcntl(cmd, arg)
}

fn do_symlink(
    thread: &Arc<Thread>,
    target: *const u8,
    newdirfd: u64,
    linkpath: *const u8,
) -> KResult<usize> {
    let target = unsafe { Ptr::new_with_const(target as *mut u8).read_c_string() }?;
    let linkpath = unsafe { Ptr::new_with_const(linkpath as *mut u8).read_c_string() }?;

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
        statbuf.write(Stat::from_metadata(&metadata));
    }

    Ok(0)
}
