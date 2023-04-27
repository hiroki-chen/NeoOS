//! This module implementes a Unix-like file handle.
//!
//! In Linux, a file handle is implemented as a data structure that contains information about a file. This information
//! includes the file's inode number, which is a unique identifier for the file within the file system, as well as various
//! flags and pointers that are used to manage the file.

use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use bitflags::bitflags;
use rcore_fs::vfs::{INode, MMapArea, Metadata, PollStatus, Result};
use spin::RwLock;

use crate::{
    error::{fserror_to_kerror, Errno, KResult},
    function, kwarn,
    memory::KernelFrameAllocator,
    mm::{
        callback::{FileArenaCallback, INodeWrapper},
        Arena, ArenaFlags, ArenaType,
    },
    net::Socket,
    process::thread::{current, Thread},
    sys::FcntlCommand,
    time::{SystemTime, UNIX_EPOCH},
};

use super::{apfs::meta::get_timespec, epoll::EpollInstance};

bitflags! {
        #[derive(Default)]
        pub struct FileOpenOption: u8{
            const READ = 0b0001;
            const WRITE = 0b0010;
            const APPEND = 0b0100;
            // async?
            const NON_BLOCKING = 0b1000;
        }
}

/// Minimum `file-like` trait.
pub trait ReadAsFile: Clone + Sync + Send + 'static {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> KResult<usize>;

    fn inode(&self) -> u64;
}

/// flock - apply or remove an advisory lock on an open file.
/// There are two types of locks that can be applied to a file using the FLOCK system call in Linux:
/// * None (no lock!)
/// * Shared locks
/// * Exclusive locks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flock {
    NONE,
    SHARED,
    EXLUSIVE,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub enum FileType {
    CONVENTIONAL = 0,
    PIPE = 1,
    SOCKET = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOption {
    /// How the file is opened.
    pub open_option: FileOpenOption,
    /// File lock.
    pub flock: Flock,
    /// Offset.
    pub offset: u64,
}

/// Seek direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seek {
    Start(usize),
    Cur(usize),
    End(usize),
}

/// A handle to the file object.
///
/// When a process opens a file, the kernel creates a file handle and assigns it to the process. The process can then
/// use the file handle to read from or write to the file, or to perform other operations on the file, such as seeking
/// to a specific location within the file or changing the file's permissions.
#[derive(Clone)]
pub struct File {
    /// The INode `File` points to.
    pub inode: Arc<dyn INode>,
    /// The file path. (relative).
    pub path: String,
    /// File descriptor flags are miscellaneous attributes of a file descriptor. These flags are associated with particular
    /// file descriptors, so that if you have created duplicate file descriptors from a single opening of a file, each
    /// descriptor has its own set of flags.
    ///
    /// This flag specifies that the file descriptor should be closed when an exec function is invoked.
    pub fd_cloexec: bool,
    /// The file option. Multiple processes may try to modify the file.
    /// We may need a read-write lock to guard the status.
    pub file_option: Arc<RwLock<FileOption>>,
    /// The file type.
    pub ty: FileType,
    /// A pre-loaded array of entries if this File is a directory.
    pub entries: Option<Vec<(usize, String)>>,
}

impl File {
    pub fn new(
        inode: Arc<dyn INode>,
        path: &str,
        fd_cloexec: bool,
        open_option: FileOpenOption,
        ty: FileType,
    ) -> Self {
        Self {
            entries: if inode.metadata().unwrap().type_ == rcore_fs::vfs::FileType::Dir {
                match inode.list() {
                    Ok(entries) => Some(entries),
                    Err(_) => None,
                }
            } else {
                None
            },
            inode,
            path: path.to_string(),
            fd_cloexec,
            file_option: Arc::new(RwLock::new(FileOption {
                flock: Flock::NONE,
                open_option,
                offset: 0,
            })),
            ty,
        }
    }

    pub fn clone(&self, fd_cloexec: bool) -> Self {
        Self {
            inode: self.inode.clone(),
            path: self.path.clone(),
            fd_cloexec,
            file_option: self.file_option.clone(),
            ty: self.ty.clone(),
            entries: self.entries.clone(),
        }
    }

    /// Performs a memory mapping.
    pub fn mmap(&self, area: &MMapArea) -> KResult<()> {
        if self.inode.metadata().unwrap().type_ != rcore_fs::vfs::FileType::File {
            return Err(Errno::EACCES);
        }

        let thread = current().unwrap();
        let mut vm = thread.vm.lock();
        vm.add(Arena {
            range: area.start_vaddr as u64..area.end_vaddr as u64,
            flags: ArenaFlags {
                writable: true,
                user_accessible: true,
                non_executable: false,
                mmio: 0,
            },
            callback: Box::new(FileArenaCallback {
                file: INodeWrapper(self.inode.clone()),
                mem_start: area.start_vaddr as _,
                file_start: area.offset as _,
                file_end: (area.offset + area.end_vaddr - area.start_vaddr) as _,
                frame_allocator: KernelFrameAllocator,
            }),
            // Heap ?!
            ty: ArenaType::Heap,
            name: self.path.clone(),
        });

        Ok(())
    }

    pub fn set_option(&self, option: FileOpenOption) {
        let mut cur_option = self.file_option.write();
        let non_blocking = option.contains(FileOpenOption::NON_BLOCKING)
            & cur_option
                .open_option
                .contains(FileOpenOption::NON_BLOCKING);
        cur_option
            .open_option
            .set(FileOpenOption::NON_BLOCKING, non_blocking);
    }

    /// Reads the file from `self.file_option.offset`.
    pub async fn read_buf(&self, buf: &mut [u8]) -> KResult<usize> {
        let offset = self.file_option.read().offset as usize;
        let len = self.read_at(offset, buf).await?;
        self.file_option.write().offset += len as u64;

        Ok(len)
    }

    /// Reads the file from `offset + self.file_option.offset`.
    pub async fn read_at(&self, offset: usize, buf: &mut [u8]) -> KResult<usize> {
        let file_option = self.file_option.read();
        // Check file option.
        if !file_option.open_option.contains(FileOpenOption::READ) {
            return Err(Errno::EBADF);
        }
        let file_offset = file_option.offset as usize + offset;
        // Get the timestamp.
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let mut metadata = self.inode.metadata().map_err(fserror_to_kerror)?;
        metadata.atime = get_timespec(timestamp.as_nanos() as _);
        self.inode
            .set_metadata(&metadata)
            .map_err(fserror_to_kerror)?;

        if !file_option
            .open_option
            .contains(FileOpenOption::NON_BLOCKING)
        {
            // Block.
            loop {
                match self.inode.read_at(file_offset, buf) {
                    Ok(len) => return Ok(len),
                    Err(errno) => {
                        let errno = fserror_to_kerror(errno);
                        match errno {
                            // Read again as inode is not ready.
                            Errno::EAGAIN => {
                                self.inode.async_poll().await.map_err(fserror_to_kerror)?;
                            }

                            _ => return Err(errno),
                        }
                    }
                }
            }
        } else {
            self.inode
                .read_at(file_offset, buf)
                .map_err(fserror_to_kerror)
        }
    }

    /// Sync write operations guarantee that the data has been written to the storage device before the write
    /// operation returns, which can be important for ensuring the integrity of the data in the event of a power
    /// failure or other interruption.
    pub fn write_buf(&self, buf: &[u8]) -> KResult<usize> {
        let offset = if self
            .file_option
            .read()
            .open_option
            .contains(FileOpenOption::APPEND)
        {
            // Jump to end.
            self.inode.metadata().map_err(fserror_to_kerror)?.size
        } else {
            self.file_option.read().offset as usize
        };

        let len = self.write_at(offset, buf)?;
        self.file_option.write().offset += len as u64;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // self.inode.(timestamp)?;
        Ok(len)
    }

    pub fn write_at(&self, offset: usize, buf: &[u8]) -> KResult<usize> {
        // First check if we have permissions to write this file.
        if !self
            .file_option
            .read()
            .open_option
            .contains(FileOpenOption::WRITE)
        {
            return Err(Errno::EBADF);
        }

        let len = self
            .inode
            .write_at(offset, buf)
            .map_err(fserror_to_kerror)?;

        // Modify the time.
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let mut metadata = self.inode.metadata().map_err(fserror_to_kerror)?;
        metadata.mtime = get_timespec(timestamp.as_nanos() as _);

        self.inode
            .set_metadata(&metadata)
            .map_err(fserror_to_kerror)?;

        Ok(len)
    }

    pub fn seek(&mut self, seek: Seek) -> KResult<usize> {
        let mut file_option = self.file_option.write();
        file_option.offset = match seek {
            Seek::Start(offset) => offset,
            Seek::Cur(offset) => (file_option.offset as usize).saturating_add(offset),
            Seek::End(offset) => self
                .inode
                .metadata()
                .map_err(fserror_to_kerror)?
                .size
                .checked_add(offset)
                .unwrap_or(0),
        } as u64;

        Ok(file_option.offset as usize)
    }

    pub fn resize(&self, size: usize) -> KResult<()> {
        // Check permissions.
        if !self
            .file_option
            .read()
            .open_option
            .contains(FileOpenOption::WRITE)
        {
            Err(Errno::EPERM)
        } else {
            self.inode.resize(size).map_err(fserror_to_kerror)
        }
    }

    pub fn metadata(&self) -> Result<Metadata> {
        self.inode.metadata()
    }

    pub fn sync_all(&self) -> KResult<()> {
        self.inode.sync_all().map_err(fserror_to_kerror)
    }

    pub fn sync_data(&self) -> KResult<()> {
        self.inode.sync_data().map_err(fserror_to_kerror)
    }

    pub fn inode(&self) -> Arc<dyn INode> {
        self.inode.clone()
    }

    pub fn lookup_with_symlink(
        &self,
        path: &str,
        maximum_follow: usize,
    ) -> KResult<Arc<dyn INode>> {
        self.inode
            .lookup_follow(path, maximum_follow)
            .map_err(fserror_to_kerror)
    }

    pub fn poll(&self) -> KResult<PollStatus> {
        self.inode.poll().map_err(fserror_to_kerror)
    }

    pub async fn async_poll(&self) -> KResult<PollStatus> {
        Ok(self.inode.async_poll().await.unwrap())
    }

    pub fn entry_with_offset(&mut self) -> KResult<(usize, String)> {
        let mut file_option = self.file_option.write();
        if !file_option.open_option.contains(FileOpenOption::READ) {
            return Err(Errno::EBADF);
        }

        // Must be directory!
        let offset = &mut file_option.offset;
        match self.entries {
            None => Err(Errno::ENOENT),
            Some(ref v) => match v.get(*offset as usize) {
                Some(entry) => {
                    *offset += 1;
                    Ok(entry.clone())
                }
                None => Err(Errno::ENOENT),
            },
        }
    }

    pub fn io_control(&self, cmd: u64, arg: u64) -> KResult<usize> {
        self.inode
            .io_control(cmd as _, arg as _)
            .map_err(fserror_to_kerror)
    }

    pub fn fcntl(
        &mut self,
        fd: u64,
        thread: &Arc<Thread>,
        raw_cmd: u64,
        arg: u64,
    ) -> KResult<usize> {
        let cmd = FcntlCommand::try_from(raw_cmd).unwrap();

        match cmd {
            FcntlCommand::FDupfd => {
                let proc = thread.parent.lock();
                let new_fd = (arg..)
                    .find(|fd| !proc.opened_files.contains_key(&fd))
                    .unwrap();
                drop(proc);
                do_dup(thread, fd, new_fd, None)
            }
            FcntlCommand::FSetfd => {
                self.fd_cloexec = arg & 0x1 != 0;
                Ok(0)
            }
            FcntlCommand::FGetfd => Ok(self.fd_cloexec as _),
            FcntlCommand::FGetfl => Ok(self.file_option.read().open_option.bits as _),
            FcntlCommand::FSetfl => {
                self.file_option.write().open_option =
                    FileOpenOption::from_bits_truncate(arg as u8);
                Ok(0)
            }
            FcntlCommand::FDupfdCloexec => {
                let proc = thread.parent.lock();
                let new_fd = (arg..)
                    .find(|fd| !proc.opened_files.contains_key(&fd))
                    .unwrap();
                drop(proc);
                do_dup(thread, fd, new_fd, Some(1))
            }
            _ => {
                kwarn!("{raw_cmd} is not implemented and is simply ignored.");
                Ok(0)
            }
        }
    }
}

/// Anything that looks like a `file`.
#[derive(Clone)]
pub enum FileObject {
    /// A regular file object.
    File(File),
    /// A socket.
    Socket(Box<dyn Socket>),
    /// An epoll instance.
    Epoll(EpollInstance),
}

impl FileObject {
    /// Io control interface. This function dispatches the request to each file.
    pub fn ioctl(&self, cmd: u64, args: [u64; 3]) -> KResult<usize> {
        match self {
            FileObject::File(file) => file.io_control(cmd, args[0]),
            FileObject::Socket(socket) => Ok(0),
            _ => unimplemented!(),
        }
    }

    pub fn poll(&self) -> KResult<PollStatus> {
        match self {
            FileObject::File(file) => file.poll(),
            FileObject::Socket(socket) => socket.poll(),
            // Polling an epoll instance is meaningless.
            _ => Err(Errno::EINVAL),
        }
    }

    pub async fn async_poll(&self) -> KResult<PollStatus> {
        match self {
            FileObject::File(file) => file.async_poll().await,
            FileObject::Socket(socket) => socket.poll(),
            // Polling an epoll instance is meaningless.
            _ => Err(Errno::EINVAL),
        }
    }

    pub fn fcntl(&mut self, thread: &Arc<Thread>, fd: u64, cmd: u64, arg: u64) -> KResult<usize> {
        match self {
            FileObject::File(file) => file.fcntl(fd, thread, cmd, arg),
            FileObject::Socket(_) | FileObject::Epoll(_) => Ok(0),
        }
    }

    pub fn write(&self, buf: &[u8]) -> KResult<usize> {
        match self {
            FileObject::File(file) => file.write_buf(buf),
            FileObject::Socket(socket) => socket.write(buf, None),

            _ => unimplemented!(),
        }
    }

    pub async fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        match self {
            FileObject::File(file) => file.read_buf(buf).await,
            FileObject::Socket(socket) => socket.read(buf).map(|(len, _)| len),
            FileObject::Epoll(_) => Err(Errno::EBADF),
        }
    }

    pub async fn read_at(&self, offset: usize, buf: &mut [u8]) -> KResult<usize> {
        match self {
            FileObject::File(file) => file.read_at(offset, buf).await,
            // Ignored.
            FileObject::Socket(socket) => socket.read(buf).map(|(len, _)| len),
            FileObject::Epoll(_) => Err(Errno::EBADF),
        }
    }

    /// Duplicates this file.
    pub fn dup(&self, o_cloexec: u64) -> KResult<Self> {
        match self {
            Self::File(file) => Ok(Self::File(File {
                inode: file.inode.clone(),
                path: file.path.clone(),
                fd_cloexec: o_cloexec != 0,
                file_option: file.file_option.clone(),
                ty: file.ty.clone(),
                entries: file.entries.clone(),
            })),
            // Do not duplicate other file descriptors.
            _ => Err(Errno::EBADF),
        }
    }
}

/// Duplicates the file descriptor and assigns a new fd to the new file.
pub fn do_dup(thread: &Arc<Thread>, oldfd: u64, newfd: u64, flags: Option<u64>) -> KResult<usize> {
    let mut proc = thread.parent.lock();
    if proc.fd_exists(newfd) {
        proc.remove_file(newfd).unwrap();
    }

    let file_clone = proc.get_fd_ref(oldfd)?.dup(flags.unwrap_or_default())?;
    proc.opened_files.insert(newfd, file_clone);

    Ok(newfd as _)
}
