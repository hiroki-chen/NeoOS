//! This module implementes a Unix-like file handle.
//!
//! In Linux, a file handle is implemented as a data structure that contains information about a file. This information
//! includes the file's inode number, which is a unique identifier for the file within the file system, as well as various
//! flags and pointers that are used to manage the file.

use alloc::{
    string::{String, ToString},
    sync::Arc,
};
use bitflags::bitflags;
use rcore_fs::vfs::{INode, Metadata, PollStatus, Result};
use spin::RwLock;

use crate::{
    error::{fserror_to_kerror, Errno, KResult},
    time::{SystemTime, UNIX_EPOCH},
};

bitflags! {
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
        }
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
    pub async fn read_buf(&mut self, buf: &mut [u8]) -> KResult<usize> {
        let offset = self.file_option.read().offset as usize;
        let len = self.read_at(offset, buf).await?;
        self.file_option.write().offset += len as u64;

        Ok(len)
    }

    /// Reads the file from `offset + self.file_option.offset`.
    pub async fn read_at(&mut self, offset: usize, buf: &mut [u8]) -> KResult<usize> {
        let file_option = self.file_option.read();
        // Check file option.
        if !file_option.open_option.contains(FileOpenOption::READ) {
            return Err(Errno::EBADF);
        }

        let file_offset = file_option.offset as usize + offset;
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
                            Errno::EAGAIN | Errno::EWOULDBLOCK => {
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
    pub fn write_buf(&mut self, buf: &[u8]) -> KResult<usize> {
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

    pub fn write_at(&mut self, offset: usize, buf: &[u8]) -> KResult<usize> {
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
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // self.inode.set_mtime(timestamp)?;
        Ok(len)
    }

    pub fn seek(&mut self, seek: Seek) -> KResult<usize> {
        let mut file_option = self.file_option.write();
        file_option.offset = match seek {
            Seek::Start(offset) => offset,
            Seek::Cur(offset) => file_option.offset as usize + offset,
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

    pub fn entry(&mut self) -> KResult<String> {
        let mut file_option = self.file_option.write();
        if !file_option.open_option.contains(FileOpenOption::READ) {
            return Err(Errno::EBADF);
        }

        let offset = &mut file_option.offset;
        let name = self
            .inode
            .get_entry(*offset as usize)
            .map_err(fserror_to_kerror)?;
        *offset += 1;
        Ok(name)
    }

    pub fn io_control(&self, cmd: u64, arg: u64) -> KResult<usize> {
        self.inode
            .io_control(cmd as _, arg as _)
            .map_err(fserror_to_kerror)
    }
}

/// Anything that looks like a `file`.
#[derive(Clone)]
pub enum FileObject {
    /// A regular file object.
    File(File),
    /// A socket.
    Socket,
}

impl FileObject {
    /// Io control interface. This function dispatches the request to each file.
    pub fn ioctl(&self, cmd: u64, args: [u64; 3]) -> KResult<usize> {
        match self {
            FileObject::File(file) => file.io_control(cmd, args[0]),

            _ => unimplemented!(),
        }
    }
}
