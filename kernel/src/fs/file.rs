//! This module implementes a Unix-like file handle.
//!
//! In Linux, a file handle is implemented as a data structure that contains information about a file. This information
//! includes the file's inode number, which is a unique identifier for the file within the file system, as well as various
//! flags and pointers that are used to manage the file.

use core::pin::Pin;

use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
};
use bitflags::bitflags;
use spin::RwLock;

use crate::{
    error::{Errno, KResult},
    memory::KernelFrameAllocator,
    mm::{
        callback::{FileArenaCallback, INodeWrapper},
        Arena, MmapPerm,
    },
    process::thread,
    time::{SystemTime, UNIX_EPOCH},
};

use super::vfs::{AsyncPoll, INode, INodeMetadata, INodeType, MemoryMap, PollFlags};

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
    fn read_buf_at(&self, offset: usize, buf: &mut [u8]) -> KResult<usize>;
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
pub enum FileType {
    CONVENTIONAL,
    PIPE,
    SOCKET,
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
        let len = self.read_buf_at(offset, buf).await?;
        self.file_option.write().offset += len as u64;

        Ok(len)
    }

    /// Reads the file from `offset + self.file_option.offset`.
    pub async fn read_buf_at(&mut self, offset: usize, buf: &mut [u8]) -> KResult<usize> {
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
                match self.inode.read_buf_at(file_offset, buf) {
                    Ok(len) => return Ok(len),
                    Err(errno) => match errno {
                        // Read again as inode is not ready.
                        Errno::EAGAIN | Errno::EWOULDBLOCK => {
                            self.inode.async_poll().await?;
                        }
                        _ => return Err(errno),
                    },
                }
            }
        } else {
            Ok(self.inode.read_buf_at(file_offset, buf)?)
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
            self.inode.metadata()?.size
        } else {
            self.file_option.read().offset as usize
        };

        let len = self.write_buf_at(offset, buf)?;
        self.file_option.write().offset += len as u64;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.inode.set_atime(timestamp)?;
        Ok(len)
    }

    pub fn write_buf_at(&mut self, offset: usize, buf: &[u8]) -> KResult<usize> {
        // First check if we have permissions to write this file.
        if !self
            .file_option
            .read()
            .open_option
            .contains(FileOpenOption::WRITE)
        {
            return Err(Errno::EBADF);
        }
        let len = self.inode.write_buf_at(offset, buf)?;

        // Modify the time.
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.inode.set_mtime(timestamp)?;
        Ok(len)
    }

    pub fn seek(&mut self, seek: Seek) -> KResult<usize> {
        let mut file_option = self.file_option.write();
        file_option.offset = match seek {
            Seek::Start(offset) => offset,
            Seek::Cur(offset) => file_option.offset as usize + offset,
            Seek::End(offset) => self.inode.metadata()?.size.checked_add(offset).unwrap_or(0),
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
            self.inode.resize(size)
        }
    }

    pub fn metadata(&self) -> KResult<INodeMetadata> {
        self.inode.metadata()
    }

    pub fn sync_all(&self) -> KResult<()> {
        self.inode.sync_all()
    }

    pub fn sync_data(&self) -> KResult<()> {
        self.inode.sync_data()
    }

    pub fn inode(&self) -> Arc<dyn INode> {
        self.inode.clone()
    }

    pub fn lookup_with_symlink(
        &self,
        path: &str,
        maximum_follow: usize,
    ) -> KResult<Arc<dyn INode>> {
        self.inode.lookup_with_symlink(path, maximum_follow)
    }

    pub fn poll(&self) -> KResult<PollFlags> {
        self.inode.poll()
    }

    pub fn async_poll(&self) -> Pin<Box<AsyncPoll>> {
        self.inode.async_poll()
    }

    pub fn entry(&mut self) -> KResult<String> {
        let mut file_option = self.file_option.write();
        if !file_option.open_option.contains(FileOpenOption::READ) {
            return Err(Errno::EBADF);
        }

        let mut offset = &mut file_option.offset;
        let name = self.inode.entry(*offset as usize)?;
        *offset += 1;
        Ok(name)
    }

    pub fn ioctl(&self, cmdline: u64, size: usize) -> KResult<()> {
        self.inode.ioctl(cmdline, size)
    }

    pub fn mmap(&mut self, mmap: MemoryMap) -> KResult<()> {
        match self.inode.metadata()?.ty {
            INodeType::CharDevice => self.inode.mmap(mmap),
            INodeType::File => {
                let perm = MmapPerm::from_bits_truncate(mmap.flags);
                let arena = Arena {
                    range: mmap.range.clone(),
                    flags: perm.into(),
                    callback: Box::new(FileArenaCallback {
                        mem_start: mmap.range.start,
                        file_start: mmap.offset,
                        file_end: mmap.offset + mmap.range.end - mmap.range.start,
                        frame_allocator: KernelFrameAllocator,
                        file: INodeWrapper(self.inode.clone()),
                    }),
                };

                let current = thread::current_thread().unwrap();
                current.vm.lock().add(arena);

                Ok(())
            }
            _ => Err(Errno::EINVAL),
        }
    }
}
