//! The Virtual File System (also known as the Virtual Filesystem Switch) is the software layer in the
//! kernel that provides the filesystem interface to userspace programs. It also provides an abstraction
//! within the kernel which allows different filesystem implementations to coexist.
//!
//! The basic idea of VFS is to provide a single file model that can represent files from any file system.
//! The file system driver is responsible for bringing to the common denominator. This way the kernel can
//! create a single directory structure that contains the entire system. There will be a file system that
//! will be the root, the rest being mounted in its various directories.
//!
//! Virtual Filesystem. is an abstract layer on top of a more concrete file system. The purpose of a VFS is
//! to allow client applications to access different types of concrete file systems in a uniform way.
//!
//! It is only a set of interfaces that are backend-agnostic.

use core::{any::Any, future::Future, ops::Range, pin::Pin};

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use bitflags::bitflags;

use crate::error::{Errno, KResult};

bitflags! {
    pub struct PollFlags: u8 {
        const READ = 0b0001;
        const WRITE = 0b0010;
        const ERROR = 0b0100;
    }
}

/// To poll futures, they must be *pinned* using a special type called Pin<T>.
pub type AsyncPoll<'a> = dyn Future<Output = KResult<PollFlags>> + Sync + Send + 'a;

/// The `Inode` abstraction.
/// The inode (index node) keeps information about a file in the general sense (abstraction): regular file
/// directory, special file (pipe, fifo), block device, character device, link, or anything that can be
/// abstracted as a file.
pub trait INode: Any + Sync + Send {
    /// Polls the event synchronously. Blocks the caller.
    fn poll(&self) -> KResult<PollFlags>;

    /// Asynchronously polls the event. Non-blocking. Returns a future.
    fn async_poll<'a>(&'a self) -> Pin<Box<AsyncPoll<'a>>> {
        // We must use `pin` to let it remain in the memory if not read.
        // So the ownership must be moved.
        Box::pin(async move { self.poll() })
    }

    /// Returns the entry at `index`.
    fn entry(&self, index: usize) -> KResult<String> {
        Err(Errno::ENOSPC)
    }

    /// Returns the filesystem.
    fn filesystem(&self) -> KResult<Arc<dyn FileSytem>> {
        Err(Errno::ENOSPC)
    }

    /// Returns the metadata of this INode.
    fn metadata(&self) -> KResult<INodeMetadata> {
        Err(Errno::ENOSPC)
    }

    /// Sets the metadata.
    fn set_metadata(&self, metadata: &INodeMetadata) -> KResult<()> {
        Err(Errno::ENOSPC)
    }

    /// Reads the file into buffer.
    fn read_buf_at(&self, offset: usize, buf: &mut [u8]) -> KResult<usize>;

    /// Writes into the file.
    fn write_buf_at(&self, offset: usize, buf: &[u8]) -> KResult<usize>;

    /// Resize to the given size.
    fn resize(&self, new_size: usize) -> KResult<()> {
        Err(Errno::ENOSPC)
    }

    /// Creates hard link to `target`.
    fn link(&self, target: &Arc<dyn INode>, name: &str) -> KResult<()> {
        Err(Errno::ENOSPC)
    }

    /// Finds the INode in the directory.
    fn find(&self, name: &str) -> KResult<Arc<dyn INode>> {
        Err(Errno::ENOSPC)
    }

    /// Unlinks to `name`.
    fn unlink(&self, name: &str) -> KResult<()> {
        Err(Errno::ENOSPC)
    }

    /// Creats a new `INode` in the directory.
    fn create(&self, inode_name: &str, ty: INodeType, mode: u16) -> KResult<Arc<dyn INode>> {
        Err(Errno::ENOSPC)
    }

    /// Move to another inode. N.b.: `move` is a Rust keyword.
    /// Rename if `target == self`.
    fn do_move(&self, target: &Arc<dyn INode>, old_name: &str, new_name: &str) -> KResult<()> {
        Err(Errno::ENOSPC)
    }

    /// Syncs all the data of this `INode` (including metadata).
    fn sync_all(&self) -> KResult<()> {
        Err(Errno::ENOSPC)
    }

    /// Syncs data except the metadata.
    fn sync_data(&self) -> KResult<()> {
        Err(Errno::ENOSPC)
    }

    /// Upper-cast to `Any`.
    fn cast_to_any(&self) -> &dyn Any;

    /// Returns the IOCTL device.
    fn ioctl(&self, cmdline: u64, size: usize) -> KResult<()> {
        Err(Errno::ENOSPC)
    }

    /// Maps into memory.
    fn mmap(&self, mem: MemoryMap) -> KResult<()> {
        Err(Errno::ENOSPC)
    }

    /// Updates last accessed time.
    fn set_atime(&self, atime: u64) -> KResult<()> {
        Err(Errno::ENOSPC)
    }

    /// Updates last modified time.
    fn set_mtime(&self, mtime: u64) -> KResult<()> {
        Err(Errno::ENOSPC)
    }

    /// Updates the last st change.
    fn set_stchange(&self, stchange: u64) -> KResult<()> {
        Err(Errno::ENOSPC)
    }
}

/// A utility trait if you want to read the INode into a vector as manipulating `[u8]` is burdensome.
pub trait INodeReadVec: INode {
    fn read_vec(&self) -> KResult<Vec<u8>> {
        let size = self.metadata()?.size;
        let mut vec = Vec::with_capacity(size);
        vec.fill(0u8);
        let read_size = self.read_buf_at(0, vec.as_mut_slice())?;

        if read_size != size {
            // Corrupted??
            Err(Errno::EFAULT)
        } else {
            Ok(vec)
        }
    }
}

/// The VFS.
pub trait FileSytem: Sync + Send {
    /// Syncs all refernces (superblock operations).
    fn sync(&self) -> KResult<()>;

    /// Returns the root inode of this file system.
    fn root(&self) -> KResult<Arc<dyn INode>>;

    /// Returns the filesystem metadata.
    fn metadata(&self) -> KResult<FsMetadata>;
}

/// File types.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum INodeType {
    File,
    Dir,
    SymLink,
    CharDevice,
    BlockDevice,
}

/// Manages mmap for the filesystem. When some blocks are read, they will be mapped into the memory
/// in the form of `INode`.
#[derive(Debug)]
pub struct MemoryMap {
    pub range: Range<u64>,
    /// Access permissions
    pub perm: u64,
    /// Flags
    pub flags: u64,
    /// Offset from the file in bytes
    pub offset: u64,
}

/// Granularity: second.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Time {
    /// Last accessed timestamp.
    pub last_accessed: usize,
    /// last modified timestamp.
    pub last_modified: usize,
    /// Last status change.
    pub last_stchange: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsMetadata {
    /// File system block size
    pub block_size: usize,
    /// Total block numbers.
    pub block_num: usize,
    /// Free block numbers.
    pub block_free_num: usize,
    /// Non-privileged block free number.
    pub block_available_num: usize,
    /// Total file numbers.
    pub file_num: usize,
    /// Free file numbers.
    pub file_free_num: usize,
    /// Maximum allowed file name length.
    pub name_maxlen: usize,
    /// Fundamental file system block size
    pub frsize: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct INodeMetadata {
    /// MAJOR | MINOR
    pub dev_id: u64,
    /// INode id.
    pub inode_id: u64,
    /// Access rights / mode.
    pub mode: u16,
    /// Number of hard links to the file.
    pub link_num: usize,
    /// User ID of the file. (who owns it?)
    pub uid: usize,
    /// Group ID of file.
    pub gid: usize,
    /// Size of the actual object.
    pub size: usize,
    /// Times.
    pub times: Time,
    /// A file system-specific preferred I/O block size for
    /// this object. In some file system types, this may
    /// vary from file to file.
    pub blksize: usize,
    /// Number of blocks allocated for this object.
    pub block_num: usize,
    /// Type.
    pub ty: INodeType,
}

/// `MaybeDirty` denotes a value can be written or read as dirty. This is used to lazily
/// write modified data back to the disk for better performance.
pub struct MaybeDirty<T> {
    inner: T,
    dirty: bool,
}

impl<T> MaybeDirty<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            dirty: false,
        }
    }

    pub fn new_dirty(inner: T) -> Self {
        Self { inner, dirty: true }
    }

    pub fn toggle(&mut self) {
        self.dirty = !self.dirty;
    }

    pub fn clear(&mut self) {
        self.dirty = false;
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
}
