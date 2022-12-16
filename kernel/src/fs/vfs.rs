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

use core::any::Any;

use alloc::sync::Arc;

use crate::error::KResult;

/// The `Inode` abstraction.
/// The inode (index node) keeps information about a file in the general sense (abstraction): regular file
/// directory, special file (pipe, fifo), block device, character device, link, or anything that can be
/// abstracted as a file.
pub trait INode: Any + Sync + Send {
    /// Returns the metadata of this INode.
    fn get_metadata(&self) -> KResult<InodeMetadata>;

    /// Sets the metadata.
    fn set_metadata(&mut self, metadata: &InodeMetadata) -> KResult<()>;

    /// Reads the file into buffer.
    fn read_buf(&self, buf: &mut [u8]) -> KResult<usize>;

    /// Writes into the file.
    fn write_buf(&mut self, buf: &[u8]) -> KResult<usize>;

    /// Creates hard link to `target`.
    fn link(&self, target: &Arc<dyn INode>, name: &str) -> KResult<()>;
}

/// The VFS.
pub trait FileSytem: Sync + Send {
    /// Syncs all refernces.
    fn sync(&self) -> KResult<()>;

    /// Returns the root inode of this file system.
    fn root() -> KResult<Arc<dyn INode>>;

    /// Returns the filesystem metadata.
    fn get_metadata(&self) -> KResult<FsMetadata>;
}

/// File types.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FileType {
    File,
    Dir,
    SymLink,
    CharDevice,
    BlockDevice,
}

/// Granularity: second.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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
pub struct InodeMetadata {
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
    pub ty: FileType,
}
