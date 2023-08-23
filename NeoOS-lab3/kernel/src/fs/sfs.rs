//! Simple Filesystem implementation.
//!
//! The first block of the disk is the superblock that describes the layout of the rest of the filesystem. A
//! certain number of blocks following the superblock contain inode data structures. Typically, ten percent
//! of the total number of disk blocks are used as inode blocks. The remaining blocks in the filesystem are
//! used as plain data blocks.

use core::fmt::Debug;

use alloc::sync::{Arc, Weak};
use bitvec::prelude::*;
use spin::RwLock;

use crate::error::KResult;

use super::{
    file::FileType,
    vfs::{FileSytem, MaybeDirty, Time},
};

pub const MAGIC_NUMBER: u32 = 0xf0f03410;

/// Superblock: Contains information about the entire file system; how many inodes, data blocks we have,
/// where the inode table starts, and some supplmentary information. 32-byte aligned.
#[derive(Debug)]
#[repr(C)]
pub struct SuperBlock {
    pub magic: u32,
    /// Number of the blocks.
    pub blocks: u32,
    /// Remaining size.
    pub free_blocks: u32,
    /// Information.
    pub info: [u8; 32],
    /// number of freemap blocks
    pub freemap_blocks: u32,
}

impl SuperBlock {
    pub fn check_magic(&self) -> bool {
        self.magic == MAGIC_NUMBER
    }
}

/// The INode for storage. Shares in common with vfs::INodeMetadata.
#[derive(Debug)]
#[repr(C)]
pub struct DiskINode {
    pub size: u32,
    pub ty: FileType,
    pub nlinks: u32,
    pub block_num: u32,
    pub link_num: u32,
    pub times: Time,
    pub direct: [u32; 12],
    pub indirect: u32,
    pub db_indirect: u32,
    pub device_inode_id: usize,
}

/// The INode for SFS.
pub struct SFSINode {
    id: u64,
    disk_inode: RwLock<MaybeDirty<DiskINode>>,
    filesystem: Arc<SimpleFileSystem>,
    device_inode_id: usize,
}

impl Debug for SFSINode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "INode {{ id: {}, disk: {:?} }}",
            self.id, self.disk_inode
        )
    }
}

pub trait Device: Send + Sync {
    fn read_buf_at(&self, offset: usize, buf: &mut [u8]) -> KResult<usize>;
    fn write_buf_at(&self, offset: usize, buf: &[u8]) -> KResult<usize>;
    fn sync(&self) -> KResult<()>;
}

pub struct SimpleFileSystem {
    superblock: RwLock<MaybeDirty<SuperBlock>>,
    device: Arc<dyn Device>,
    slf: Weak<Self>,
    freemap: RwLock<MaybeDirty<BitVec<u8, Lsb0>>>,
}

impl FileSytem for SimpleFileSystem {
    fn metadata(&self) -> KResult<super::vfs::FsMetadata> {
        todo!()
    }

    fn root(&self) -> KResult<Arc<dyn super::vfs::INode>> {
        todo!()
    }

    fn sync(&self) -> KResult<()> {
        todo!()
    }
}

impl Drop for SimpleFileSystem {
    fn drop(&mut self) {
        self.sync()
            .expect("Failed to sync when dropping the SimpleFileSystem");
    }
}
