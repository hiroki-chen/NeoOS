//!  A sink like `/dev/null` is a destination for data that is discarded and not used. In programming, it's often
//! used to discard unwanted output or errors.

use core::sync::atomic::Ordering;

use rcore_fs::vfs::{INode, Metadata};

use crate::fs::INODE_COUNT;

pub struct NullINode {
    /// The inode id.
    pub id: u64,
}

impl NullINode {
    pub fn new() -> Self {
        Self {
            id: INODE_COUNT.fetch_add(1, Ordering::SeqCst),
        }
    }
}

impl INode for NullINode {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> rcore_fs::vfs::Result<usize> {
        Ok(0)
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> rcore_fs::vfs::Result<usize> {
        Ok(buf.len())
    }

    fn poll(&self) -> rcore_fs::vfs::Result<rcore_fs::vfs::PollStatus> {
        Ok(rcore_fs::vfs::PollStatus {
            read: false,
            write: true,
            error: false,
        })
    }

    fn as_any_ref(&self) -> &dyn core::any::Any {
        self
    }

    fn set_metadata(&self, _metadata: &Metadata) -> rcore_fs::vfs::Result<()> {
        Ok(())
    }
}
