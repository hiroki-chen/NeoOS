//! /dev/zero A zerod device.

use rcore_fs::vfs::INode;

pub struct ZeroInode;

impl INode for ZeroInode {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> rcore_fs::vfs::Result<usize> {
        buf.fill(0);
        Ok(buf.len())
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> rcore_fs::vfs::Result<usize> {
        // Do not write to zero.
        Ok(0)
    }

    fn poll(&self) -> rcore_fs::vfs::Result<rcore_fs::vfs::PollStatus> {
        Ok(rcore_fs::vfs::PollStatus {
            read: true,
            write: false,
            error: false,
        })
    }

    fn as_any_ref(&self) -> &dyn core::any::Any {
        self
    }
}
