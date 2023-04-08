//! /dev/ttyS*

use core::sync::atomic::Ordering;

use alloc::{format, string::String, sync::Arc, vec::Vec};
use rcore_fs::vfs::{make_rdev, FileType, INode, Metadata, PollStatus, Timespec};

use crate::{
    drivers::{serial::SerialDriver, SERIAL_DRIVERS},
    fs::INODE_COUNT,
};

pub struct SerialINode {
    id: u64,
    serial_driver: Arc<dyn SerialDriver>,
}

impl SerialINode {
    pub fn get_all_device_inodes() -> Vec<(String, Arc<dyn INode>)> {
        SERIAL_DRIVERS
            .read()
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, driver)| {
                // Need an explicit type annotation.
                let inode: Arc<dyn INode> = Arc::new(Self {
                    id: INODE_COUNT.fetch_add(1, Ordering::SeqCst),
                    serial_driver: driver,
                });

                (format!("ttyS{}", idx), inode)
            })
            .collect()
    }
}

impl INode for SerialINode {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> rcore_fs::vfs::Result<usize> {
        let mut read_bytes = 0;
        buf.iter_mut().for_each(|b| {
            *b = self.serial_driver.read();
            read_bytes += 1;
        });

        Ok(read_bytes)
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> rcore_fs::vfs::Result<usize> {
        self.serial_driver.write(buf);
        Ok(buf.len())
    }

    fn poll(&self) -> rcore_fs::vfs::Result<PollStatus> {
        Ok(PollStatus {
            read: true,
            write: true,
            error: false,
        })
    }

    fn as_any_ref(&self) -> &dyn core::any::Any {
        self
    }

    fn metadata(&self) -> rcore_fs::vfs::Result<Metadata> {
        Ok(Metadata {
            dev: 1,
            inode: 1,
            size: 0,
            blk_size: 0,
            blocks: 0,
            atime: Timespec { sec: 0, nsec: 0 },
            mtime: Timespec { sec: 0, nsec: 0 },
            ctime: Timespec { sec: 0, nsec: 0 },
            type_: FileType::CharDevice,
            mode: 0o666,
            nlinks: 1,
            uid: 0,
            gid: 0,
            rdev: make_rdev(4, self.id as _),
        })
    }

    fn set_metadata(&self, _metadata: &Metadata) -> rcore_fs::vfs::Result<()> {
        Ok(())
    }
}
