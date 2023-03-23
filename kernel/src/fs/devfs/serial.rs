//! /dev/ttyS*

use core::sync::atomic::Ordering;

use alloc::{format, string::String, sync::Arc, vec::Vec};
use rcore_fs::vfs::INode;

use crate::drivers::{serial::SerialDriver, SERIAL_DRIVERS};

use super::INODE_COUNT;

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
        todo!()
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> rcore_fs::vfs::Result<usize> {
        todo!()
    }

    fn poll(&self) -> rcore_fs::vfs::Result<rcore_fs::vfs::PollStatus> {
        todo!()
    }

    fn as_any_ref(&self) -> &dyn core::any::Any {
        self
    }
}
