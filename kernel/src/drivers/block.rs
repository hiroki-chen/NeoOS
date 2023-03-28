//! This module implements block-like drivers.

use alloc::sync::Arc;
use log::debug;
use rcore_fs::dev::{self, BlockDevice, DevError};

use crate::{
    error::{Errno, KResult},
    function, kerror,
    memory::{allocate_frame_contiguous, deallocate_frame, phys_to_virt, virt_to_phys},
    sync::mutex::SpinLock as Mutex,
};

#[cfg(feature = "apfs")]
use crate::fs::apfs::Device;

use super::{
    isomorphic_drivers::{
        block::ahci::{AHCI, BLOCK_SIZE},
        provider::Provider,
    },
    Driver, Type, AHCI_UUID, BLOCK_DRIVERS, DRIVERS,
};

pub trait BlockDriver: Driver {
    /// Read block.
    fn read_block(&self, _bid: usize, _buf: &mut [u8]) -> bool {
        panic!("read_block(): Not a driver");
    }

    /// Write block.
    fn write_block(&self, _bid: usize, _buf: &[u8]) -> bool {
        panic!("write_block(): Not a driver");
    }
}

struct AhciProvider;

impl Provider for AhciProvider {
    const PAGE_SIZE: usize = 0x1000;

    fn alloc_dma(size: usize) -> (usize, usize) {
        let page_num = size / Self::PAGE_SIZE;
        let phys_addr = match allocate_frame_contiguous(page_num, 0) {
            Ok(addr) => addr,
            Err(errno) => panic!(" cannot allocate dma. Errno: {:?}", errno),
        }
        .as_u64();

        (phys_to_virt(phys_addr) as usize, phys_addr as usize)
    }

    fn dealloc_dma(vaddr: usize, size: usize) {
        let phys_addr = virt_to_phys(vaddr as u64);
        let page_num = size / Self::PAGE_SIZE;

        for i in 0..page_num {
            if let Err(errno) = deallocate_frame(phys_addr + (i * Self::PAGE_SIZE) as u64) {
                panic!(
                    "failed to deallocate memory at {:#x}. Errno: {:?}",
                    vaddr, errno
                );
            }
        }
    }
}

pub struct AhciDriver {
    inner: Mutex<AHCI<AhciProvider>>,
}

impl Driver for AhciDriver {
    fn dispatch(&self, _irq: Option<u64>) -> bool {
        false
    }

    fn ty(&self) -> Type {
        Type::Block
    }

    fn uuid(&self) -> &'static str {
        AHCI_UUID
    }
}

impl BlockDriver for AhciDriver {
    fn read_block(&self, bid: usize, buf: &mut [u8]) -> bool {
        let bytes = self.inner.lock().read_block(bid, buf);
        bytes != 0
    }

    fn write_block(&self, bid: usize, buf: &[u8]) -> bool {
        let bytes = match buf.len() {
            0..BLOCK_SIZE => 0,
            _ => self.inner.lock().write_block(bid, buf),
        };

        bytes != 0
    }
}

pub fn init_ahci(header: usize, size: usize) -> KResult<Arc<AhciDriver>> {
    debug!(
        "init_ahci(): initializing AHCI at {:#x} with size {:#x}",
        header, size
    );

    match AHCI::new(header, size) {
        Some(ahci) => {
            let ahci = Arc::new(AhciDriver {
                inner: Mutex::new(ahci),
            });
            DRIVERS.write().push(ahci.clone());
            BLOCK_DRIVERS.write().push(ahci.clone());

            Ok(ahci)
        }
        // No device!
        None => Err(Errno::EACCES),
    }
}

pub struct BlockDriverWrapper(pub Arc<dyn BlockDriver>);

#[cfg(feature = "sfs")]
impl BlockDevice for BlockDriverWrapper {
    const BLOCK_SIZE_LOG2: u8 = 9; // 512
    fn read_at(&self, block_id: usize, buf: &mut [u8]) -> dev::Result<()> {
        match self.0.read_block(block_id, buf) {
            true => Ok(()),
            false => Err(DevError),
        }
    }

    fn write_at(&self, block_id: usize, buf: &[u8]) -> dev::Result<()> {
        match self.0.write_block(block_id, buf) {
            true => Ok(()),
            false => Err(DevError),
        }
    }

    fn sync(&self) -> dev::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "apfs")]
impl Device for BlockDriverWrapper {
    fn read_buf_at(&self, offset: usize, buf: &mut [u8]) -> KResult<usize> {
        // Note that the block_size for AHCI driver is 512 bytes.
        let start = offset / BLOCK_SIZE;
        // How many AHCI blocks to be read.
        let nblocks = (buf.len() as f64 / BLOCK_SIZE as f64).ceil() as usize;

        for i in 0..nblocks {
            // The buf range.
            let range_start = i * BLOCK_SIZE;
            let range_end = (range_start + BLOCK_SIZE).min(buf.len());

            if !self
                .0
                .read_block(i + start, &mut buf[range_start..range_end])
            {
                kerror!("read AHCI block error.");
                return Err(Errno::ENODEV);
            }
        }

        Ok(buf.len())
    }

    fn write_buf_at(&self, offset: usize, buf: &[u8]) -> KResult<usize> {
        #[cfg(feature = "apfs_write")]
        unimplemented!();

        #[cfg(not(feature = "apfs_write"))]
        panic!("cannot write to a read-only partition!");
    }

    fn sync(&self) -> KResult<()> {
        Ok(())
    }
}
