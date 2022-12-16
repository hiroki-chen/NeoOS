//! This module implements block-like drivers.

use alloc::sync::Arc;
use log::debug;

use crate::{
    error::{Errno, KResult},
    memory::{allocate_frame_contiguous, deallocate_frame, phys_to_virt, virt_to_phys},
    sync::mutex::SpinLock as Mutex,
};

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
        debug!("alloc_dma(): need {:#x}", size);

        let page_num = size / Self::PAGE_SIZE;
        let phys_addr = match allocate_frame_contiguous(page_num, 0) {
            Ok(addr) => addr,
            Err(errno) => panic!("alloc_dma(): cannot allocate dma. Errno: {:?}", errno),
        }
        .as_u64();

        (phys_to_virt(phys_addr) as usize, phys_addr as usize)
    }

    fn dealloc_dma(vaddr: usize, size: usize) {
        debug!("dealloc_dma(): {:#x} @ {:#x}", size, vaddr);

        let phys_addr = virt_to_phys(vaddr as u64);
        let page_num = size / Self::PAGE_SIZE;

        for i in 0..page_num {
            if let Err(errno) = deallocate_frame(phys_addr + (i * Self::PAGE_SIZE) as u64) {
                panic!(
                    "dealloc_dma(): failed to deallocate memory at {:#x}. Errno: {:?}",
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
        Type::BLOCK
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
