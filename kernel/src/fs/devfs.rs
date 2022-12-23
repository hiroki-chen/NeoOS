//! Devfs is an alternative to "real" character and block special devices on your root filesystem. Kernel device
//! drivers can register devices by name rather than major and minor numbers. These devices will appear in devfs
//! automatically, with whatever default ownership and protection the driver specified.

use core::any::Any;

use alloc::sync::Arc;

use crate::{arch::cpu::rdrand, error::KResult, sync::mutex::SpinLockNoInterrupt as Mutex};

use super::vfs::{INode, INodeMetadata, INodeType, PollFlags, Time};

struct RandomInner {
    seed: u32,
}

/// /dev/random
/// This is intended to be cryptographically secure, but this is left as future work.
#[derive(Clone)]
pub struct Random {
    inner: Arc<Mutex<RandomInner>>,
}

impl Random {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(RandomInner {
                seed: rdrand() as u32,
            })),
        }
    }
}

impl INode for Random {
    fn read_buf_at(&self, offset: usize, buf: &mut [u8]) -> KResult<usize> {
        let mut inner = self.inner.lock();

        // A simple linear congruential generator (LCG).
        // state = ((state * 1103515245) + 12345) & 0x7fffffff
        for byte in buf.iter_mut() {
            inner.seed = inner.seed.wrapping_mul(1103515245).wrapping_add(12345);
            *byte = ((inner.seed / 65536) % 255) as u8;
        }

        Ok(buf.len())
    }

    fn write_buf_at(&self, offset: usize, buf: &[u8]) -> KResult<usize> {
        Ok(0)
    }

    fn cast_to_any(&self) -> &dyn Any {
        self
    }

    fn poll(&self) -> KResult<PollFlags> {
        Ok(PollFlags::READ)
    }

    /// stat /dev/random
    fn metadata(&self) -> KResult<INodeMetadata> {
        Ok(INodeMetadata {
            dev_id: 1,
            inode_id: 9,
            mode: 0o666,
            link_num: 1,
            uid: 0,
            gid: 0,
            size: 0,
            times: Time {
                last_accessed: 0,
                last_modified: 0,
                last_stchange: 0,
            },
            blksize: 4096,
            block_num: 0,
            ty: INodeType::CharDevice,
        })
    }
}
