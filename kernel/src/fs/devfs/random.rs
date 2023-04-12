use core::{any::Any, sync::atomic::Ordering};

use alloc::sync::Arc;
use rcore_fs::vfs::{make_rdev, FileType, INode, Metadata, PollStatus, Result, Timespec};

use crate::{arch::cpu::rdrand, fs::INODE_COUNT, sync::mutex::SpinLockNoInterrupt as Mutex};

struct RandomInner {
    seed: u32,
}

/// /dev/random
/// This is intended to be cryptographically secure, but this is left as future work.
#[derive(Clone)]
pub struct Random {
    id: u64,
    inner: Arc<Mutex<RandomInner>>,
}

impl Random {
    pub fn new() -> Self {
        Self {
            id: INODE_COUNT.fetch_add(1, Ordering::SeqCst),
            inner: Arc::new(Mutex::new(RandomInner {
                seed: rdrand() as u32,
            })),
        }
    }
}

impl INode for Random {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let mut inner = self.inner.lock();

        // A simple linear congruential generator (LCG).
        // state = ((state * 1103515245) + 12345) & 0x7fffffff
        for byte in buf.iter_mut() {
            inner.seed = inner.seed.wrapping_mul(1103515245).wrapping_add(12345);
            *byte = ((inner.seed / 65536) % 255) as u8;
        }

        Ok(buf.len())
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        Ok(0)
    }

    fn as_any_ref(&self) -> &dyn Any {
        self
    }

    fn poll(&self) -> Result<PollStatus> {
        Ok(PollStatus::default())
    }

    /// stat /dev/random
    fn metadata(&self) -> Result<Metadata> {
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
            // Assume secure.
            rdev: make_rdev(1, 9),
        })
    }

    fn set_metadata(&self, _metadata: &Metadata) -> Result<()> {
        Ok(())
    }
}
