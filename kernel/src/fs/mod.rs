//! Implementes the filesystem. We will migrate to APFS (to appear) and SFS.
//!
//! Some useful links:
//! * <https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf>
//! * <https://developer.apple.com/documentation/foundation/file_system/about_apple_file_system>

use alloc::{sync::Arc, vec::Vec};
use lazy_static::lazy_static;
use rcore_fs::vfs::{FileSystem, INode};
use rcore_fs_mountfs::MountFS;

use crate::{
    drivers::{block::BlockDriverWrapper, BLOCK_DRIVERS},
    error::KResult,
    fs::sfs::SimpleFileSystem,
};

use self::apfs::Device;

pub mod devfs;
pub mod file;

#[cfg(feature = "apfs")]
pub mod apfs;
#[cfg(feature = "sfs")]
pub mod sfs;

#[cfg(not(any(feature = "sfs", feature = "apfs")))]
compile_error!("Must specify one filesystem type: apfs or sfs.");

#[cfg(all(feature = "mount_sfs", feature = "mount_apfs"))]
compile_error!("You cannot mount both filesystems!");

pub const MAXIMUM_FOLLOW: usize = 0x4;

// A debugging implementation.
impl Device for Vec<u8> {
    fn read_buf_at(&self, offset: usize, buf: &mut [u8]) -> KResult<usize> {
        buf.copy_from_slice(&self[offset..offset + buf.len()]);
        Ok(buf.len())
    }

    fn sync(&self) -> KResult<()> {
        Ok(())
    }

    fn write_buf_at(&self, _offset: usize, _buf: &[u8]) -> KResult<usize> {
        Ok(0)
    }
}

#[cfg(feature = "mount_sfs")]
lazy_static! {
    /// Mounts the simple filesystem and returns a root inode.
    pub static ref ROOT_INODE: Arc<dyn INode> = {
        let device = Arc::new( BlockDriverWrapper(BLOCK_DRIVERS.read().iter().next().unwrap().clone()));
        let sfs = SimpleFileSystem::open(device).expect("failed to open SFS");
        let rootfs = MountFS::new(sfs);
        let root = rootfs.root_inode();

        root
    };
}

#[cfg(feature = "mount_apfs")]
lazy_static! {
    // to be implemented.
}
