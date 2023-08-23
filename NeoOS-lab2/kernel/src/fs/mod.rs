//! Implementes the filesystem. We will migrate to APFS (to appear) and SFS.
//!
//! Some useful links:
//! * <https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf>
//! * <https://developer.apple.com/documentation/foundation/file_system/about_apple_file_system>

use core::sync::atomic::AtomicU64;

use alloc::{sync::Arc, vec::Vec};
use bitflags::bitflags;
use lazy_static::lazy_static;
use rcore_fs::vfs::INode;
use rcore_fs_mountfs::MountFS;

use crate::{
    drivers::{block::BlockDriverWrapper, BLOCK_DRIVERS},
    error::KResult,
    fs::{devfs::DEV_FS, proc::PROC_FS},
};

pub mod devfs;
pub mod epoll;
pub mod file;
pub mod proc;

#[cfg(feature = "apfs")]
pub mod apfs;
#[cfg(feature = "sfs")]
pub mod sfs;

pub const AT_FDCWD: isize = -100;
/// Shared for pseudo filesystems.
pub static INODE_COUNT: AtomicU64 = AtomicU64::new(0);

bitflags! {
    #[derive(Default)]
    pub struct InodeOpType: u8 {
        const ACCESS = 0x1;
        const MODIFY = 0x2;
        const CREATE = 0x4;
    }
}

#[cfg(not(any(feature = "sfs", feature = "apfs")))]
compile_error!("Must specify one filesystem type: apfs or sfs.");

#[cfg(all(feature = "mount_sfs", feature = "mount_apfs"))]
compile_error!("You cannot mount both filesystems!");

pub const MAXIMUM_FOLLOW: usize = 0x4;

#[cfg(feature = "apfs")]
// A debugging implementation.
impl apfs::Device for Vec<u8> {
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
    use rcore_fs_mountfs::MountFS;

    use crate::fs::sfs::SimpleFileSystem;
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
    pub static ref ROOT_INODE: Arc<dyn INode> = {
        let device = Arc::new(BlockDriverWrapper(
            BLOCK_DRIVERS.read().iter().next().unwrap().clone(),
        ));
        let apfs = apfs::AppleFileSystem::mount_container(device).unwrap();
        apfs.load_nx_object_map().unwrap();
        apfs.mount_volumns_all().unwrap();

        let apfs = MountFS::new(apfs);
        let root = apfs.mountpoint_root_inode();
        let dev = root.find(true, "dev").unwrap();
        dev.mount(DEV_FS.clone()).unwrap();
        let proc = root.find(true, "proc").unwrap();
        proc.mount(PROC_FS.clone()).unwrap();

        root
    };
}
