//! Implementes the filesystem. We will migrate to APFS (to appear) and SFS.
//!
//! Some useful links:
//! * <https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf>
//! * <https://developer.apple.com/documentation/foundation/file_system/about_apple_file_system>

use alloc::vec::Vec;

use crate::error::KResult;

use self::apfs::Device;

pub mod devfs;
pub mod file;

#[cfg(feature = "apfs")]
pub mod apfs;
#[cfg(feature = "sfs")]
pub mod sfs;

#[cfg(not(any(feature = "sfs", feature = "apfs")))]
compile_error!("Must specify one filesystem type: apfs or sfs.");

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
