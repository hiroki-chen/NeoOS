//! Implementes the filesystem. We will migrate to APFS (to appear) and SFS.
//!
//! Some useful links:
//! * <https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf>
//! * <https://developer.apple.com/documentation/foundation/file_system/about_apple_file_system>

pub mod devfs;
pub mod file;

#[cfg(feature = "apfs")]
pub mod apfs;
#[cfg(feature = "sfs")]
pub mod sfs;

#[cfg(not(any(feature = "sfs", feature = "apfs")))]
compile_error!("Must specify one filesystem type: apfs or sfs.");

pub const MAXIMUM_FOLLOW: usize = 0x4;
