//! Some bindings to the Unix-like data structures and function prototypes.

use bitflags::bitflags;
use rcore_fs::vfs::Metadata;

use crate::fs::apfs::meta::get_timestamp;

pub const AT_EMPTY_PATH: u64 = 0x1000;
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;

bitflags! {
    #[derive(Default)]
    pub struct Prot: u64 {
        const PROT_READ = 0x1;		/* page can be read */
        const PROT_WRITE = 0x2;		/* page can be written */
        const PROT_EXEC = 0x4;		/* page can be executed */
        const PROT_SEM = 0x8;		/* page may be used for atomic ops */
        /*			0x10		   reserved for arch-specific use */
        /*			0x20		   reserved for arch-specific use */
        const PROT_NONE = 0x0;		/* page can not be accessed */
        const PROT_GROWSDOWN = 0x01000000;	/* mprotect flag: extend change to start of growsdown vma */
        const PROT_GROWSUP = 0x02000000;	/* mprotect flag: extend change to end of growsup vma */
    }
}

pub const MAP_SHARED: u64 = 0x01; /* Share changes */
pub const MAP_PRIVATE: u64 = 0x02; /* Changes are private */
pub const MAP_SHARED_VALIDATE: u64 = 0x03; /* share + validate extension flags */
pub const MAP_TYPE: u64 = 0x0f; /* Mask for type of mapping */
pub const MAP_FIXED: u64 = 0x10; /* Interpret addr exactly */
pub const MAP_ANONYMOUS: u64 = 0x20; /* don't use a file */
pub const MAP_POPULATE: u64 = 0x008000; /* populate (prefault) pagetables */
pub const MAP_NONBLOCK: u64 = 0x010000; /* do not block on IO */
pub const MAP_STACK: u64 = 0x020000; /* give out an address that is best suited for process/thread stacks */
pub const MAP_HUGETLB: u64 = 0x040000; /* create a huge page mapping */
pub const MAP_SYNC: u64 = 0x080000; /* perform synchronous page faults for the mapping */
pub const MAP_FIXED_NOREPLACE: u64 = 0x100000; /* MAP_FIXED which doesn't unmap underlying mapping */

pub const MAP_UNINITIALIZED: u64 = 0x4000000; /* For anonymous mmap, memory could be
                                               * uninitialized */

// MAP_HUDE_* constants are not supported.

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Stat64 {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: u64,
    pub st_blksize: u64,
    pub st_blocks: u64,
    pub st_atime: u64,
    pub st_atime_nsec: u64,
    pub st_mtime: u64,
    pub st_mtime_nsec: u64,
    pub st_ctime: u64,
    pub st_ctime_nsec: u64,
    pub __unused: [u8; 24],
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Timeval {
    pub tv_sec: u64,
    pub tv_usec: u64,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Timespec {
    /// Seconds
    tv_sec: u64,
    /// Nanoseconds
    tv_nsec: u64,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Timezone {
    pub tz_minuteswest: u32,
    pub tz_dsttime: u32,
}

#[derive(Debug, Clone)]
/// Struct representing file status information, as returned by the `newfstatat()` system call.
#[repr(C)]
pub struct Stat {
    /// ID of device containing file
    st_dev: u64,
    /// Inode number
    st_ino: u64,
    /// File type and mode
    st_mode: u32,
    /// Number of hard links
    st_nlink: u32,
    /// User ID of owner
    st_uid: u32,
    /// Group ID of owner
    st_gid: u32,
    /// Device ID (if special file)
    st_rdev: u64,
    /// Total size, in bytes
    st_size: u64,
    /// Block size for filesystem I/O
    st_blksize: u32,
    /// Number of 512B blocks allocated
    st_blocks: u64,
    /// Time of last access
    st_atim: Timespec,
    /// Time of last modification
    st_mtim: Timespec,
    /// Time of last status change
    st_ctim: Timespec,
    /// Backward compatibility for st_atim
    st_atime: u64,
    /// Backward compatibility for st_mtim
    st_mtime: u64,
    /// Backward compatibility for st_ctim
    st_ctime: u64,
}

impl Stat {
    pub fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            st_dev: metadata.dev as _,
            st_ino: metadata.inode as _,
            st_mode: metadata.mode as _,
            st_nlink: metadata.nlinks as _,
            st_uid: metadata.uid as _,
            st_gid: metadata.gid as _,
            st_rdev: metadata.rdev as _,
            st_size: metadata.size as _,
            st_blksize: metadata.blk_size as _,
            st_blocks: metadata.blocks as _,
            st_atim: Timespec {
                tv_sec: metadata.atime.sec as _,
                tv_nsec: metadata.atime.nsec as _,
            },
            st_mtim: Timespec {
                tv_sec: metadata.mtime.sec as _,
                tv_nsec: metadata.mtime.nsec as _,
            },
            st_ctim: Timespec {
                tv_sec: metadata.ctime.sec as _,
                tv_nsec: metadata.ctime.nsec as _,
            },
            st_atime: get_timestamp(metadata.atime).as_nanos() as _,
            st_mtime: get_timestamp(metadata.mtime).as_nanos() as _,
            st_ctime: get_timestamp(metadata.ctime).as_nanos() as _,
        }
    }
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct Utsname {
    /// Operating system name
    pub sysname: [u8; 65],
    /// Name within "some implementation-defined network"
    pub nodename: [u8; 65],
    /// Operating system release (e.g., "2.6.28")
    pub release: [u8; 65],
    /// Operating system version
    pub version: [u8; 65],
    /// Hardware identifier
    pub machine: [u8; 65],
    /// NIS or YP domain name
    pub domainname: [u8; 65],
}

impl Utsname {
    pub fn default_uname() -> Self {
        const SYSNAME: &[u8] = b"NeoOS";
        const RELEASE: &[u8] = b"0.1.0";
        const VERSION: &[u8] = b"1";
        const MACHINE: &[u8] = b"QEMU_Simulator";
        const DOMAIN: &[u8] = b"com.qemu.kernel.neoos";

        Self {
            sysname: {
                let mut arr = [0u8; 65];
                arr[..SYSNAME.len()].copy_from_slice(SYSNAME);
                arr
            },
            nodename: [0u8; 65],
            release: {
                let mut arr = [0u8; 65];
                arr[..RELEASE.len()].copy_from_slice(RELEASE);
                arr
            },
            version: {
                let mut arr = [0u8; 65];
                arr[..VERSION.len()].copy_from_slice(VERSION);
                arr
            },
            machine: {
                let mut arr = [0u8; 65];
                arr[..MACHINE.len()].copy_from_slice(MACHINE);
                arr
            },
            domainname: {
                let mut arr = [0u8; 65];
                arr[..DOMAIN.len()].copy_from_slice(DOMAIN);
                arr
            },
        }
    }
}
