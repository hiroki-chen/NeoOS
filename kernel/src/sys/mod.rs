//! Some bindings to the Unix-like data structures and function prototypes.

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use bitflags::bitflags;
use rcore_fs::vfs::Metadata;

use crate::{arch::io::IoVec, fs::apfs::meta::get_timestamp};

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

pub const AF_UNSPEC: u64 = 0;
pub const AF_UNIX: u64 = 1; /* Unix domain sockets 		*/
pub const AF_LOCAL: u64 = 1; /* POSIX name for AF_UNIX	*/
pub const AF_INET: u64 = 2; /* Internet IP Protocol 	*/
pub const AF_AX25: u64 = 3; /* Amateur Radio AX.25 		*/
pub const AF_IPX: u64 = 4; /* Novell IPX 			*/
pub const AF_APPLETALK: u64 = 5; /* AppleTalk DDP 		*/
pub const AF_NETROM: u64 = 6; /* Amateur Radio NET/ROM 	*/
pub const AF_BRIDGE: u64 = 7; /* Multiprotocol bridge 	*/
pub const AF_ATMPVC: u64 = 8; /* ATM PVCs			*/
pub const AF_X25: u64 = 9; /* Reserved for X.25 project 	*/
pub const AF_INET6: u64 = 10; /* IP version 6			*/
pub const AF_ROSE: u64 = 11; /* Amateur Radio X.25 PLP	*/
pub const AF_DECNET: u64 = 12; /* Reserved for DECnet project	*/
pub const AF_NETBEUI: u64 = 13; /* Reserved for 802.2LLC project*/
pub const AF_SECURITY: u64 = 14; /* Security callback pseudo AF */
pub const AF_KEY: u64 = 15; /* PF_KEY key management API */
pub const AF_NETLINK: u64 = 16;
pub const AF_ROUTE: u64 = AF_NETLINK; /* Alias to emulate 4.4BSD */
pub const AF_PACKET: u64 = 17; /* Packet family		*/
pub const AF_ASH: u64 = 18; /* Ash				*/
pub const AF_ECONET: u64 = 19; /* Acorn Econet			*/
pub const AF_ATMSVC: u64 = 20; /* ATM SVCs			*/
pub const AF_RDS: u64 = 21; /* RDS sockets 			*/
pub const AF_SNA: u64 = 22; /* Linux SNA Project (nutters!) */
pub const AF_IRDA: u64 = 23; /* IRDA sockets			*/
pub const AF_PPPOX: u64 = 24; /* PPPoX sockets		*/
pub const AF_WANPIPE: u64 = 25; /* Wanpipe API Sockets */
pub const AF_LLC: u64 = 26; /* Linux LLC			*/
pub const AF_IB: u64 = 27; /* Native InfiniBand address	*/
pub const AF_MPLS: u64 = 28; /* MPLS */
pub const AF_CAN: u64 = 29; /* Controller Area Network      */
pub const AF_TIPC: u64 = 30; /* TIPC sockets			*/
pub const AF_BLUETOOTH: u64 = 31; /* Bluetooth sockets 		*/
pub const AF_IUCV: u64 = 32; /* IUCV sockets			*/
pub const AF_RXRPC: u64 = 33; /* RxRPC sockets 		*/
pub const AF_ISDN: u64 = 34; /* mISDN sockets 		*/
pub const AF_PHONET: u64 = 35; /* Phonet sockets		*/
pub const AF_IEEE802154: u64 = 36; /* IEEE802154 sockets		*/
pub const AF_CAIF: u64 = 37; /* CAIF sockets			*/
pub const AF_ALG: u64 = 38; /* Algorithm sockets		*/
pub const AF_NFC: u64 = 39; /* NFC sockets			*/
pub const AF_VSOCK: u64 = 40; /* vSockets			*/
pub const AF_KCM: u64 = 41; /* Kernel Connection Multiplexor*/
pub const AF_QIPCRTR: u64 = 42; /* Qualcomm IPC Router          */
pub const AF_SMC: u64 = 43; /* smc sockets: reserve number for
                             * PF_SMC protocol family that
                             * reuses AF_INET address family
                             */
pub const AF_XDP: u64 = 44; /* XDP sockets			*/
pub const AF_MCTP: u64 = 45; /* Management component
                              * transport protocol
                              */
pub const AF_MAX: u64 = 46; /* For now.. */

pub const SEEK_SET: u64 = 0; /* seek relative to beginning of file */
pub const SEEK_CUR: u64 = 1; /* seek relative to current file position */
pub const SEEK_END: u64 = 2; /* seek relative to end of file */
pub const SEEK_DATA: u64 = 3; /* seek to the next data */
pub const SEEK_HOLE: u64 = 4; /* seek to the next hole */

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum IpProto {
    IpprotoIp = 0,
    IpprotoIcmp = 1,
    IpprotoTcp = 6,
    IpprotoUdp = 17,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct SockAddr {
    pub sa_family: u16,
    pub sa_data_min: [u8; 14],
}

impl SockAddr {
    pub fn to_core_sockaddr(&self) -> SocketAddr {
        let ip = Ipv4Addr::new(
            self.sa_data_min[2],
            self.sa_data_min[3],
            self.sa_data_min[4],
            self.sa_data_min[5],
        );
        let port = u16::from_be_bytes(self.sa_data_min[..2].try_into().unwrap());
        SocketAddr::V4(SocketAddrV4::new(ip, port))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum SocketType {
    SockStream = 1,
    SockDgram = 2,
    SockRaw = 3,
    // May be not supported.
    // pub const SOCK_RDM: u64 = 4;
    // pub const SOCK_SEQPACKET: u64 = 5;
    // pub const SOCK_DCCP: u64 = 6;
    // pub const SOCK_PACKET: u64 = 10;
}

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
    pub tv_sec: u64,
    /// Nanoseconds
    pub tv_nsec: u64,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Timezone {
    pub tz_minuteswest: u32,
    pub tz_dsttime: u32,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Time {
    pub time: i64,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct EpollEvent {
    pub events: EpollFlags,
    /// A pointer to the user data.
    pub data: u64,
}

bitflags! {
    #[derive(Default)]
    pub struct EpollFlags: u32 {
        const EPOLLIN = 0x001;
        const EPOLLPRI = 0x002;
        const EPOLLOUT = 0x004;
        const EPOLLERR = 0x008;
        const EPOLLHUP = 0x010;
        const EPOLLRDNORM = 0x040;
        const EPOLLRDBAND = 0x080;
        const EPOLLWRNORM = 0x100;
        const EPOLLWRBAND = 0x200;
        const EPOLLMSG = 0x400;
        const EPOLLRDHUP = 0x2000;
        const EPOLLEXCLUSIVE = 0x10000000;
        const EPOLLWAKEUP = 0x20000000;
        const EPOLLONESHOT = 0x40000000;
        const EPOLLET = 0x80000000;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u64)]
/// The socket options.
pub enum SocketOptions {
    /* Setsockoptions(2) level. Thanks to BSD these must match IPPROTO_xxx */
    SolIp = 0,
    /// This option is used to allow an application to provide its own IP header instead of relying
    /// on the kernel to generate it.
    IpHdrincl = 3,
    SolTcp = 6,
    SolUdp = 17,
    SolIpv6 = 41,
    SolIcmpv6 = 58,
    SolSctp = 132,
    SolUdplite = 136, /* UDP-Lite (RFC 3828) */
    SolRaw = 255,
    SolIpx = 256,
    SolAx25 = 257,
    SolAtalk = 258,
    SolNetrom = 259,
    SolRose = 260,
    SolDecnet = 261,
    SolX25 = 262,
    SolPacket = 263,
    SolAtm = 264, /* ATM layer (cell level) */
    SolAal = 265, /* ATM Adaption Layer (packet level) */
    SolIrda = 266,
    SolNetbeui = 267,
    SolLlc = 268,
    SolDccp = 269,
    SolNetlink = 270,
    SolTipc = 271,
    SolRxrpc = 272,
    SolPppol2tp = 273,
    SolBluetooth = 274,
    SolPnpipe = 275,
    SolRds = 276,
    SolIucv = 277,
    SolCaif = 278,
    SolAlg = 279,
    SolNfc = 280,
    SolKcm = 281,
    SolTls = 282,
    SolXdp = 283,
    SolMptcp = 284,
    SolMctp = 285,
    SolSmc = 286,
}

/// The `MsgHdr` struct is used to specify the message header in a call to `sendmsg` or `recvmsg` on a socket.
/// This struct is defined in the system header file `sys/socket.h`.
#[derive(Debug)]
#[repr(C)]
pub struct MsgHdr {
    pub msg_name: *mut SockAddr,
    pub msg_namelen: u64,
    pub msg_iov: *mut IoVec,
    pub msg_iovlen: u64,
    pub msg_control: u64,
    pub msg_controllen: u64,
    pub msg_flags: u64,
}

#[derive(Debug, Clone)]
/// Struct representing file status information, as returned by the `newfstatat()` system call.
#[repr(C)]
pub struct Stat {
    /// ID of device containing file
    st_dev: u64,
    /// Inode number
    st_ino: u64,
    /// Number of hard links
    st_nlink: u32,
    /// File type and mode
    st_mode: u32,
    /// User ID of owner
    st_uid: u32,
    /// Group ID of owner
    st_gid: u32,
    /// Pad
    _pad: u32,
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u64)]
pub enum FcntlCommand {
    FDupfd = 0,
    FGetfd = 1,
    /// Sets the descriptor flags for descriptor.
    FSetfd = 2,
    Unknown,
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
            _pad: 0,
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
