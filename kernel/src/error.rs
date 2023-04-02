use core::result::Result;

use rcore_fs::vfs::FsError;

/// Unix standard error codes.
///
/// The `perror` tool can be used to find the error message which is associated with a given error code.
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
pub enum Errno {
    EPERM = 1,
    ENOENT = 2,
    ESRCH = 3,
    EINTR = 4,
    EIO = 5,
    ENXIO = 6,
    E2BIG = 7,
    ENOEXEC = 8,
    EBADF = 9,
    ECHILD = 10,
    EAGAIN = 11,
    ENOMEM = 12,
    EACCES = 13,
    EFAULT = 14,
    ENOTBLK = 15,
    EBUSY = 16,
    EEXIST = 17,
    EXDEV = 18,
    ENODEV = 19,
    ENOTDIR = 20,
    EISDIR = 21,
    EINVAL = 22,
    ENFILE = 23,
    EMFILE = 24,
    ENOTTY = 25,
    ETXTBSY = 26,
    EFBIG = 27,
    ENOSPC = 28,
    ESPIPE = 29,
    EROFS = 30,
    EMLINK = 31,
    EPIPE = 32,
    EDOM = 33,
    ERANGE = 34,
    EDEADLK = 35,
    ENAMETOOLONG = 36,
    ENOLCK = 37,
    ENOSYS = 38,
    ENOTEMPTY = 39,
    ELOOP = 40,
    ENOMSG = 42,
    EIDRM = 43,
    ECHRNG = 44,
    EL2NSYNC = 45,
    EL3HLT = 46,
    EL3RST = 47,
    ELNRNG = 48,
    EUNATCH = 49,
    ENOCSI = 50,
    EL2HLT = 51,
    EBADE = 52,
    EBADR = 53,
    EXFULL = 54,
    ENOANO = 55,
    EBADRQC = 56,
    EBADSLT = 57,
    EBFONT = 59,
    ENOSTR = 60,
    ENODATA = 61,
    ETIME = 62,
    ENOSR = 63,
    ENONET = 64,
    ENOPKG = 65,
    EREMOTE = 66,
    ENOLINK = 67,
    EADV = 68,
    ESRMNT = 69,
    ECOMM = 70,
    EPROTO = 71,
    EMULTIHOP = 72,
    EDOTDOT = 73,
    EBADMSG = 74,
    EOVERFLOW = 75,
    ENOTUNIQ = 76,
    EBADFD = 77,
    EREMCHG = 78,
    ELIBACC = 79,
    ELIBBAD = 80,
    ELIBSCN = 81,
    ELIBMAX = 82,
    ELIBEXEC = 83,
    EILSEQ = 84,
    ERESTART = 85,
    ESTRPIPE = 86,
    EUSERS = 87,
    ENOTSOCK = 88,
    EDESTADDRREQ = 89,
    EMSGSIZE = 90,
    EPROTOTYPE = 91,
    ENOPROTOOPT = 92,
    EPROTONOSUPPORT = 93,
    ESOCKTNOSUPPORT = 94,
    EOPNOTSUPP = 95,
    EPFNOSUPPORT = 96,
    EAFNOSUPPORT = 97,
    EADDRINUSE = 98,
    EADDRNOTAVAIL = 99,
    ENETDOWN = 100,
    ENETUNREACH = 101,
    ENETRESET = 102,
    ECONNABORTED = 103,
    ECONNRESET = 104,
    ENOBUFS = 105,
    EISCONN = 106,
    ENOTCONN = 107,
    ESHUTDOWN = 108,
    ETOOMANYREFS = 109,
    ETIMEDOUT = 110,
    ECONNREFUSED = 111,
    EHOSTDOWN = 112,
    EHOSTUNREACH = 113,
    EALREADY = 114,
    EINPROGRESS = 115,
    ESTALE = 116,
    EUCLEAN = 117,
    ENOTNAM = 118,
    ENAVAIL = 119,
    EISNAM = 120,
    EREMOTEIO = 121,
    EDQUOT = 122,
    ENOMEDIUM = 123,
    EMEDIUMTYPE = 124,
    ECANCELED = 125,
    ENOKEY = 126,
    EKEYEXPIRED = 127,
    EKEYREVOKED = 128,
    EKEYREJECTED = 129,
    EOWNERDEAD = 130,
    ENOTRECOVERABLE = 131,
    ERFKILL = 132,
    EHWPOISON = 133,
}

/// The return value that indicates a successful execution ([`Ok`]) or failure ([`Err`]).
///
/// In Rust, it is idiomatic to model functions that may fail as returning
/// a [`Result`]. Since in the kernel many functions return an error code,
/// [`Result`] is a type alias for a [`core::result::Result`] that uses
/// [`Error`] as its error type.
pub type KResult<T> = Result<T, Errno>;

/// Converts from [`KResult`] to the unix-like error code represented by an [`i32`].
///
/// Useful in cases when the raw number of the error is needed. For example, a C function may want to invoke the Rust
/// FFI function but it does not recognize Rust error types.
///
/// # Examples
/// ```rust
/// let error = Err(Errno::EINVAL);
/// let error_code = error_to_int(error);
///
/// println!("My error code is {:#x}", error_code);
/// ```
pub fn error_to_int<T>(result: &KResult<T>) -> i32 {
    match result.as_ref() {
        Ok(_) => 0i32,
        Err(errno) => *errno as i32,
    }
}

// NotSupported,  // E_UNIMP, or E_INVAL
// NotFile,       // E_ISDIR
// IsDir,         // E_ISDIR, used only in link
// NotDir,        // E_NOTDIR
// EntryNotFound, // E_NOENT
// EntryExist,    // E_EXIST
// NotSameFs,     // E_XDEV
// InvalidParam,  // E_INVAL
// NoDeviceSpace, // E_NOSPC, but is defined and not used in the original ucore, which uses E_NO_MEM
// DirRemoved,    // E_NOENT, when the current dir was remove by a previous unlink
// DirNotEmpty,   // E_NOTEMPTY
// WrongFs,       // E_INVAL, when we find the content on disk is wrong when opening the device
// DeviceError,
// IOCTLError,
// NoDevice,
// Again,       // E_AGAIN, when no data is available, never happens in fs
// SymLoop,     // E_LOOP
// Busy,        // E_BUSY
// Interrupted, // E_INTR
pub fn fserror_to_kerror(err: FsError) -> Errno {
    match err {
        FsError::Again => Errno::EAGAIN,
        FsError::Busy => Errno::EBUSY,
        FsError::DeviceError => Errno::EACCES,
        FsError::DirNotEmpty => Errno::EINVAL,
        FsError::EntryExist => Errno::EEXIST,
        FsError::EntryNotFound => Errno::ENOENT,
        FsError::NotFile => Errno::EISDIR,
        FsError::IsDir => Errno::EISDIR,
        FsError::NoDeviceSpace => Errno::ENOSPC,
        FsError::Interrupted => Errno::EINTR,
        FsError::NotSameFs => Errno::EXDEV,
        _ => Errno::EINVAL,
    }
}

/// A simple wrapepr for conversion between unix error code and intermediate error status.
#[macro_export]
macro_rules! make_unix_error_code {
    ($e:expr) => {
        0x80u8 + $e as u8
    };
}
