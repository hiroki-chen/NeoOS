use core::result::Result;

use rcore_fs::vfs::FsError;

/// Unix standard error codes.
///
/// The `perror` tool can be used to find the error message which is associated with a given error code.
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
pub enum Errno {
    EPERM = 1,
    ENOENT,
    ESRCH,
    EINTR,
    EIO,
    ENXIO,
    E2BIG,
    ENOEXEC,
    EBADF,
    ECHILD,
    EAGAIN,
    ENOMEM,
    EACCES,
    EFAULT,
    ENOTBLK,
    EBUSY,
    EEXIST,
    EXDEV,
    ENODEV,
    ENOTDIR,
    EISDIR,
    EINVAL,
    ENFILE,
    EMFILE,
    ENOTTY,
    ETXTBSY,
    EFBIG,
    ENOSPC,
    ESPIPE,
    EROFS,
    EMLINK,
    EPIPE,
    EDOM,
    ERANGE,
    EWOULDBLOCK,
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
