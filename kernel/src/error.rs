use core::result::Result;

#[derive(Copy, Clone, Debug)]
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

/// The return value that indicates a successful execution (`Ok`) or failure (`Err`).
///
/// In Rust, it is idiomatic to model functions that may fail as returning
/// a [`Result`]. Since in the kernel many functions return an error code,
/// [`Result`] is a type alias for a [`core::result::Result`] that uses
/// [`Error`] as its error type.
pub type KResult<T> = Result<T, Errno>;

pub fn error_to_int<T>(result: &KResult<T>) -> i32 {
    match result.as_ref() {
        Ok(_) => 0i32,
        Err(errno) => -(*errno as i32),
    }
}
