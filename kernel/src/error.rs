use core::result::Result;

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
        Err(errno) => -(*errno as i32),
    }
}
