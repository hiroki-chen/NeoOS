//! This module implements IO related operations. Especially print.

use core::{
    ffi::{c_size_t, c_void},
    fmt::Arguments,
};

use alloc::{string::ToString, sync::Arc, vec::Vec};

use crate::{drivers::SERIAL_DRIVERS, error::KResult, process::thread::Thread, utils::ptr::Ptr};

pub fn writefmt(arg: Arguments) {
    // Default to serial port.
    // RwLock<Vec<Arc<dyn SerialDriver>>>
    // To ensure printing can proceed, we need to prevent timer interrupt so that the lock can be properly
    // dropped; otherwise, if we do something in the handler that requries the logger, read/write causes
    // deadlock, and it never ends.

    SERIAL_DRIVERS
        .write() // remember to make it write.
        .first()
        .unwrap()
        .write(arg.to_string().as_bytes());
}

/// IoVec (short for "I/O vector") is a data structure used to describe a block of data to be read or written
/// by an I/O operation. It is similar to the struct iovec used by the writev system call in Unix-like operating
/// systems. One can check the header `sys/iovec.h` for more details.
#[derive(Debug)]
#[repr(C, align(8))]
pub struct IoVec {
    /// pointer to the start of the block of data
    pub iov_base: *const c_void,
    /// size of the block of data in bytes
    pub iov_len: c_size_t,
}

impl IoVec {
    /// Read all the buffers from this IoVec pointer. Note the parameter in the syscall is `struct iovec* iov`.
    /// So IoVec describes a seris of buffers!
    pub fn get_all_iovecs(
        thread: &Arc<Thread>,
        iov_ptr: *const Self,
        iov_count: usize,
        read_or_write: bool,
    ) -> KResult<Vec<Vec<u8>>> {
        let vm = thread.vm.lock();
        let io_vectors = unsafe { core::slice::from_raw_parts(iov_ptr, iov_count) };

        let mut v = Vec::with_capacity(io_vectors.len());
        for iov in io_vectors.iter() {
            if iov.iov_len != 0 {
                let ptr = unsafe { Ptr::new_with_const(iov.iov_base as *const u8) };
                match read_or_write {
                    true => vm.check_read_array(&ptr, iov.iov_len),
                    false => vm.check_read_array(&ptr, iov.iov_len),
                }?;

                unsafe {
                    v.push(
                        core::slice::from_raw_parts(iov.iov_base as *const u8, iov.iov_len)
                            .to_vec(),
                    );
                }
            }
        }

        Ok(v)
    }
}
