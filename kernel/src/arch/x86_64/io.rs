//! This module implements IO related operations. Especially print.

use core::{
    ffi::{c_size_t, c_void},
    fmt::Arguments,
};

use alloc::{string::ToString, sync::Arc, vec::Vec};

use crate::{drivers::SERIAL_DRIVERS, error::KResult, process::thread::Thread};

pub fn writefmt(arg: Arguments) {
    // Default to serial port.
    // RwLock<Vec<Arc<dyn SerialDriver>>>
    // To ensure printing can proceed, we need to prevent timer interrupt so that the lock can be properly
    // dropped; otherwise, if we do something in the handler that requries the logger, read/write causes
    // deadlock, and it never ends.

    // Wait for 10000000 at most; if we cannot acquire the lock, then it means a possible deadlock.
    // We can force unlock the rwlock then (still unsafe).
    const MAX_ATTEPMT_COUNT: usize = 10000000;

    // Try to acquire the lock; if timeout, force unlock.
    let mut attepmt = 0usize;
    loop {
        match SERIAL_DRIVERS.try_write() {
            Some(lock) => {
                lock // remember to make it write.
                    .first()
                    .unwrap()
                    .write(arg.to_string().as_bytes());
                break;
            }
            None => {
                attepmt += 1;
                if attepmt == MAX_ATTEPMT_COUNT {
                    // force unlock.
                    unsafe {
                        SERIAL_DRIVERS.force_write_unlock();
                        SERIAL_DRIVERS
                            .write()
                            .first()
                            .unwrap()
                            .write(arg.to_string().as_bytes());
                    }

                    break;
                }
            }
        }
    }
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
    ) -> KResult<Vec<Vec<u8>>> {
        let vm = thread.vm.lock();
        let io_vectors = unsafe { core::slice::from_raw_parts(iov_ptr, iov_count) };

        let mut v = Vec::with_capacity(io_vectors.len());
        for iov in io_vectors.iter() {
            if iov.iov_len != 0 {
                vm.get_slice::<u8>(iov.iov_base as _, iov.iov_len)?;
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

    /// Writes all the buffers into the io vectors pointed by `iov_ptr`.
    pub fn write_all_iovecs(
        thread: &Arc<Thread>,
        iov_ptr: *const Self,
        iov_count: usize,
        buf: &[u8],
    ) -> KResult<usize> {
        let io_vectors = unsafe { core::slice::from_raw_parts(iov_ptr, iov_count) };

        // Denote the position of buf.
        let mut cur = 0usize;
        for iov in io_vectors.iter() {
            let byte_write = (buf.len() - cur + 1).min(iov.iov_len);
            (0..byte_write).for_each(|i| unsafe {
                core::ptr::write(iov.iov_base.add(i) as *mut u8, buf[cur + i]);
            });
            cur += byte_write;
        }

        Ok(cur)
    }
}
