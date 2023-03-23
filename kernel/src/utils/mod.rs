//! Some utility functions and data structures that the kernel can take use of.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    error::{Errno, KResult},
    memory::copy_from_user,
};

pub mod ptr;

/// Calculate the fletcher 64's checksum for a given byte array.
pub fn calc_fletcher64(src: &[u8]) -> KResult<u64> {
    let initial_value = 0u64;

    if src.len() % 4 != 0 {
        return Err(Errno::EINVAL);
    }
    let mut lower_32bit = initial_value & 0xffffffff;
    let mut upper_32bit = (initial_value >> 32) & 0xffffffff;

    for buffer_offset in (0..src.len()).step_by(4) {
        let value_32bit = ((src[buffer_offset + 0] as u64) << 0)
            | ((src[buffer_offset + 1] as u64) << 8)
            | ((src[buffer_offset + 2] as u64) << 16)
            | ((src[buffer_offset + 3] as u64) << 24);

        lower_32bit += value_32bit;
        upper_32bit += lower_32bit;
    }
    lower_32bit %= 0xffffffff;
    upper_32bit %= 0xffffffff;

    let value_32bit = 0xffffffff - ((lower_32bit + upper_32bit) % 0xffffffff);
    upper_32bit = 0xffffffff - ((lower_32bit + value_32bit) % 0xffffffff);

    Ok((upper_32bit << 32) | value_32bit)
}

/// Reads a string from the user space in a byte array form.
pub fn read_user_string(ptr: *const u8) -> KResult<String> {
    if ptr.is_null() {
        Ok("".to_string())
    } else {
        let mut s = Vec::new();
        for i in 0.. {
            let byte = unsafe { copy_from_user(ptr.add(i)) }?;
            if byte == 0 {
                break;
            }
            s.push(byte);
        }

        String::from_utf8(s).map_err(|_| Errno::EFAULT)
    }
}

/// Get the path and filename from a fully qualified path.
///
/// We need to deal with some special cases:
/// - foo -> ./foo
/// - /bar -> force '/'.
/// - bar/ -> remove '/'.
pub fn split_path(path: &str) -> KResult<(&str, &str)> {
    // First remove trailing '/'. Then split into two parts.
    let mut idx = path.trim_end_matches('/').rsplitn(2, '/');
    let file_name = idx.next().unwrap();
    let mut dir_path = idx.next().unwrap_or(".");
    if dir_path == "" {
        dir_path = "/";
    }

    Ok((dir_path, file_name))
}
