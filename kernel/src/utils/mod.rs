//! Some utility functions and data structures that the kernel can take use of.

use alloc::{string::String, sync::Arc, vec::Vec};
use rcore_fs::vfs::{INode, Timespec};

use crate::{
    error::{Errno, KResult},
    fs::InodeOpType,
    time::{SystemTime, UNIX_EPOCH},
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
    if dir_path.is_empty() {
        dir_path = "/";
    }

    Ok((dir_path, file_name))
}

/// Updates the time of the inode.
pub fn update_inode_time(inode: &Arc<dyn INode>, ty: InodeOpType) {
    if let Ok(mut metadata) = inode.metadata() {
        if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
            if ty.contains(InodeOpType::ACCESS) {
                metadata.atime = Timespec {
                    sec: now.as_secs() as _,
                    nsec: now.as_nanos() as _,
                };
            }
            if ty.contains(InodeOpType::MODIFY) {
                metadata.mtime = Timespec {
                    sec: now.as_secs() as _,
                    nsec: now.as_nanos() as _,
                };
            }
            if ty.contains(InodeOpType::CREATE) {
                metadata.ctime = Timespec {
                    sec: now.as_secs() as _,
                    nsec: now.as_nanos() as _,
                };
            }
        }
    }
}

pub fn realpath(pathname: &str) -> String {
    // Process '.' and '..' in advance: '.' can be ignored and '..' means to pop up the directory stack.
    // E.g.: ./proc/foo/bar/../bar/./curdir => proc/foo/bar/curdir
    let dir_items = pathname.split('/').collect::<Vec<&str>>();
    let mut sanized_dir_items = Vec::new();

    // We visit the vector reversely and remove '.' and pop up the previous directory if we visit non-leading '..'
    // What about some patterns like "./.."?
    let mut idx = 0usize;
    while idx < dir_items.len() {
        let dir = dir_items[idx];

        match dir {
            "." => (),
            ".." => {
                if sanized_dir_items.is_empty() {
                    sanized_dir_items.push(String::from(".."));
                } else {
                    if sanized_dir_items.last().unwrap() != ".." {
                        // Removes the last item.
                        sanized_dir_items.pop();
                    } else {
                        sanized_dir_items.push(String::from(".."));
                    }
                }
            }
            _ => {
                sanized_dir_items.push(String::from(dir));
            }
        }
        idx += 1;
    }

    match sanized_dir_items.is_empty() {
        true => ".".into(),
        false => sanized_dir_items.join("/"),
    }
}
