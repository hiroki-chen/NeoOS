//! This module implements *highl-level* paging mechanism that is platform-agnostic.
//!
//! The idea is to divide both the virtual and physical memory space into small, fixed-size blocks.
//! The blocks of the virtual memory space are called pages, and the blocks of the physical address
//! space are called frames. Each page can be individually mapped to a frame, which makes it possible
//! to split larger memory regions across non-continuous physical frames.

mod callback;

use alloc::{boxed::Box, vec::Vec};
use bitflags::bitflags;
use core::ops::Range;
use log::debug;
use x86_64::{
    structures::paging::{Page, Size4KiB},
    VirtAddr,
};

use crate::{
    arch::mm::paging::PageTableBehaviors,
    error::{Errno, KResult},
};

use callback::ArenaCallback;

bitflags! {
    pub struct ArenaFlags: u8 {
        const USER_ACCESSIBLE= 0b00000001;
        const WRITABLE = 0b00000010;
        const NON_EXECUTABLE = 0b00000100;
        const MMIO = 0b00001000;
    }
}

/// A continuous memory region.
#[derive(Clone, Debug)]
pub struct Arena {
    /// The virtual memory region managed by this arena.
    range: Range<u64>,
    /// Memory flags.
    flags: ArenaFlags,
    /// The memory write / read callback.
    callback: Box<dyn ArenaCallback>,
}

impl Arena {
    /// Returns true if a given address is within this area.
    pub fn contains_addr(&self, addr: u64) -> bool {
        self.range.contains(&addr)
    }

    /// Checks whether a read request is valid, i.e., the given address + size should
    /// not exceed `self.range`.
    ///
    /// Returns non-zero value to indicate how many bytes can be read.
    /// Returns `Errno::ENOMEM` to indicate memory is not sufficient for page-allocation.
    pub fn check_read<T>(&self, ptr: *const T, size: usize) -> KResult<usize> {
        let arena_start = self.range.start;
        let arena_end = self.range.end;

        // Get page start and end regions.
        let min = (ptr as u64).max(
            Page::<Size4KiB>::containing_address(VirtAddr::new(arena_start))
                .start_address()
                .as_u64(),
        );
        let max = ((ptr as u64) + size as u64).min(
            Page::<Size4KiB>::containing_address(VirtAddr::new(arena_end + 0x1000 - 1))
                .start_address()
                .as_u64(),
        );

        if max >= min {
            Ok((max - min) as usize)
        } else {
            Err(Errno::ENOMEM)
        }
    }

    /// Checks whether a write request is valid, i.e., the given address + size should
    /// not exceed `self.range`.
    ///
    /// Returns non-zero value to indicate how many bytes are written.
    /// Returns `Errno::EINVAL` to indicate an invalid operation.
    /// Returns `Errno::EPERM` to indicate a non-writable memory address.
    pub fn check_write<T>(&self, ptr: *mut T, size: usize) -> KResult<usize> {
        if !self.flags.contains(ArenaFlags::WRITABLE) {
            debug!(
                "checked_write(): error writing {:#x} with size {:#x}",
                ptr as u64, size
            );
            Err(Errno::EPERM)
        } else {
            self.check_read(ptr, size)
        }
    }
}

/// The memory manager as `struct_mm` in Linux kernel source code.
/// This is only used to manage the memory of *high-level* processes.
pub struct MemoryManager<P>
where
    P: PageTableBehaviors,
{
    arena: Vec<Arena>,
    page_table: P,
}

impl<P> MemoryManager<P>
where
    P: PageTableBehaviors,
{
    pub fn new(empty_page_table: bool) -> Self {
        Self {
            arena: Vec::new(),
            page_table: if empty_page_table {
                P::empty()
            } else {
                P::new()
            },
        }
    }
}
