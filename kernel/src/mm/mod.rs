//! This module implements *highl-level* paging mechanism that is platform-agnostic.
//!
//! The idea is to divide both the virtual and physical memory space into small, fixed-size blocks.
//! The blocks of the virtual memory space are called pages, and the blocks of the physical address
//! space are called frames. Each page can be individually mapped to a frame, which makes it possible
//! to split larger memory regions across non-continuous physical frames.

pub mod callback;

use alloc::{boxed::Box, vec::Vec};
use bitflags::bitflags;
use core::ops::Range;
use log::debug;
use x86_64::{
    structures::paging::{Page, Size4KiB},
    VirtAddr,
};

use crate::{
    arch::{
        mm::paging::{PageTableBehaviors, PageTableMoreBehaviors},
        PAGE_SIZE,
    },
    error::{Errno, KResult},
};

use callback::ArenaCallback;

bitflags! {
  pub struct MmapFlags: u16 {
      /// Changes are shared.
      const SHARED = 1 << 0;
      /// Changes are private.
      const PRIVATE = 1 << 1;
      /// Place the mapping at the exact address
      const FIXED = 1 << 4;
      /// The mapping is not backed by any file. (non-POSIX)
      const ANONYMOUS = 1 << 5;
  }
}

bitflags! {
    pub struct ArenaFlags: u8 {
        const USER_ACCESSIBLE= 0b00000001;
        const WRITABLE = 0b00000010;
        const NON_EXECUTABLE = 0b00000100;
        const MMIO = 0b00001000;
    }
}

bitflags! {
    pub struct MmapPerm: u64 {
        const NONE = 0x0001;
        const READ = 0x0010;
        const WRITE = 0x0100;
        const EXECUTE= 0x01000;
    }
}

impl Into<ArenaFlags> for MmapPerm {
    fn into(self) -> ArenaFlags {
        let mut arena_flags = ArenaFlags::empty();

        if self.contains(MmapPerm::EXECUTE) {
            arena_flags.set(ArenaFlags::NON_EXECUTABLE, false);
        }

        arena_flags
    }
}

/// A continuous memory region.
#[derive(Clone, Debug)]
pub struct Arena {
    /// The virtual memory region managed by this arena.
    pub range: Range<u64>,
    /// Memory flags.
    pub flags: ArenaFlags,
    /// The memory write / read callback.
    pub callback: Box<dyn ArenaCallback>,
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
            Page::<Size4KiB>::containing_address(VirtAddr::new(arena_end + PAGE_SIZE as u64 - 1))
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
    P: PageTableBehaviors + PageTableMoreBehaviors,
{
    arena: Vec<Arena>,
    page_table: P,
}

impl<P> MemoryManager<P>
where
    P: PageTableBehaviors + PageTableMoreBehaviors,
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

    /// Extends this memory space.
    pub fn add(&mut self, other: Arena) {
        todo!();
        // self.arena.push(other);
    }
}
