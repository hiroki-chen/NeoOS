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
use log::{debug, error};
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
    memory::{is_page_aligned, page_mask},
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
    /// We do not care how it is implemented.
    pub callback: Box<dyn ArenaCallback>,
}

impl Arena {
    /// Returns true if a given address is within this area.
    pub fn contains_addr(&self, addr: u64) -> bool {
        self.range.contains(&addr)
    }

    /// Maps itself into `page_table`.
    pub fn map(&self, page_table: &mut dyn PageTableBehaviors) -> KResult<()> {
        if !is_page_aligned(self.range.start) {
            error!("map(): arena not aligned to 4 KB.");
            return Err(Errno::EINVAL);
        }
        if !is_page_aligned(self.range.end.checked_sub(self.range.start).unwrap_or(1)) {
            error!("map(): corrupted arena size");
            return Err(Errno::EINVAL);
        }

        for mem in self.range.clone().step_by(PAGE_SIZE) {
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(mem));
            // Invoke callback and let it do something for us.
            self.callback
                .map(page_table, page.start_address(), self.flags);
        }

        Ok(())
    }

    /// Unmaps itself.
    pub fn unmap(&self, page_table: &mut dyn PageTableBehaviors) -> KResult<()> {
        if !is_page_aligned(self.range.start) {
            error!("map(): arena not aligned to 4 KB.");
            return Err(Errno::EINVAL);
        }
        if !is_page_aligned(self.range.end.checked_sub(self.range.start).unwrap_or(1)) {
            error!("map(): corrupted arena size");
            return Err(Errno::EINVAL);
        }

        for mem in self.range.clone().step_by(PAGE_SIZE) {
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(mem));
            // Invoke callback and let it do something for us.
            self.callback.unmap(page_table, page.start_address());
        }

        Ok(())
    }

    /// Returns true if this arena overlaps with [start, end].
    pub fn overlap_with(&self, range: &Range<u64>) -> bool {
        let self_start = Page::<Size4KiB>::containing_address(VirtAddr::new(self.range.start))
            .start_address()
            .as_u64();
        let self_end = Page::<Size4KiB>::containing_address(VirtAddr::new(self.range.end))
            .start_address()
            .as_u64();
        let other_start = Page::<Size4KiB>::containing_address(VirtAddr::new(range.start))
            .start_address()
            .as_u64();
        let other_end = Page::<Size4KiB>::containing_address(VirtAddr::new(range.end))
            .start_address()
            .as_u64();

        !(self_end <= other_start || self_start >= other_end)
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
    /// The free chunk list in Linux.
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

    /// Receives the page fault handling request from the kernel.
    pub fn handle_page_fault(&mut self, addr: u64) -> bool {
        // Locate memory region where page fault occurs.
        match self.arena.iter().find(|arena| arena.contains_addr(addr)) {
            Some(arena) => {
                // Dispatch to the handler.
                arena.callback.handle_page_fault(&mut self.page_table, addr)
            }
            None => {
                error!("handle_page_fault(): cannot find arena for this address ?!");
                false
            }
        }
    }

    pub fn clear(&mut self) {
        for arena in self.arena.iter_mut() {
            debug!("clear(): dropping arena {:?}", arena.range);
            arena.unmap(&mut self.page_table).unwrap();
        }

        self.arena.clear();
    }

    /// Returns true if the [addr, addr + size) is not occupied.
    pub fn is_free(&self, addr: u64, size: usize) -> bool {
        self.arena
            .iter()
            .find(|item| item.overlap_with(&(addr..addr + size as u64)))
            .is_none()
    }

    /// Finds a free arena that can be used for a given size.
    pub fn find_free_arena(&self, addr_hint: u64, size: usize) -> KResult<VirtAddr> {
        core::iter::once(addr_hint)
            .chain(self.arena.iter().map(|item| item.range.clone().end))
            .map(|addr| page_mask(addr + PAGE_SIZE as u64 - 1))
            .find(|addr| self.is_free(*addr, size))
            .ok_or(Errno::ENOMEM)
            .map(|raw_addr| VirtAddr::new(raw_addr))
    }

    /// Returns true if `self.arena` has some memory regions overlapping with `other`.
    pub fn check_overlap(&self, other: &Arena) -> bool {
        self.arena
            .iter()
            .find(|item| item.overlap_with(&other.range))
            .is_some()
    }

    /// Extends this memory space.
    pub fn add(&mut self, other: Arena) {
        let start_addr = other.range.start & !(PAGE_SIZE as u64 - 1);
        let end_addr = (other.range.end + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);

        // Performs sanity check: we must ensure that `other` is valid.
        if start_addr >= end_addr {
            panic!(
              "add(): cannot add this arena into the vm because the memory region is invalid. Address: {:#x} >= {:#x}!",
              start_addr,
              end_addr);
        }
        if self.check_overlap(&other) {
            panic!("add(): cannot allocate memory regions that overlap with each other!");
        }

        self.add_ordered(other);
    }

    /// Adds to `self.arena` and sort the vector based on their starting addresses (ascending).
    fn add_ordered(&mut self, other: Arena) {
        other.map(&mut self.page_table).unwrap();

        // Find the correct index and insert.
        let index = match self
            .arena
            .binary_search_by(|item| item.range.clone().cmp(other.range.clone()))
        {
            Ok(index) => index,
            Err(index) => index,
        };

        // Insert into the arena.
        self.arena.insert(index, other);
    }

    /// Returns the page table.
    pub fn page_table(&mut self) -> &mut P {
        &mut self.page_table
    }

    /// Returns the iterator.
    pub fn iter(&self) -> impl Iterator<Item = &Arena> {
        self.arena.iter()
    }

    /// Validates the page table.
    pub unsafe fn validate(&self) {
        self.page_table.validate();
    }
}
