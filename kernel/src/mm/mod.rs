//! This module implements *highl-level* paging mechanism that is platform-agnostic.
//!
//! The idea is to divide both the virtual and physical memory space into small, fixed-size blocks.
//! The blocks of the virtual memory space are called pages, and the blocks of the physical address
//! space are called frames. Each page can be individually mapped to a frame, which makes it possible
//! to split larger memory regions across non-continuous physical frames.

pub mod callback;

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use bitflags::bitflags;
use core::{future::Future, ops::Range, pin::Pin};
use x86_64::{
    structures::paging::{Page, Size4KiB},
    VirtAddr,
};

use crate::{
    arch::{
        cpu::cpu_id,
        mm::paging::{set_page_table, EntryBehaviors, PageTableBehaviors, PageTableMoreBehaviors},
        PAGE_SIZE,
    },
    error::{Errno, KResult},
    memory::{is_page_aligned, page_frame_number, page_mask},
    process::thread::{Thread, CURRENT_THREAD_PER_CPU},
    sync::mutex::SpinLockNoInterrupt as Mutex,
    sys::Prot,
    utils::ptr::Ptr,
};

use callback::ArenaCallback;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ArenaFlags {
    pub writable: bool,
    pub user_accessible: bool,
    pub non_executable: bool,
    pub mmio: u8,
}

impl From<Prot> for ArenaFlags {
    fn from(value: Prot) -> Self {
        Self {
            writable: value.contains(Prot::PROT_WRITE),
            user_accessible: value.contains(Prot::PROT_READ),
            non_executable: !value.contains(Prot::PROT_EXEC),
            mmio: 0,
        }
    }
}

/// A wrapper struct for a future that requires a specific page table (CR3 value) to run. This enables page table switching
/// between the kernel and the user space.
///
/// This struct contains the future itself, a `Mutex` to allow for synchronization, the CR3 value of
/// the required page table, and an `Arc` reference to the thread that will run the future.
pub struct FutureWithPageTable {
    future: Mutex<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
    cr3: u64,
    thread: Arc<Thread>,
}

impl FutureWithPageTable {
    pub fn new(
        future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
        cr3: u64,
        thread: Arc<Thread>,
    ) -> Self {
        Self {
            future: Mutex::new(future),
            cr3,
            thread,
        }
    }
}

impl Future for FutureWithPageTable {
    type Output = ();

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        let old = unsafe { CURRENT_THREAD_PER_CPU[cpu_id()].replace(self.thread.clone()) };

        set_page_table(self.cr3);
        let poll_res = self.future.lock().as_mut().poll(cx);

        if let Some(old) = old {
            drop(old);
        }

        poll_res
    }
}

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
    pub struct MmapPerm: u64 {
        const NONE = 0b0001;
        const READ = 0b0010;
        const WRITE = 0b0100;
        const EXECUTE = 0b01000;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct AccessType: u64 {
        const EXECUTE = 0b0001;
        const WRITE = 0b0010;
        const USER = 0b0100;
    }
}

impl From<MmapPerm> for ArenaFlags {
    fn from(val: MmapPerm) -> ArenaFlags {
        let mut arena_flags = ArenaFlags::default();

        if val.contains(MmapPerm::EXECUTE) {
            arena_flags.non_executable = false;
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
    /// The memory write / read callback. This backend implements all the page table interfaces.
    pub callback: Box<dyn ArenaCallback>,
}

impl Arena {
    /// Returns true if a given address is within this area.
    pub fn contains_addr(&self, addr: u64) -> bool {
        self.range.contains(&addr)
    }

    /// Maps itself into `page_table`.
    pub fn map(&self, page_table: &mut dyn PageTableBehaviors) -> KResult<()> {
        // Useless check.
        // if !is_page_aligned(self.range.start) {
        //     kwarn!("arena start point is not aligned to 4 KB.");
        // }
        // if !is_page_aligned(self.range.end.checked_sub(self.range.start).unwrap_or(1)) {
        //     kwarn!("arena size is not 4KB aligned.");
        // }

        for page in
            Page::<Size4KiB>::range_inclusive(page!(self.range.start), page!(self.range.end - 1))
        {
            // Invoke callback and let it do something for us.
            self.callback
                .map(page_table, page.start_address(), &self.flags);
        }

        Ok(())
    }

    /// Unmaps itself.
    pub fn unmap(&self, page_table: &mut dyn PageTableBehaviors) -> KResult<()> {
        if !is_page_aligned(self.range.start) {
            kerror!("map(): arena not aligned to 4 KB.");
            return Err(Errno::EINVAL);
        }
        if !is_page_aligned(self.range.end.checked_sub(self.range.start).unwrap_or(1)) {
            kerror!("map(): corrupted arena size");
            return Err(Errno::EINVAL);
        }

        for mem in self.range.clone().step_by(PAGE_SIZE) {
            let page = page!(mem);
            // Invoke callback and let it do something for us.
            self.callback.unmap(page_table, page.start_address());
        }

        Ok(())
    }

    /// Returns true if this arena overlaps with [start, end].
    pub fn overlap_with(&self, range: &Range<u64>) -> bool {
        let self_start = page!(self.range.start).start_address().as_u64();
        let self_end = page!(self.range.end).start_address().as_u64();
        let other_start = page!(range.start).start_address().as_u64();
        let other_end = page!(range.end).start_address().as_u64();

        !(self_end <= other_start || self_start >= other_end)
    }

    /// Checks whether a read request is valid, i.e., the given address + size should
    /// not exceed `self.range`.
    ///
    /// - Returns non-zero value to indicate how many bytes can be read.
    /// - Returns `Errno::ENOMEM` to indicate memory is not sufficient for page-allocation.
    pub fn check_read<T>(&self, ptr: *const T, size: usize) -> KResult<usize>
    where
        T: Sized + 'static,
    {
        let arena_start = self.range.start;
        let arena_end = self.range.end;

        // Get page start and end regions.
        let min = (ptr as u64).max(page!(arena_start).start_address().as_u64());
        let max = ((ptr as u64) + size as u64).min(
            page!(arena_end + PAGE_SIZE as u64 - 1)
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
    pub fn check_write<T>(&self, ptr: *mut T, size: usize) -> KResult<usize>
    where
        T: Sized + 'static,
    {
        if !self.flags.writable {
            kdebug!(
                "checked_write(): error writing {:#x} with size {:#x}",
                ptr as u64,
                size
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

    /// Removes the memory region from the process manager (used to, e.g., map another address), if the address is valid;
    /// otherwise, we return [`Errno::EINVAL`]. This function returns the old arena on succcess.
    pub fn remove_addr(&self, addr: u64, len: usize) -> KResult<Arena> {
        todo!()
    }

    /// Checks whether a read request is valid, i.e., the given address + size should
    /// not exceed `self.range`. If the pointer is valid, we convert it into a slice.
    pub fn check_read_array<T>(&self, ptr: &Ptr<T>, size: usize) -> KResult<&'static [T]>
    where
        T: Sized + 'static,
    {
        let mut valid_size = 0;
        let ptr = ptr.as_ptr();

        for arena in self.arena.iter() {
            valid_size += arena.check_read(ptr, size).unwrap_or(0);

            if valid_size == core::mem::size_of::<T>() * size {
                return unsafe { Ok(core::slice::from_raw_parts(ptr, size)) };
            }
        }

        Err(Errno::EINVAL)
    }

    /// Checks whether a read request is valid, i.e., the given address + size should
    /// not exceed `self.range`. If the pointer is valid, we convert it into a slice.
    pub fn check_write_array<T>(&self, ptr: &Ptr<T>, size: usize) -> KResult<&'static mut [T]>
    where
        T: Sized + 'static,
    {
        let mut valid_size = 0;
        let ptr = ptr.as_mut_ptr();

        for arena in self.arena.iter() {
            valid_size += arena.check_write(ptr, size).unwrap_or(0);

            if valid_size == core::mem::size_of::<T>() * size {
                return unsafe { Ok(core::slice::from_raw_parts_mut(ptr, size)) };
            }
        }

        Err(Errno::EINVAL)
    }

    /// Executes function `f` with `page_table`.
    pub unsafe fn with(&self, f: impl FnOnce()) {
        self.page_table.with(f)
    }

    pub fn do_handle_page_fault(&mut self, addr: u64, access_type: AccessType) -> bool {
        match self.arena.iter().find(|arena| arena.contains_addr(addr)) {
            Some(arena) => {
                // Dispatch.
                arena
                    .callback
                    .do_handle_page_fault(&mut self.page_table, addr, access_type)
            }
            None => {
                kerror!("cannot find arena for this address @ {:#x}.", addr);
                false
            }
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
                kerror!("cannot find arena for this address @ {:#x}.", addr);
                false
            }
        }
    }

    pub fn clear(&mut self) {
        for arena in self.arena.iter_mut() {
            kdebug!("clear(): dropping arena {:?}", arena.range);
            arena.unmap(&mut self.page_table).unwrap();
        }

        self.arena.clear();
    }

    pub fn clone(&mut self) -> Self {
        let mut new_page_table = P::new();
        let MemoryManager {
            ref mut page_table,
            ref arena,
            ..
        } = self;

        for item in self.arena.iter() {
            let page_start = page!(item.range.start);
            let page_end = page!(item.range.end);

            for page in Page::range_inclusive(page_start, page_end) {
                item.callback.clone_and_map(
                    &mut new_page_table,
                    page_table,
                    page.start_address(),
                    &item.flags,
                )
            }
        }

        Self {
            arena: self.arena.clone(),
            page_table: new_page_table,
        }
    }

    /// Returns true if the [addr, addr + size) is not occupied.
    pub fn is_free(&self, addr: u64, size: usize) -> bool {
        self.arena
            .iter()
            .any(|item| item.overlap_with(&(addr..addr + size as u64)))
    }

    /// Finds a free arena that can be used for a given size.
    pub fn find_free_arena(&self, addr_hint: u64, size: usize) -> KResult<VirtAddr> {
        core::iter::once(addr_hint)
            .chain(self.arena.iter().map(|item| item.range.clone().end))
            .map(|addr| page_mask(addr + PAGE_SIZE as u64 - 1))
            .find(|addr| self.is_free(*addr, size))
            .ok_or(Errno::ENOMEM)
            .map(|addr| virt!(addr))
    }

    /// Returns true if `self.arena` has some memory regions overlapping with `other`.
    pub fn check_overlap(&self, other: &Arena) -> bool {
        self.arena
            .iter()
            .any(|item| item.overlap_with(&other.range))
    }

    /// Extends this memory space.
    pub fn add(&mut self, other: Arena) {
        kdebug!("add(): adding {:#x?} to vm...", other);

        let start_addr = page_frame_number(other.range.start);
        let end_addr = page_frame_number(other.range.end + PAGE_SIZE as u64);

        // Performs sanity check: we must ensure that `other` is valid.
        // Also note that the range is exclusive on the right side.
        if start_addr > end_addr {
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

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Arena> {
        self.arena.iter_mut()
    }

    /// Validates the page table.
    pub unsafe fn validate(&self) {
        self.page_table.validate();
    }
}

pub fn check_permission(access_type: &AccessType, entry: &dyn EntryBehaviors) -> bool {
    (!access_type.contains(AccessType::WRITE) || entry.writable())
        && (!access_type.contains(AccessType::EXECUTE) || entry.execute())
        && (!access_type.contains(AccessType::USER) || entry.user())
}
