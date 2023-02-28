//! This module implements x86_64 page table algorithms and some utility functions.

use core::mem::ManuallyDrop;

use boot_header::{Header, MemoryDescriptor, MemoryType};

use log::{debug, error, info, trace, warn};
use x86_64::{
    instructions::tlb::flush,
    registers::control::{Cr2, Cr3, Cr3Flags},
    structures::paging::{
        mapper::PageTableFrameMapping, page_table::PageTableEntry, FrameAllocator,
        FrameDeallocator, MappedPageTable, Mapper, Page, PageTable, PageTableFlags, PhysFrame,
        Size4KiB,
    },
    PhysAddr, VirtAddr,
};

use crate::{
    arch::{KERNEL_PM4, PAGE_SIZE, PHYSICAL_MEMORY_PM4, PHYSICAL_MEMORY_START},
    error::{Errno, KResult},
    memory::{allocate_frame, deallocate_frame, phys_to_virt, BitMapAlloc, LOCKED_FRAME_ALLOCATOR},
    process::thread::current,
};

struct PTFrameAllocator;

unsafe impl FrameAllocator<Size4KiB> for PTFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        match allocate_frame() {
            Ok(f) => Some(PhysFrame::containing_address(f)),
            Err(errno) => {
                error!(
                    "allocate_frame(): failed to allocate frame! Errno: {:?}",
                    errno
                );
                None
            }
        }
    }
}

impl FrameDeallocator<Size4KiB> for PTFrameAllocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        if let Err(errno) = deallocate_frame(frame.start_address().as_u64()) {
            error!(
                "deallocate_frame(): failed to deallocate the frame {:#x?}! Errno: {:?}",
                frame, errno
            );
            panic!();
        }
    }
}

/// Handles the page fault by the current thread.
pub fn handle_page_fault(addr: u64) -> bool {
    let thread = current().expect("handle_page_fault(): no thread is running?");

    trace!(
        "handle_page_fault(): page fault @ {:#x} handled by {:#x}",
        addr,
        thread.id
    );

    let mut vm = thread.vm.lock();
    vm.handle_page_fault(addr)
}

pub trait EntryBehaviors {
    /// Make all changes take effect.
    ///
    /// IMPORTANT!
    /// This must be called after any change to ensure it become effective.
    /// Usually it will cause a TLB/MMU flush.
    fn update(&mut self);
    /// A bit set by hardware when the page is accessed
    fn accessed(&self) -> bool;
    /// A bit set by hardware when the page is written
    fn dirty(&self) -> bool;
    /// Will PageFault when try to write page where writable=0
    fn writable(&self) -> bool;
    /// Will PageFault when try to access page where present=0
    fn present(&self) -> bool;

    fn clear_accessed(&mut self);
    fn clear_dirty(&mut self);
    fn set_writable(&mut self, value: bool);
    fn set_present(&mut self, value: bool);

    /// The target physics address in the entry
    /// Can be used for other purpose if present=0
    fn target(&self) -> PhysAddr;
    fn set_target(&mut self, target: PhysAddr);

    // For Copy-on-write
    fn writable_shared(&self) -> bool;
    fn readonly_shared(&self) -> bool;
    fn set_shared(&mut self, writable: bool);
    fn clear_shared(&mut self);

    // For Swap
    fn swapped(&self) -> bool;
    fn set_swapped(&mut self, value: bool);

    fn user(&self) -> bool;
    fn set_user(&mut self, value: bool);
    fn execute(&self) -> bool;
    fn set_execute(&mut self, value: bool);
    fn mmio(&self) -> u8;
    fn set_mmio(&mut self, value: u8);

    fn flags(&self) -> PageTableFlags;
}

pub trait PageTableBehaviors {
    /// Remaps the kernel memory space. This ensures that the user-space applications can access
    /// kernel-space memory regions.
    fn remap_kernel(&mut self);
    /// Map a page of virual address `addr` to the frame of physics address `target`
    /// Return the page table entry of the mapped virual address
    fn map(&mut self, addr: VirtAddr, target: PhysAddr) -> &mut dyn EntryBehaviors;

    /// Unmap a page of virual address `addr`
    fn unmap(&mut self, addr: VirtAddr);

    /// Get the page table entry of a page of virual address `addr`
    /// If its page do not exist, return `None`
    fn get_entry(&mut self, addr: VirtAddr) -> KResult<&mut dyn EntryBehaviors>;

    /// Get a mutable reference of the content of a page of virtual address `addr`
    fn get_page_slice_mut<'a>(&mut self, addr: VirtAddr) -> KResult<&'a mut [u8]>;

    /// Validates this page table by overwriting CR3.
    ///
    /// # Safety
    /// This function is unsafe because we must ensure that the page table is valid; otherwise,
    /// the page fault handler will capture PF but it does not know how to deal with it.
    unsafe fn validate(&self);

    /// Gets the starting virtual address of this page table.
    fn cr3(&self) -> u64;
}

pub trait PageTableMoreBehaviors: Sized + PageTableBehaviors {
    /// Creates an empty page table and remap itself.
    fn new() -> Self {
        let mut pt = Self::empty();
        pt.remap_kernel();
        pt
    }

    /// Empty.
    fn empty() -> Self;

    /// Execute function `f` with this page table activated
    unsafe fn with<T>(&self, f: impl FnOnce() -> T) -> T {
        let cur = get_page_table() as *const _ as u64;
        let new = self.cr3();

        debug!("with(): switch from {:#x} to {:#x}", cur, new);
        if cur != new {
            set_page_table(new);
        }

        let ans = f();

        debug!("with(): switch back.");
        if cur != new {
            set_page_table(cur);
        }
        ans
    }
}

/// Implements `PageTableFrameMapping`.
pub struct PageTableMapper;

unsafe impl PageTableFrameMapping for PageTableMapper {
    fn frame_to_pointer(&self, frame: PhysFrame) -> *mut PageTable {
        frame_to_page_table(frame)
    }
}

/// A wrapper for page table entry that contains its page and physical frame.
/// Built atop x86_64 page entry.
pub struct PageEntryWrapper(&'static mut PageTableEntry, Page, PhysFrame);

impl EntryBehaviors for PageEntryWrapper {
    fn update(&mut self) {
        let addr = self.1.start_address();
        flush(addr);
    }

    fn accessed(&self) -> bool {
        self.0.flags().contains(PageTableFlags::ACCESSED)
    }

    fn dirty(&self) -> bool {
        self.0.flags().contains(PageTableFlags::DIRTY)
    }

    fn user(&self) -> bool {
        self.0.flags().contains(PageTableFlags::USER_ACCESSIBLE)
    }

    fn present(&self) -> bool {
        self.0.flags().contains(PageTableFlags::PRESENT)
    }

    fn writable(&self) -> bool {
        self.0.flags().contains(PageTableFlags::WRITABLE)
    }

    fn execute(&self) -> bool {
        !self.0.flags().contains(PageTableFlags::NO_EXECUTE)
    }

    fn swapped(&self) -> bool {
        self.0.flags().contains(PageTableFlags::BIT_11)
    }

    fn writable_shared(&self) -> bool {
        self.0.flags().contains(PageTableFlags::BIT_10)
    }

    fn readonly_shared(&self) -> bool {
        self.0.flags().contains(PageTableFlags::BIT_9)
    }

    fn mmio(&self) -> u8 {
        0
    }

    fn target(&self) -> PhysAddr {
        self.0.addr()
    }

    fn set_execute(&mut self, value: bool) {
        self.0.flags().set(PageTableFlags::NO_EXECUTE, value)
    }

    fn set_mmio(&mut self, value: u8) {
        error!("Do no set MMIO for entries!");
    }

    fn set_present(&mut self, value: bool) {
        self.0.flags().set(PageTableFlags::PRESENT, value)
    }

    fn set_user(&mut self, value: bool) {
        self.0.flags().set(PageTableFlags::USER_ACCESSIBLE, value)
    }
    fn set_writable(&mut self, value: bool) {
        self.0.flags().set(PageTableFlags::WRITABLE, value)
    }

    fn set_shared(&mut self, writable: bool) {
        self.0.flags().set(PageTableFlags::BIT_10, writable);
        self.0.flags().set(PageTableFlags::BIT_9, !writable);
    }

    fn set_swapped(&mut self, value: bool) {
        self.0.flags().set(PageTableFlags::BIT_11, value);
    }

    fn clear_accessed(&mut self) {
        self.0.flags().remove(PageTableFlags::ACCESSED);
    }

    fn clear_dirty(&mut self) {
        self.0.flags().remove(PageTableFlags::DIRTY);
    }

    fn clear_shared(&mut self) {
        self.0
            .flags()
            .remove(PageTableFlags::BIT_9 | PageTableFlags::BIT_10);
    }

    fn set_target(&mut self, target: PhysAddr) {
        let flags = self.0.flags();
        self.0.set_addr(target, flags);
    }

    fn flags(&self) -> PageTableFlags {
        self.0.flags()
    }
}

/// A wrapper struct that contains the reference to the kernel page table and its frame.
pub struct KernelPageTable {
    /// The page table itself.
    pub page_table: MappedPageTable<'static, PageTableMapper>,
    pub page_table_frame: PhysFrame,
    /// The last accessed page table entry.
    pub page_table_entry: Option<PageEntryWrapper>,
}

impl KernelPageTable {
    /// Get the active page table for the kernel.
    pub fn active() -> ManuallyDrop<Self> {
        let page_table_addr = Cr3::read().0;

        unsafe { Self::new(page_table_addr) }
    }

    /// Load from some address.
    ///
    /// # Safety
    /// This function is unsafe because the page table address `addr` must be valid.
    pub unsafe fn new(page_table_frame: PhysFrame) -> ManuallyDrop<Self> {
        let page_table = unsafe { &mut *frame_to_page_table(page_table_frame) };

        ManuallyDrop::new(Self {
            page_table: MappedPageTable::new(page_table, PageTableMapper {}),
            page_table_frame,
            page_table_entry: None,
        })
    }

    /// Dumps the kernel page table.
    ///
    /// We cannot implement `Debug` or `Display` trait for this struct because they require
    /// immutable reference to `self` but `level_4_table()` requires mutable ones.
    ///
    /// This print function requires the compilatio time environment variable `LOG_LEVEL` to be
    /// set to `DEBUG` or `TRACE`.
    pub fn print(&mut self) {
        debug!("================= Kernel Page Table =================");
        for (index, entry) in self.page_table.level_4_table().iter().enumerate() {
            if entry.flags().contains(PageTableFlags::PRESENT) {
                debug!(
                    "Entry #{:0>4x} | Address: {:0>16x}, flags: {:<?}",
                    index,
                    entry.addr().as_u64(),
                    entry.flags()
                );
            }
        }

        debug!("================= Kernel Page Table =================");
    }
}

impl Drop for KernelPageTable {
    /// If you want to invalidate this page table, call this function `manually`.
    fn drop(&mut self) {
        info!(
            "drop(): dropping page table at {:#x?}",
            self.page_table_frame
        );
        deallocate_frame(self.page_table_frame.start_address().as_u64()).unwrap();
    }
}

impl PageTableBehaviors for KernelPageTable {
    fn remap_kernel(&mut self) {
        let page_table = get_page_table();

        let kernel_space = page_table[KERNEL_PM4 as usize].clone();
        let physical_space = page_table[PHYSICAL_MEMORY_PM4 as usize].clone();
        let new_table = unsafe { &mut *frame_to_page_table(self.page_table_frame) };
        new_table[KERNEL_PM4 as usize].set_addr(
            kernel_space.addr(),
            kernel_space.flags() | PageTableFlags::GLOBAL,
        );
        new_table[PHYSICAL_MEMORY_PM4 as usize].set_addr(
            physical_space.addr(),
            physical_space.flags() | PageTableFlags::GLOBAL,
        );
    }

    fn map(&mut self, addr: VirtAddr, target: PhysAddr) -> &mut dyn EntryBehaviors {
        let flags = PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE | PageTableFlags::PRESENT;
        unsafe {
            self.page_table
                .map_to(
                    Page::<Size4KiB>::containing_address(addr),
                    PhysFrame::<Size4KiB>::containing_address(target),
                    flags,
                    &mut PTFrameAllocator,
                )
                .unwrap()
                .flush();
        }

        match self.get_entry(addr) {
            Ok(e) => e,
            Err(errno) => panic!("map(): failed to get mapped entry. Errno: {:?}", errno),
        }
    }

    fn unmap(&mut self, addr: VirtAddr) {
        self.page_table
            .unmap(Page::<Size4KiB>::containing_address(addr))
            .unwrap()
            .1
            .flush();
    }

    // FIXME: Buggy. This function always returns empty entry.
    fn get_entry(&mut self, addr: VirtAddr) -> KResult<&mut dyn EntryBehaviors> {
        debug!(
            "get_entry(): getting entry for {:#x} with current page table located at {:#x}",
            addr.as_u64(),
            self.page_table_frame.start_address().as_u64()
        );

        let page_table = frame_to_page_table(self.page_table_frame);
        for page_table_level in 0..4 {
            // Get the index for level at `page_table_level`.
            let index = index_at_level(page_table_level, addr.as_u64());
            let entry = unsafe { &mut (&mut *page_table)[index as usize] };

            // If this is not page table entry (PTE), continue walking.
            if page_table_level == 3 {
                let page = Page::<Size4KiB>::containing_address(addr);
                self.page_table_entry = Some(PageEntryWrapper(entry, page, self.page_table_frame));
                return Ok(self.page_table_entry.as_mut().unwrap());
            }

            if !entry.flags().contains(PageTableFlags::PRESENT) {
                return Err(Errno::EEXIST);
            }
        }

        Err(Errno::EEXIST)
    }

    fn get_page_slice_mut<'a>(&mut self, addr: VirtAddr) -> KResult<&'a mut [u8]> {
        if let Ok(frame) = self
            .page_table
            .translate_page(Page::<Size4KiB>::containing_address(addr))
        {
            let virt_addr = phys_to_virt(frame.start_address().as_u64());
            let slice = unsafe { core::slice::from_raw_parts_mut(virt_addr as *mut u8, PAGE_SIZE) };

            Ok(slice)
        } else {
            error!("get_page_slice_mut(): invalid operation at {:#x}", addr);
            Err(Errno::EINVAL)
        }
    }

    unsafe fn validate(&self) {
        // Performs page table switching!
        let old_page_table = Cr3::read().0.start_address().as_u64();
        let new_page_table = self.page_table_frame.start_address().as_u64();

        if old_page_table == new_page_table {
            warn!(
                "validate(): duplicate page table found: {:#x}",
                new_page_table
            );
            return;
        }

        debug!(
            "validate(): page table from {:#x} to {:#x}",
            old_page_table, new_page_table
        );
        set_page_table(new_page_table);
    }

    fn cr3(&self) -> u64 {
        self.page_table_frame.start_address().as_u64()
    }
}

impl PageTableMoreBehaviors for KernelPageTable {
    fn empty() -> Self {
        let phys_addr = allocate_frame().expect("empty(): failed to allocate frame");
        let page_table_frame = PhysFrame::<Size4KiB>::containing_address(phys_addr);
        let table = unsafe { &mut *frame_to_page_table(page_table_frame) };

        // Clear it.
        table.zero();
        unsafe {
            Self {
                page_table: MappedPageTable::new(table, PageTableMapper {}),
                page_table_frame,
                page_table_entry: None,
            }
        }
    }
}

pub fn frame_to_page_table(frame: PhysFrame) -> *mut PageTable {
    let addr = phys_to_virt(frame.start_address().as_u64());

    addr as *mut PageTable
}

/// This function will take the page table constructed by the bootloader and reconstruct
/// mapping from virtual adrdress into physical address. Then, it completely invalidates
/// previous page tables. After this function is exeucted, we can divide the kernel virtual
/// memory space into several segments listed in the module document above.
pub fn init_kernel_page_table() -> KResult<()> {
    let mut page_table = KernelPageTable::active();

    page_table.print();

    Ok(())
}

/// Gets the kernel page table in raw format.
pub fn get_page_table() -> &'static mut PageTable {
    let frame = Cr3::read().0;
    let ptr = frame.start_address().as_u64() as *mut PageTable;
    unsafe { &mut *ptr }
}

/// Inserts all UEFI mapped memory regions into the bitmap-based frame allocator.
/// It is important for the use of the memory management.
pub fn init_mm(header: &'static Header) -> KResult<()> {
    // Initialize the kernel frame allocator for the user space.
    let mut allocator = LOCKED_FRAME_ALLOCATOR.lock();
    // Reinterpret the memory region.
    let mmap = unsafe {
        core::slice::from_raw_parts(
            (header.mmap as *const u8).add(PHYSICAL_MEMORY_START as usize)
                as *const MemoryDescriptor,
            header.mmap_len as usize,
        )
    };

    for descriptor in mmap.iter() {
        log::debug!("init_mm(): {:?}", descriptor);

        if descriptor.ty == MemoryType::CONVENTIONAL
            || descriptor.ty == MemoryType::BOOT_SERVICES_CODE
            || descriptor.ty == MemoryType::BOOT_SERVICES_DATA
        {
            let start_frame = descriptor.phys_start as usize / PAGE_SIZE;
            let end_frame = start_frame + descriptor.page_count as usize;
            allocator.insert(start_frame..end_frame)?;
        }
    }

    Ok(())
}

/// When page faule occurs, the CPU will write the target virtual address into `cr2`.
/// This function is a wrapper for fetching that value.
pub fn get_pf_addr() -> u64 {
    Cr2::read_raw()
}

/// Set the page table by overwriting the `cr3` value.
///
/// # Safety
/// There is no guarantee that we always obtain a valid page table after this function call.
/// It is kernel's responsibility to ensure that `page_table_addr` is always valid. Otherwise,
/// the kernel will crash.
pub fn set_page_table(page_table_addr: u64) {
    unsafe {
        Cr3::write(
            PhysFrame::containing_address(PhysAddr::new(page_table_addr)),
            Cr3Flags::empty(),
        );
    }
}

/// Extract the page entry index for `level`.
#[inline]
pub fn index_at_level(level: usize, addr: u64) -> u64 {
    (addr >> (12 + (3 - level) * 9)) & 0o777
}
