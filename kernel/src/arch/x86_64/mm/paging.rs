//! This module implements x86_64 page table algorithms and some utility functions.

use core::mem::ManuallyDrop;

use boot_header::{Header, MemoryDescriptor, MemoryType};

use log::{debug, error, info};
use x86_64::{
    registers::control::{Cr2, Cr3, Cr3Flags},
    structures::paging::{
        mapper::PageTableFrameMapping, FrameAllocator, FrameDeallocator, MappedPageTable, Mapper,
        Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
    },
    PhysAddr, VirtAddr,
};

use crate::{
    arch::PHYSICAL_MEMORY_START,
    error::KResult,
    memory::{allocate_frame, deallocate_frame, phys_to_virt, BitMapAlloc, LOCKED_FRAME_ALLOCATOR},
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
}

pub trait PageTableBehaviors: Sized {
    /// Creates an empty page table and remap itself.
    fn new() -> Self {
        let mut pt = Self::empty();
        pt.remap_kernel();
        pt
    }
    /// Empty.
    fn empty() -> Self;
    /// Remaps the kernel memory space.
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
    fn get_page_slice_mut<'a>(&mut self, addr: VirtAddr) -> &'a mut [u8];

    /// When copied user data (in page fault handler)，maybe need to flush I/D cache.
    fn flush_cache_copy_user(&mut self, start: VirtAddr, end: VirtAddr, execute: bool);
}

/// Implements `PageTableFrameMapping`.
pub struct PageTableMapper;

unsafe impl PageTableFrameMapping for PageTableMapper {
    fn frame_to_pointer(&self, frame: PhysFrame) -> *mut PageTable {
        frame_to_page_table(frame) as *mut PageTable
    }
}

/// A wrapper struct that contains the reference to the kernel page table and its frame.
pub struct KernelPageTable {
    /// The page table itself.
    pub page_table: MappedPageTable<'static, PageTableMapper>,
    pub page_table_frame: PhysFrame,
}

impl KernelPageTable {
    /// Get the active page table for the kernel.
    pub fn active() -> ManuallyDrop<Self> {
        let page_table_addr = Cr3::read_raw().0.start_address().as_u64();

        unsafe { Self::new(page_table_addr) }
    }

    /// Load from some address.
    ///
    /// # Safety
    /// This function is unsafe because the page table address `addr` must be valid.
    pub unsafe fn new(addr: u64) -> ManuallyDrop<Self> {
        let page_table_frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(addr));
        let page_table = frame_to_page_table(page_table_frame);

        ManuallyDrop::new(Self {
            page_table: MappedPageTable::new(page_table, PageTableMapper {}),
            page_table_frame,
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

        let mut index = 0usize;
        for entry in self.page_table.level_4_table().iter() {
            if entry.flags().contains(PageTableFlags::PRESENT) {
                debug!(
                    "Entry #{:0>4x} | Address: {:0>16x}, flags: {:<?}",
                    index,
                    entry.addr().as_u64(),
                    entry.flags()
                );
            }

            index += 1;
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
    fn empty() -> Self {
        let phys_addr = allocate_frame().expect("empty(): failed to allocate frame");
        let page_table_frame = PhysFrame::<Size4KiB>::containing_address(phys_addr);
        let table = frame_to_page_table(page_table_frame);

        // Clear it.
        table.zero();
        unsafe {
            Self {
                page_table: MappedPageTable::new(table, PageTableMapper {}),
                page_table_frame,
            }
        }
    }

    fn remap_kernel(&mut self) {
        todo!();
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

    fn flush_cache_copy_user(&mut self, _: VirtAddr, _: VirtAddr, _: bool) {}

    fn get_entry(&mut self, addr: VirtAddr) -> KResult<&mut dyn EntryBehaviors> {
        todo!()
    }

    fn get_page_slice_mut<'a>(&mut self, addr: VirtAddr) -> &'a mut [u8] {
        todo!()
    }
}

pub fn frame_to_page_table(frame: PhysFrame) -> &'static mut PageTable {
    let addr = phys_to_virt(frame.start_address().as_u64());

    unsafe { &mut *(addr as *mut PageTable) }
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

        if descriptor.ty == MemoryType::CONVENTIONAL {
            let start_frame = descriptor.phys_start as usize / 0x1000;
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
