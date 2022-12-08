//! All the interfaces of page table creation, allocation, and deallocation.
//! Useful resources: https://wiki.osdev.org/Page_Frame_Allocation
//!
//! You may also need to check the IA32 developer manual to now how X86_64 CPUs manage their page tables.

use log::info;
use uefi::{
    prelude::BootServices,
    table::boot::{AllocateType, MemoryDescriptor, MemoryType},
};
use x86_64::{
    registers::{
        control::{Cr0, Cr0Flags, Cr3, Cr3Flags},
        model_specific::{Efer, EferFlags},
    },
    structures::paging::{
        FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame,
        Size4KiB,
    },
    PhysAddr, VirtAddr,
};
use xmas_elf::program::{self, ProgramHeader};

use crate::utils::Kernel;

pub const PAGE_MASK: u64 = 0xFFFFFFFFFFFFF000;

/// Provides access to the page tables of the bootloader and kernel address space.
/// We create a unified page table for both the bootloader and the kernel.
pub struct PageTables {
    /// Provides access to the page tables of the bootloader address space.
    pub bootloader: OffsetPageTable<'static>,
    /// Provides access to the page tables of the kernel address space (not active).
    pub kernel: OffsetPageTable<'static>,
    /// The physical frame where the level 4 page table of the kernel address space is stored.
    ///
    /// Must be the page table that the `kernel` field of this struct refers to.
    ///
    /// This frame is loaded into the `CR3` register on the final context switch to the kernel.  
    pub kernel_level_4_frame: PhysFrame,
}

/// A physical frame allocator based on a BIOS or UEFI provided memory map.
pub struct OsFrameAllocator<'a, M>
where
    M: ExactSizeIterator<Item = &'a MemoryDescriptor> + Clone,
{
    original: M,
    memory_map: M,
    current_descriptor: Option<&'a MemoryDescriptor>,
    next_frame: PhysFrame,
}

impl<'a, M> OsFrameAllocator<'a, M>
where
    M: ExactSizeIterator<Item = &'a MemoryDescriptor> + Clone,
{
    /// Creates a new frame allocator based on the given legacy memory regions.
    ///
    /// Skips the frame at physical address zero to avoid potential problems. For example
    /// identity-mapping the frame at address zero is not valid in Rust, because Rust's `core`
    /// library assumes that references can never point to virtual address `0`.  
    pub fn new(memory_map: M) -> Self {
        // skip frame 0 because the rust core library does not see 0 as a valid address
        let start_frame = PhysFrame::containing_address(PhysAddr::new(0x1000));
        Self::new_starting_at(start_frame, memory_map)
    }

    /// Construct the allocator at the given frame.
    pub fn new_starting_at(frame: PhysFrame, memory_map: M) -> Self {
        Self {
            original: memory_map.clone(),
            memory_map,
            current_descriptor: None,
            next_frame: frame,
        }
    }

    fn allocate(&mut self, d: &'a MemoryDescriptor) -> Option<PhysFrame<Size4KiB>> {
        let start_addr = PhysAddr::new(d.phys_start);
        let start_frame = PhysFrame::containing_address(start_addr);
        let end_addr = start_addr + d.page_count * 0x1000;
        let end_frame = PhysFrame::containing_address(end_addr - 1u64);

        // increase self.next_frame to start_frame if smaller
        if self.next_frame < start_frame {
            self.next_frame = start_frame;
        }

        if self.next_frame < end_frame {
            let ret = self.next_frame;
            self.next_frame += 1;
            Some(ret)
        } else {
            None
        }
    }
}

unsafe impl<'a, M> FrameAllocator<Size4KiB> for OsFrameAllocator<'a, M>
where
    M: ExactSizeIterator<Item = &'a MemoryDescriptor> + Clone,
{
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        // If the current memory is usable.
        if let Some(d) = self.current_descriptor {
            match self.allocate(d) {
                Some(frame) => return Some(frame),
                None => {
                    // Invalidate.
                    self.current_descriptor = None;
                }
            }
        }

        // Not found. Search next.
        while let Some(d) = self.memory_map.next() {
            // OK.
            if d.ty == MemoryType::CONVENTIONAL {
                if let Some(f) = self.allocate(d) {
                    self.current_descriptor = Some(d);
                    return Some(f);
                }
            }
        }

        None
    }
}

/// Gets the starting address of the top-level page table from the cr3 register.
pub fn locate_page_table<'a>() -> &'a PageTable {
    // Get the start address of the top-level page table.
    let frame = Cr3::read().0;
    // Convert this into an OffsetPageTable (the virtual memory will be added with an offset).
    // UEFI identity-maps all memory, so the offset between physical and virtual addresses is 0
    let ptr: *const PageTable = (VirtAddr::new(0) + frame.start_address().as_u64()).as_ptr();
    unsafe { &*ptr }
}

/// Creates the page tables for the kernel.
pub fn create_page_tables(frame_allocator: &mut impl FrameAllocator<Size4KiB>) -> PageTables {
    // UEFI identity-maps all memory, so the offset between physical and virtual addresses is 0
    let phys_offset = VirtAddr::new(0);

    // copy the currently active level 4 page table, because it might be read-only
    info!("Switching to new level 4 table");
    let bootloader_page_table = {
        let old_table = locate_page_table();
        let new_frame = frame_allocator
            .allocate_frame()
            .expect("Failed to allocate frame for new level 4 table");
        let new_table: &mut PageTable = {
            let ptr: *mut PageTable =
                (phys_offset + new_frame.start_address().as_u64()).as_mut_ptr();
            // create a new, empty page table
            unsafe {
                ptr.write(PageTable::new());
                &mut *ptr
            }
        };

        // copy the first entry (we don't need to access more than 512 GiB; also, some UEFI
        // implementations seem to create an level 4 table entry 0 in all slots)
        new_table[0] = old_table[0].clone();
        // the first level 4 table entry is now identical, so we can just load the new one
        unsafe {
            Cr3::write(new_frame, Cr3Flags::empty());
            OffsetPageTable::new(&mut *new_table, phys_offset)
        }
    };

    // create a new page table hierarchy for the kernel
    let (kernel_page_table, kernel_level_4_frame) = {
        // get an unused frame for new level 4 page table
        let frame: PhysFrame = frame_allocator.allocate_frame().expect("no unused frames");
        log::info!("New page table at: {:#?}", &frame);
        // get the corresponding virtual address
        let addr = phys_offset + frame.start_address().as_u64();
        // initialize a new page table
        let ptr = addr.as_mut_ptr();
        unsafe { *ptr = PageTable::new() };
        let level_4_table = unsafe { &mut *ptr };
        (
            unsafe { OffsetPageTable::new(level_4_table, phys_offset) },
            frame,
        )
    };

    PageTables {
        bootloader: bootloader_page_table,
        kernel: kernel_page_table,
        kernel_level_4_frame,
    }
}

/// Turns off the permission check because we are root.
pub fn disable_protection() {
    unsafe {
        Cr0::update(|flag| flag.remove(Cr0Flags::WRITE_PROTECT));
        Efer::update(|flag| flag.insert(EferFlags::NO_EXECUTE_ENABLE));
    }
}

/// Restore the persission check.
pub fn enable_protection() {
    unsafe {
        Cr0::update(|flag| flag.insert(Cr0Flags::WRITE_PROTECT));
    }
}
