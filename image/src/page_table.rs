//! All the interfaces of page table creation, allocation, and deallocation.
//! Useful resources: https://wiki.osdev.org/Page_Frame_Allocation
//!
//! You may also need to check the IA32 developer manual to now how X86_64 CPUs manage their page tables.

use log::info;
use uefi::{
    prelude::BootServices,
    table::boot::{AllocateType, MemoryType},
};
use x86_64::{
    registers::{
        control::{Cr0, Cr0Flags, Cr3},
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

/// Manages the physical page allocation for pre-kernel phase.
pub struct PreKernelAllocator<'a> {
    bs: &'a BootServices,
}

unsafe impl<'a> FrameAllocator<Size4KiB> for PreKernelAllocator<'a> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let addr = self
            .bs
            .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
            .expect("failed to allocate frame");
        let frame = PhysFrame::containing_address(PhysAddr::new(addr));
        Some(frame)
    }
}

impl<'a> PreKernelAllocator<'a> {
    /// Returns a new UEFIFrameAllocator.
    pub fn new(bs: &'a BootServices) -> Self {
        Self { bs }
    }

    /// Allocates virtual memory for each segment, at the address specified by the p_vaddr member
    /// in the program header. The size of the segment in memory is specified by the `p_memsize`.
    fn map_elf_segment(
        &mut self,
        page_table: &mut impl Mapper<Size4KiB>,
        program_segment: &ProgramHeader,
        elf_entry: PhysAddr,
    ) {
        // Skip non-loadable
        if program_segment.get_type().unwrap() == program::Type::Load {
            info!("Mapping segment for {:?}", program_segment);

            let seg_flags = program_segment.flags();
            let mem_size = program_segment.mem_size();
            let file_size = program_segment.file_size();
            // Not 4KiB aligned. So we need a conversion.
            let offset = program_segment.offset() & PAGE_MASK;
            let virt_addr = VirtAddr::new(program_segment.virtual_addr());
            // We need to offset the physical memory by adding the elf base.
            let phys_addr = elf_entry + offset;
            // Copy the segment data from the file offset specified by the p_offset member to the
            // virtual memory address specified by the p_vaddr member. The size of the segment in
            // the file is contained in the p_filesz member. This can be zero.
            // 1. Locate the starting points of virtual & physical addresses.
            let page_start = Page::<Size4KiB>::containing_address(virt_addr);
            let frame_start = PhysFrame::<Size4KiB>::containing_address(phys_addr);
            // The size this segment needs.
            let frame_end = PhysFrame::<Size4KiB>::containing_address(phys_addr + file_size - 1u64);
            // 2. Allocate.
            for frame in PhysFrame::range_inclusive(frame_start, frame_end) {
                info!("start: {:?}, end: {:?}", frame_start, frame_end);

                let offset = frame - frame_start;
                let page = page_start + offset;
                let mut page_table_flags = PageTableFlags::PRESENT;
                if !seg_flags.is_execute() {
                    page_table_flags |= PageTableFlags::NO_EXECUTE
                };
                if seg_flags.is_write() {
                    page_table_flags |= PageTableFlags::WRITABLE
                };

                unsafe {
                    page_table
                        .map_to(page, frame, page_table_flags, self)
                        .expect("Page mapping failed")
                        .flush();
                }
            }

            // If the p_filesz and p_memsz members differ, this indicates that the segment is padded with zeros.
            // All bytes in memory between the ending offset of the file size, and the segment's virtual memory
            // size are to be cleared with zeros.
        }
    }

    /// Maps the kernel into the virtual address.
    /// This is equivalent to loading the ELF binary.
    pub fn map_kernel(&mut self, kernel: &Kernel) {
        info!("Kernel entry loaded at {:#p}", kernel.elf.input);
        // Get the top-level page table.
        let mut page_table = get();
        let elf_entry = PhysAddr::new(kernel.elf.input.as_ptr() as u64);
        // Check the alignment. Must be 4KiB aligned.
        if !elf_entry.is_aligned(0x1000u64) {
            panic!("The ELF file is not 4KiB aligned!");
        }

        // Read the ELF executable's program headers.
        // These specify where in the file the program segments are located,
        // and where they need to be loaded into memory.
        for segment in kernel.elf.program_iter() {
            // In case the segment is corrupted, we abort loading.
            if let Err(e) = program::sanity_check(segment, &kernel.elf) {
                panic!("Sanity check failed. Error: {}", e);
            }

            self.map_elf_segment(&mut page_table, &segment, elf_entry);
        }
    }
}

/// Gets the starting address of the top-level page table from the cr3 register.
pub fn get() -> OffsetPageTable<'static> {
    info!("Getting the top-level page table...");
    // Get the start address of the top-level page table.
    let page_table_addr = Cr3::read().0.start_address().as_u64();
    // Convert this into an OffsetPageTable (the virtual memory will be added with an offset).
    // UEFI identity-maps all memory, so the offset between physical and virtual addresses is 0
    unsafe {
        let page_table = unsafe {&mut *(page_table_addr as *mut PageTable) };
        OffsetPageTable::new(page_table, VirtAddr::new(0))
    }
}

/// Creates the page tables for the kernel.
pub fn create_page_tables(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> (OffsetPageTable, PhysFrame) {
    let offset = VirtAddr::new(0);
    // create a new page table hierarchy for the kernel.
    // get an unused frame for new level 4 page table.
    let frame: PhysFrame = frame_allocator.allocate_frame().expect("no unused frames");
    info!("New page table at: {frame:#?}");
    // get the corresponding virtual address
    let addr = offset + frame.start_address().as_u64();
    // initialize a new page table
    let ptr: *mut PageTable = addr.as_u64() as *mut PageTable;
    unsafe { ptr.write(PageTable::new()) };
    let level_4_table = unsafe { &mut *ptr };
    (
        unsafe { OffsetPageTable::new(level_4_table, offset) },
        frame,
    )
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
