//! All the interfaces of page table creation, allocation, and deallocation.
//! Useful resources: https://wiki.osdev.org/Page_Frame_Allocation
//!
//! You may also need to check the IA32 developer manual to now how X86_64 CPUs manage their page tables.

use core::arch::asm;
use log::info;
use uefi::table::boot::{MemoryDescriptor, MemoryType};
use x86_64::{
    registers::{
        control::{Cr0, Cr0Flags, Cr3, Cr3Flags, Cr4, Cr4Flags},
        model_specific::{Efer, EferFlags},
    },
    structures::paging::{
        FrameAllocator, Mapper, OffsetPageTable, Page, PageSize, PageTable, PageTableFlags,
        PhysFrame, Size4KiB,
    },
    PhysAddr, VirtAddr,
};
use xmas_elf::program::{self, ProgramHeader};

use crate::utils::Kernel;

pub const PAGE_MASK: u64 = 0xFFFFFFFFFFFFF000;
pub const PAGE_SIZE: u64 = 0x1000;

pub trait MaxPhysicalAddress<S>
where
    S: PageSize,
{
    /// Returns the largest detected physical memory address.
    ///
    /// Useful for creating a mapping for all physical memory.
    fn max_phys_addr(&self) -> u64;
}

/// Provides access to the page tables of the bootloader and kernel address space.
/// We create a unified page table for both the bootloader and the kernel.
pub struct PageTables {
    /// Provides access to the page tables of the bootloader address space.
    #[allow(unused)]
    pub bootloader: OffsetPageTable<'static>,
    /// Provides access to the page tables of the kernel address space (not active).
    ///
    /// This page table is just a bootstrap tool that enables the kernel to access
    /// some addresses *before* it is able to setup its own page tables.
    pub kernel: OffsetPageTable<'static>,
    /// The physical frame where the level 4 page table of the kernel address space is stored.
    ///
    /// Must be the page table that the `kernel` field of this struct refers to.
    ///
    /// This frame is loaded into the `CR3` register on the final context switch to the kernel.  
    pub kernel_level_4_frame: PhysFrame,
}

/// A physical frame allocator based on a BIOS or UEFI provided memory map.
pub struct OsFrameAllocator<M>
where
    M: ExactSizeIterator<Item = &'static MemoryDescriptor> + Clone,
{
    #[allow(unused)]
    original: M,
    memory_map: M,
    current_descriptor: Option<&'static MemoryDescriptor>,
    next_frame: PhysFrame,
}

impl<M> OsFrameAllocator<M>
where
    M: ExactSizeIterator<Item = &'static MemoryDescriptor> + Clone,
{
    /// Creates a new frame allocator based on the given legacy memory regions.
    ///
    /// Skips the frame at physical address zero to avoid potential problems. For example
    /// identity-mapping the frame at address zero is not valid in Rust, because Rust's `core`
    /// library assumes that references can never point to virtual address `0`.  
    pub fn new(memory_map: M) -> Self {
        // skip frame 0 because the rust core library does not see 0 as a valid address
        let start_frame = PhysFrame::containing_address(PhysAddr::new(PAGE_SIZE));
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

    fn allocate(&mut self, d: &MemoryDescriptor) -> Option<PhysFrame<Size4KiB>> {
        let start_addr = PhysAddr::new(d.phys_start);
        let start_frame = PhysFrame::containing_address(start_addr);
        let end_addr = start_addr + d.page_count * PAGE_SIZE;
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

    pub fn refactor_mmap_storage(&self, mmap_ptr: *mut u8, entry_size: usize) {
        // Refactor mmap.
        for (index, descriptor) in self.memory_map.clone().enumerate() {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    descriptor as *const MemoryDescriptor as *const u8,
                    mmap_ptr.add(index * entry_size),
                    entry_size,
                );
            }
        }
    }
}

impl<M, S> MaxPhysicalAddress<S> for OsFrameAllocator<M>
where
    M: ExactSizeIterator<Item = &'static MemoryDescriptor> + Clone,
    S: PageSize,
{
    fn max_phys_addr(&self) -> u64 {
        self.memory_map
            .clone()
            .map(|d| d.phys_start + d.page_count * S::SIZE)
            .max()
            .unwrap()
            .max(0x0001_0000_0000)
    }
}

unsafe impl<M> FrameAllocator<Size4KiB> for OsFrameAllocator<M>
where
    M: ExactSizeIterator<Item = &'static MemoryDescriptor> + Clone,
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
            if d.ty == MemoryType::CONVENTIONAL || d.ty == MemoryType::PERSISTENT_MEMORY {
                if let Some(f) = self.allocate(d) {
                    self.current_descriptor = Some(d);
                    return Some(f);
                }
            }
        }

        None
    }
}

pub fn enable_nxe_efer() {
    unsafe {
        Efer::update(|efer| efer.insert(EferFlags::NO_EXECUTE_ENABLE));
    }
}

pub fn enable_write_protect() {
    unsafe {
        Cr0::update(|f| f.insert(Cr0Flags::WRITE_PROTECT));
    }
}

#[allow(unused)]
pub fn enable_global() {
    unsafe {
        Cr4::update(|f| f.insert(Cr4Flags::PAGE_GLOBAL));
    }
}

/// Gets the starting address of the top-level page table from the cr3 register.
pub fn locate_page_table() -> &'static PageTable {
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
    info!("create_page_tables(): Switching to new level 4 table");
    let bootloader_page_table = {
        let old_table = locate_page_table();
        let new_frame = frame_allocator
            .allocate_frame()
            .expect("create_page_tables(): Failed to allocate frame for new level 4 table");
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
        log::info!("create_page_tables(): New page table at: {:#?}", &frame);
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
#[allow(unused)]
pub fn disable_protection() {
    unsafe {
        Cr0::update(|flag| flag.remove(Cr0Flags::WRITE_PROTECT));
        Efer::update(|flag| flag.insert(EferFlags::NO_EXECUTE_ENABLE));
    }
}

/// Restore the persission check.
#[allow(unused)]
pub fn enable_protection() {
    unsafe {
        Cr0::update(|flag| flag.insert(Cr0Flags::WRITE_PROTECT));
    }
}

/// The real implementation of the mapping function.
///
/// This function maps `size` memory bytes started at `virt_addr` into `phys_addr`, if it is not
/// `None`, i.e., the memory is allocated; otherwise, it explicitly allocates a physical frame on
/// the fly.
pub fn map_addr(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    page_table: &mut OffsetPageTable<'static>,
    virt_addr: u64,
    phys_addr: Option<u64>,
    size: usize,
    flags: PageTableFlags,
) {
    let page_num = (size - 1) as u64 / PAGE_SIZE + 1;
    let page_start = Page::<Size4KiB>::containing_address(VirtAddr::new(virt_addr));
    let page_end = page_start + page_num;

    // Calculates the current memory index.

    for (cur, page) in Page::range_inclusive(page_start, page_end).enumerate() {
        let frame = match phys_addr {
            Some(addr) => PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(
                addr + cur as u64 * PAGE_SIZE,
            )),
            None => frame_allocator.allocate_frame().unwrap(),
        };

        unsafe {
            page_table
                .map_to(page, frame, flags, frame_allocator)
                .unwrap()
                .flush();
        }
    }
}

/// Map the rest free physical addresses.
/// Note that this is just a linear mapping: 0xffff_8880_0000_0000 + physical_address.
pub fn map_physical(
    kernel: &Kernel,
    frame_allocator: &mut (impl FrameAllocator<Size4KiB> + MaxPhysicalAddress<Size4KiB>),
    page_tables: &mut PageTables,
) {
    let phys_start = kernel.config.physical_mem;
    let max_addr = frame_allocator.max_phys_addr();
    let start_frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0));
    let end_frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(max_addr));

    for frame in PhysFrame::range_inclusive(start_frame, end_frame) {
        let virt_addr = VirtAddr::new(frame.start_address().as_u64() + phys_start);
        let page = Page::<Size4KiB>::containing_address(virt_addr);
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::GLOBAL;

        unsafe {
            page_tables
                .kernel
                .map_to(page, frame, flags, frame_allocator)
                .unwrap()
                .flush();
        }
    }
}

/// Construct the stack mapping.
pub fn map_stack(
    kernel: &Kernel,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    page_tables: &mut PageTables,
) {
    // This is done by locating the top of the physical address and allocating
    // this page for us.
    let stack_addr = kernel.config.kernel_stack_address;
    let stack_size = kernel.config.kernel_stack_size;
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::GLOBAL;

    map_addr(
        frame_allocator,
        &mut page_tables.kernel,
        stack_addr,
        None,
        (stack_size * PAGE_SIZE) as usize,
        flags,
    );
}

/// Loads the kernel ELF executable into memory and switches to it.
/// Returns the entry point of the kernel in virtual address.
pub fn map_kernel(
    kernel: &Kernel,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    page_tables: &mut PageTables,
) {
    // Physical address where kernel is loaded.
    let kernel_start = PhysAddr::new(kernel.start_address as u64);

    for segment in kernel.elf.program_iter() {
        if program::sanity_check(segment, &kernel.elf).is_err() {
            panic!();
        }

        map_segment(&segment, frame_allocator, page_tables, kernel_start);
    }
}

/// Identity maps the gdt physical address into virtual address. Otherwise,
/// the kernel cannot access it.
pub fn map_gdt(
    _kernel: &Kernel,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    page_tables: &mut PageTables,
) {
    let gdt = x86_64::instructions::tables::sgdt();
    let addr = gdt.base;
    let size = (gdt.limit + 1) as usize / core::mem::size_of::<u64>();
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    map_addr(
        frame_allocator,
        &mut page_tables.kernel,
        addr.as_u64(),
        Some(addr.as_u64()),
        size,
        flags,
    )
}

/// Identity-maps context switch function, so that we don't get an immediate page fault.
pub fn map_context_switch(
    _kernel: &Kernel,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    page_tables: &mut PageTables,
) {
    let context_switch_function = PhysAddr::new(context_switch as *const () as u64);
    let context_switch_function_start_frame: PhysFrame =
        PhysFrame::containing_address(context_switch_function);
    for frame in PhysFrame::range_inclusive(
        context_switch_function_start_frame,
        context_switch_function_start_frame + 1,
    ) {
        unsafe {
            page_tables
                .kernel
                .identity_map(frame, PageTableFlags::PRESENT, frame_allocator)
                .unwrap()
                .flush();
        }
    }
}

/// Maps each program header into the memory and sets up the page table mapping.
fn map_segment(
    segment: &ProgramHeader,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    page_tables: &mut PageTables,
    kernel_start: PhysAddr,
) {
    if segment.get_type().unwrap() == program::Type::Load {
        let mem_size = segment.mem_size();
        let file_size = segment.file_size();
        let file_offset = segment.offset() & PAGE_MASK;
        let phys_start_addr = kernel_start + file_offset;
        let virt_start_addr = VirtAddr::new(segment.virtual_addr());

        let start_page = Page::<Size4KiB>::containing_address(virt_start_addr);
        let start_frame = PhysFrame::<Size4KiB>::containing_address(phys_start_addr);
        let end_frame =
            PhysFrame::<Size4KiB>::containing_address(phys_start_addr + file_size - 1u64);

        let flags = segment.flags();
        let mut page_table_flags = PageTableFlags::PRESENT;
        if !flags.is_execute() {
            page_table_flags |= PageTableFlags::NO_EXECUTE
        };
        if flags.is_write() {
            page_table_flags |= PageTableFlags::WRITABLE
        };

        for frame in PhysFrame::range_inclusive(start_frame, end_frame) {
            let offset = frame - start_frame;
            let page = start_page + offset;
            unsafe {
                page_tables
                    .kernel
                    .map_to(page, frame, page_table_flags, frame_allocator)
                    .unwrap()
                    .flush();
            }
        }

        // Handle mem_size > file_size: zero padded.
        // This section is .bss section.
        if mem_size > file_size {
            handle_bss_section(
                frame_allocator,
                page_tables,
                end_frame,
                mem_size,
                file_size,
                virt_start_addr,
                page_table_flags,
            );
        }
    }
}

/// Pad zeros to the memory region if the file size is not sufficient enough to fill the memory.
fn handle_bss_section(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    page_tables: &mut PageTables,
    end_frame: PhysFrame,
    mem_size: u64,
    file_size: u64,
    virt_start_addr: VirtAddr,
    flags: PageTableFlags,
) {
    // A type alias that helps in efficiently clearing a page
    type PageArray = [u64; Size4KiB::SIZE as usize / 8];

    let zero_start = virt_start_addr + file_size;
    let zero_end = virt_start_addr + mem_size;

    // In some cases, `zero_start` might not be page-aligned. This requires some
    // special treatment because we can't safely zero a frame of the original file.
    if zero_start.as_u64() & PAGE_MASK != 0 {
        // A part of the last mapped frame needs to be zeroed.
        let new_frame = frame_allocator.allocate_frame().unwrap();
        let last_page = Page::<Size4KiB>::containing_address(virt_start_addr + file_size - 1u64);
        let last_page_ptr = end_frame.start_address().as_u64() as *mut PageArray;
        let temp_page_ptr = new_frame.start_address().as_u64() as *mut PageArray;

        unsafe {
            temp_page_ptr.write(last_page_ptr.read());
        }

        // remap last page.
        unsafe {
            let _ = page_tables.kernel.unmap(last_page);
            page_tables
                .kernel
                .map_to(last_page, new_frame, flags, frame_allocator)
                .unwrap()
                .flush();
        }

        // Map additional frames.
        let start_page: Page = Page::containing_address(VirtAddr::new(x86_64::align_up(
            zero_start.as_u64(),
            Size4KiB::SIZE,
        )));
        let end_page = Page::containing_address(zero_end);
        for page in Page::range_inclusive(start_page, end_page) {
            let frame = frame_allocator.allocate_frame().unwrap();
            unsafe {
                page_tables
                    .kernel
                    .map_to(page, frame, flags, frame_allocator)
                    .unwrap()
                    .flush();
                page_tables
                    .bootloader
                    .map_to(page, frame, flags, frame_allocator)
                    .unwrap()
                    .flush();
            }
        }

        unsafe {
            core::ptr::write_bytes(
                zero_start.as_mut_ptr() as *mut u8,
                0u8,
                (mem_size - file_size) as usize,
            );
        }
    }
}

/// Performs a jump into the entry of the kernel so that bootloader no long works.
pub unsafe fn context_switch(
    page_tables: &PageTables,
    entry: u64,
    header_address: u64,
    stack_top: u64,
) -> ! {
    asm!("mov cr3, {}; mov rsp, {}; push 0x0; call {}",
        in(reg) page_tables.kernel_level_4_frame.start_address().as_u64(),
        in(reg) stack_top,
        in(reg) entry,
        in("rdi") header_address);
    loop {
        asm!("nop");
    }
}
