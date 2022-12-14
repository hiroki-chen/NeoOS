//! This module implementes the paging mechanism targeted at x86_64 platform.
//! Note that this is *platform-specific* implementation, and if you want to
//! check the backend-agnostic implementation of the kernel paging mechanism,
//! please refer to `kernel/src/mm/mod.rs`.
//!
//! The x86_64 architecture uses a 4-level page table and a page size of 4 KiB.
//! Each page table, independent of the level, has a fixed size of 512 entries.
//! Each entry has a size of 8 bytes, so each table is 512 * 8 B = 4 KiB large
//! and thus fits exactly into one page.
//!
//! It’s worth noting that the recent “Ice Lake” Intel CPUs optionally support
//! 5-level page tables to extend virtual addresses from 48-bit to 57-bit, but
//! we do not use 5-level page table.

use boot_header::{Header, MemoryDescriptor, MemoryType};
use log::debug;
use x86_64::{
    registers::control::{Cr2, Cr3, Cr3Flags},
    structures::paging::{PageTable, PhysFrame},
    PhysAddr,
};

use crate::{
    error::KResult,
    memory::{BitMapAlloc, LOCKED_FRAME_ALLOCATOR},
};

/// Gets the kernel page table in raw format.
pub fn kerel_page_table() -> &'static PageTable {
    let frame = Cr3::read().0;
    let ptr = frame.start_address().as_u64() as *mut PageTable;
    unsafe { &*ptr }
}

/// Inserts all UEFI mapped memory regions into the bitmap-based frame allocator.
/// It is important for the use of the memory management.
pub fn init_mm(header: &'static Header) -> KResult<()> {
    // Initialize the kernel frame allocator for the user space.
    let mut allocator = LOCKED_FRAME_ALLOCATOR.lock();
    // Reinterpret the memory region.
    let mmap = unsafe {
        core::slice::from_raw_parts(
            header.mmap as *const MemoryDescriptor,
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

/// Pretty-prints the current page error information.
pub fn pretty_interpret(pf_errno: usize) {
    let present = pf_errno & 1;
    let write = (pf_errno & (1 << 1)) >> 1;
    let user = (pf_errno & (1 << 2)) >> 2;
    let reserved_write = (pf_errno & (1 << 3)) >> 3;
    let instruction_fetch = (pf_errno & (1 << 4)) >> 4;
    let protection_key = (pf_errno & (1 << 5)) >> 5;
    let shadow_stack = (pf_errno & (1 << 6)) >> 6;
    let sgx = (pf_errno & (1 << 7)) >> 7;

    debug!("+-------+------+------+------+------+-----+-----+-----+");
    debug!("|  SGX  |  SS  |  PK  |  IF  |  RW  |  U  |  W  |  P  |");
    debug!("+-------+------+------+------+------+-----+-----+-----+");
    debug!(
        "|   {}   |  {}   |  {}   |  {}   |  {}   |  {}  |  {}  |  {}  |",
        sgx, shadow_stack, protection_key, instruction_fetch, reserved_write, user, write, present
    );
    debug!("+-------+------+------+------+------+-----+-----+-----+");
}
