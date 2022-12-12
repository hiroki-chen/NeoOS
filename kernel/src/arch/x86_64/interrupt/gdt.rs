//! The Global Descriptor Table (GDT) is a data structure used in the x86-64 architecture
//! to define the characteristics of the various memory segments used by the system. The
//! GDT is a table of entries, each of which describes a memory segment, including its
//! base address, its size, and its access permissions.
//!
//! The GDT is used by the processor to enforce the memory protection mechanism of the
//! x86-64 architecture. When a program accesses memory, the processor uses the GDT to
//! determine the characteristics of the memory segment that is being accessed, and to
//! ensure that the access is allowed. If the access is not allowed, the processor generates
//! a fault, which causes the operating system to handle the exception and take an appropriate
//! action.

use alloc::{boxed::Box, vec::Vec};
use core::arch::asm;
use x86_64::{
    registers::model_specific::{GsBase, Star},
    structures::{
        gdt::{Descriptor, SegmentSelector},
        tss::TaskStateSegment,
        DescriptorTablePointer,
    },
    PrivilegeLevel, VirtAddr,
};

use crate::error::{Errno, KResult};

// The layout of GDT entry is given as follows (x86_64).
//
// +========+========+========+================+========+
// |63    56|55    52|51    48|47            40|39    32|
// |  base  |  flags |  limit |  access byte   |  base  |
// +========+========+========+================+========+
//
// Note: in 64-bit mode, the Base and Limit values are ignored, each descriptor covers the
// entire linear address space regardless of what they are set to.

// Constants for cs and ds.
const KERN_CODE_64B: u64 = 0x00209800_00000000; // EXECUTABLE | USER_SEGMENT | PRESENT | LONG_MODE
const KERN_DATA_64B: u64 = 0x00009200_00000000; // DATA_WRITABLE | USER_SEGMENT | PRESENT
const USER_CODE_64B: u64 = 0x0020F800_00000000; // EXECUTABLE | USER_SEGMENT | USER_MODE | PRESENT | LONG_MODE
const USER_CODE_32B: u64 = 0x00cffa00_0000ffff; // EXECUTABLE | USER_SEGMENT | USER_MODE | PRESENT
const USER_DATA_32B: u64 = 0x00cff200_0000ffff; // EXECUTABLE | USER_SEGMENT | USER_MODE | PRESENT
const GDT_ENTRIES: &'static [u64; 5] = &[
    KERN_CODE_64B,
    KERN_DATA_64B,
    USER_CODE_32B,
    USER_DATA_32B,
    USER_CODE_64B,
];

/// Initializes the global descriptor table. When the operating system kernel starts,
/// it typically initializes the Global Descriptor Table (GDT) by performing the following
/// steps:
///
/// * Allocate memory for the GDT.
/// * Define the GDT entries.
/// * Set up the TSS entries.
/// * Load the GDT into the processor.
/// * Load the task register (`ltr`).
pub unsafe fn init_interrupt_all() -> KResult<()> {
    let gdt_ptr = sgdt();
    // Align to 8 bytes.
    let gdt_len = (gdt_ptr.limit + 1) as usize / core::mem::size_of::<u64>();
    log::info!("init_interrupt_all(): gdt_ptr: {:?}, len: {}", gdt_ptr, gdt_len);

    let gdt = core::slice::from_raw_parts(gdt_ptr.base.as_ptr() as *const u64, gdt_len);
    // Step 1: Memory allocation. The GDT is typically stored in a fixed location in memory.
    let mut gdt = Vec::from(gdt);

    // Step 2: Define the GDT entries (statically). The GDT is a table of entries, each of which describes a
    // memory segment, including its base address, its size, and its access permissions.
    // Step 3: Set up the TSS entries.
    let mut tss = Box::new(TaskStateSegment::new());
    // Allocate stack for trap from user
    let trap_stack_top = Box::leak(Box::new([0u8; 0x1000])).as_ptr() as u64 + 0x1000;
    tss.privilege_stack_table[0] = VirtAddr::new(trap_stack_top);
    let tss: &'static _ = Box::leak(tss);
    let (tss0, tss1) = match Descriptor::tss_segment(tss) {
        Descriptor::SystemSegment(tss0, tss1) => (tss0, tss1),
        Descriptor::UserSegment(_) => return Err(Errno::EPERM),
    };

    gdt.extend_from_slice(&[tss0, tss1]);
    gdt.extend_from_slice(GDT_ENTRIES);
    // Do not drop this!
    let gdt = gdt.leak();

    // Step 4: Finally, we load it into the processor.
    let gdt = DescriptorTablePointer {
        base: VirtAddr::new(gdt.as_ptr() as u64),
        limit: gdt.len() as u16 * 8 - 1,
    };
    let tr = SegmentSelector::new(gdt_len as u16, PrivilegeLevel::Ring0);
    lgdt(&gdt);
    ltr(tr);

    // store address of TSS to kernel_gsbase
    #[allow(const_item_mutation)]
    GsBase::MSR.write(tss as *const _ as u64);

    // Syscall Register: STAR.
    Star::write_raw(
        SegmentSelector::new(gdt_len as u16 + 4, PrivilegeLevel::Ring3).0,
        SegmentSelector::new(gdt_len as u16 + 2, PrivilegeLevel::Ring0).0,
    );
    Ok(())
}

/// `sgdt` is a machine instruction in the x86-64 instruction set that is used to store the
/// current value of the Global Descriptor Table (GDT) register in memory.
#[inline(always)]
pub unsafe fn sgdt() -> DescriptorTablePointer {
    let mut gdt_ptr = DescriptorTablePointer {
        limit: 0,
        base: VirtAddr::new(0),
    };
    asm!("sgdt [{}]", in(reg) &mut gdt_ptr);
    gdt_ptr
}

/// Loads a GDT from kernel provided gdt pointer.
///
/// ## Safety
///
/// This function is unsafe because the caller must ensure that the given
/// `DescriptorTablePointer` points to a valid GDT and that loading this
/// GDT is safe.
#[inline(always)]
pub unsafe fn lgdt(gdt: &DescriptorTablePointer) {
    asm!("lgdt [{}]", in(reg) gdt, options(readonly, nostack, preserves_flags));
}

#[inline(always)]
pub unsafe fn ltr(ss: SegmentSelector) {
    asm!("ltr {0:x}", in(reg) ss.0, options(nostack, preserves_flags));
}
