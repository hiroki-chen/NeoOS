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

use crate::{
    arch::{cpu::init_current_cpu, PAGE_SIZE},
    error::{Errno, KResult},
    memory::virt_to_phys,
};

// The layout of GDT entry is given as follows (x86_64).
//
// +========+========+========+================+========+
// |63    56|55    52|51    48|47            40|39    32|
// |  base  |  flags |  limit |  access byte   |  base  |
// +========+========+========+================+========+
//
// Note: in 64-bit mode, the Base and Limit values are ignored, each descriptor covers the
// entire linear address space regardless of what they are set to.
//
// This is because we do *not* desire to use gegmentation to separate memory into protected
// areas. As well, this model is strictly enforced in Long Mode, as the base and limit values
// are simply *ignored*.

// Constants for cs and ds.
pub const KERN_CODE_64B: u64 = 0x0020_9800_0000_0000; // EXECUTABLE | USER_SEGMENT | PRESENT | LONG_MODE
pub const KERN_DATA_64B: u64 = 0x0000_9200_0000_0000; // DATA_WRITABLE | USER_SEGMENT | PRESENT
pub const USER_CODE_64B: u64 = 0x0020_F800_0000_0000; // EXECUTABLE | USER_SEGMENT | USER_MODE | PRESENT | LONG_MODE
pub const USER_CODE_32B: u64 = 0x00cf_fa00_0000_ffff; // EXECUTABLE | USER_SEGMENT | USER_MODE | PRESENT
pub const USER_DATA_32B: u64 = 0x00cf_f200_0000_ffff; // EXECUTABLE | USER_SEGMENT | USER_MODE | PRESENT
pub const GDT_ENTRIES: &[u64; 5] = &[
    KERN_CODE_64B,
    KERN_DATA_64B,
    USER_CODE_32B,
    USER_DATA_32B,
    USER_CODE_64B,
];

pub const AP_TRAMPOLINE_GDT: &[u16; 12] = &[
    0x0000, 0x0000, 0x0000, 0x0000, // Null
    0xffff, 0x0000, 0x9a00, 0x00cf, // Code32
    0xffff, 0x0000, 0x9200, 0x00cf, // Data32
];

/// Initializes the GDP entries for the AP trampoline code so that it is able to jump to long mode.
///
/// Why cannot AP trampoline itself sets up the GDP entries? This is because we put the code at 0x10000,
/// an address that real mode fails to access, but we tell the trampoline code that 'it runs at 0xf000'.
/// Thus there is a 0x1000 offset! If we hard-code GDT entries in the assembly code and let AP trampoline
/// code access the address `0xf000 + gdt_offset`, it will read the wrong physical address and nothing is
/// there as the actual GDT entries reside at `0x10000 + gdt_offset`.
///
/// Only the BSP can access 0x10000 and help AP trampoline set up the necessary data structures.
///
/// HACK: We can assume 0xf000 is safe to use so that we do not need to care about the offset :)
pub unsafe fn init_ap_gdt(gdt_addr: u64) {
    let u16_len = core::mem::size_of::<u16>();
    let gdt_size = AP_TRAMPOLINE_GDT.len() * u16_len;
    // Fill the data for `gdtr`.
    let gdtr_addr = gdt_addr + gdt_size as u64;
    kinfo!("gdtr addr = {:#x}", gdtr_addr);
    kinfo!("gdt addr = {:#x}", gdt_addr);
    kinfo!("gdt size = {:#x}", gdt_size);
    core::intrinsics::atomic_store_seqcst(gdtr_addr as *mut u32, gdt_size as u32 - 1);
    core::intrinsics::atomic_store_seqcst(
        (gdtr_addr as *mut u32).add(1) as *mut u16,
        virt_to_phys(gdt_addr) as u16,
    );

    // Copy the GDT entries.
    AP_TRAMPOLINE_GDT.iter().enumerate().for_each(|(idx, d)| {
        core::intrinsics::atomic_store_seqcst((gdt_addr as *mut u16).add(idx), *d);
    });
}

/// Initializes the global descriptor table. When the operating system kernel starts,
/// it typically initializes the Global Descriptor Table (GDT) by performing the following
/// steps:
///
/// * Allocate memory for the GDT.
/// * Define the GDT entries.
/// * Set up the TSS entries.
/// * Load the GDT into the processor.
/// * Load the task register (`ltr`).
pub unsafe fn init_gdt() -> KResult<()> {
    let gdt_ptr = sgdt();
    // Align to 8 bytes.
    let gdt_len = (gdt_ptr.limit + 1) as usize / core::mem::size_of::<u64>();
    kinfo!("init_gdt(): gdt_ptr: {:?}, len: {}", gdt_ptr, gdt_len);

    let gdt = core::slice::from_raw_parts(gdt_ptr.base.as_ptr() as *const u64, gdt_len);
    // Step 1: Memory allocation. The GDT is typically stored in a fixed location in memory.
    let mut gdt = Vec::from(gdt);

    // Step 2: Define the GDT entries (statically). The GDT is a table of entries, each of which describes a
    // memory segment, including its base address, its size, and its access permissions.
    // Step 3: Set up the TSS entries.
    let mut tss = Box::new(TaskStateSegment::new());
    // Allocate stack for trap from user
    let trap_stack_top = Box::leak(Box::new([0u8; PAGE_SIZE])).as_ptr() as u64 + PAGE_SIZE as u64;
    tss.privilege_stack_table[0] = virt!(trap_stack_top);
    let tss: &'static _ = Box::leak(tss);
    let (tss0, tss1) = match Descriptor::tss_segment(tss) {
        Descriptor::SystemSegment(tss0, tss1) => (tss0, tss1),
        Descriptor::UserSegment(tss) => {
            log::error!(
                "init_gdt(): expect tss at kernel level, found at user segment: {:#x}",
                tss
            );
            return Err(Errno::EPERM);
        }
    };

    gdt.extend_from_slice(&[tss0, tss1]);
    gdt.extend_from_slice(GDT_ENTRIES);
    // Do not drop this!
    let gdt_slice = gdt.leak();

    // Step 4: Finally, we load it into the processor.
    let gdt = DescriptorTablePointer {
        base: virt!(gdt_slice.as_ptr() as u64),
        limit: gdt_slice.len() as u16 * 8 - 1,
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

    // Initialize the CPU.
    init_current_cpu(gdt_slice.as_ptr() as u64, tss, trap_stack_top)
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
