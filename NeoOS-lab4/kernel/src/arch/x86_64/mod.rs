pub mod acpi;
pub mod apic;
pub mod boot;
pub mod cpu;
pub mod gdt;
pub mod hpet;
pub mod interrupt;
pub mod io;
pub mod mm;
pub mod pit;
pub mod signal;
pub mod timer;

// Some constants.
pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_MASK: usize = 0xffff_ffff_ffff_f000;
pub const KERNEL_BASE: u64 = 0xffff_ffff_8000_0000;
pub const KERNEL_HEAP_SIZE: usize = 0x0100_0000;
// Direct mapping!
pub const PHYSICAL_MEMORY_START: u64 = 0xffff_8880_0000_0000;
// User space top.
pub const USER_MEM_TOP: u64 = 0xffff_7fff_ffff_ffff;
// VMALLOC / IOREMAP space (we do not use it currently.)
#[allow(unused)]
pub const VM_MEMORY_START: u64 = 0xffff_c900_0000_0000;
// VMMAP base.
#[allow(unused)]
pub const VMMAP_BASE: u64 = 0xffff_ea00_0000_0000;

pub const BYTE_LEN: usize = core::mem::size_of::<u8>();
pub const WORD_LEN: usize = core::mem::size_of::<u16>();
pub const DWORD_LEN: usize = core::mem::size_of::<u32>();
pub const QWORD_LEN: usize = core::mem::size_of::<u64>();

// Paging-related constants.
// These two constants are used to locate the page table entries of kernel components.
pub const KERNEL_PM4: u64 = (KERNEL_BASE >> 39) & 0o777;
pub const PHYSICAL_MEMORY_PM4: u64 = (PHYSICAL_MEMORY_START >> 39) & 0o777;
