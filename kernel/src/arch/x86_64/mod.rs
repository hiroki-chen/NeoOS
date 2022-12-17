pub mod acpi;
pub mod apic;
pub mod boot;
pub mod cpu;
pub mod gdt;
pub mod interrupt;
pub mod io;
pub mod mm;

// Some constants.
pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_MASK: usize = 0x0fff;
pub const KERNEL_BASE: u64 = 0x0100_0000;
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
