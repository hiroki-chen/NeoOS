pub mod apic;
pub mod boot;
pub mod cpu;
pub mod interrupt;
pub mod io;

// Some constants.
pub const KERNEL_BASE: u64 = 0x1_000_000;
pub const KERNEL_HEAP_SIZE: usize = 0x1000000;
pub const PHYSICAL_MEMORY_START: u64 = 0xf_fff_800_000_000_000;
pub const SERIAL_IO_PORT: u16 = 0x3F8;
