pub mod apic;
pub mod acpi;
pub mod boot;
pub mod cpu;
pub mod gdt;
pub mod interrupt;
pub mod io;
pub mod mm;

// Some constants.
pub const KERNEL_BASE: u64 = 0x0100_0000;
pub const KERNEL_HEAP_SIZE: usize = 0x0100_0000;
pub const PHYSICAL_MEMORY_START: u64 = 0xffff_8000_0000_0000;
pub const SERIAL_IO_PORT: u16 = 0x3F8;
