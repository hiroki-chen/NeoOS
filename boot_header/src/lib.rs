#![allow(non_snake_case)]
#![no_std]

extern crate alloc;

use uefi::proto::console::gop::ModeInfo;
// Export.
pub use uefi::table::boot::{MemoryDescriptor, MemoryType};

/// original address of boot-sector
pub const BOOTSEG: u16 = 0x07C0;
/// historical load address >> 4
pub const SYSSEG: u16 = 0x1000;
/// The current version.
pub const KERN_VERSION: u8 = 0x01;

/// The boot header. See linux/arch/x86/boot/header.S
/// Will be linked against the assembly code.
///
/// This header is obtained by the bootloader and passed to the kernel.
#[repr(C)]
#[derive(Debug)]
pub struct Header {
    /// The version of the boot protocol.
    pub version: u8,
    /// The boot flags.
    pub cmdline: *const u8,
    /// The length of the cmdline string.
    pub cmdline_len: u64,
    /// The graphic mode. Must be false because we do not support it but we may add it in the future(?)
    pub enable_graph: bool,
    /// The address of the Root System Description Pointer used in the ACPI programming interface.
    pub acpi2_rsdp_addr: u64,
    /// The physical address to the start of virtual address.
    pub mem_start: u64,
    /// The address of the System Management BIOS.
    pub smbios_addr: u64,
    /// The graphic information.
    pub graph_info: GraphInfo,
    /// The address to the memory mapping provided by the UEFI.
    pub mmap: u64,
    /// The length of the mmap descriptors.
    pub mmap_len: u64,
    /// The kernel entry.
    pub kernel_entry: u64,
    /// The first process.
    pub first_proc: *const u8,
    /// The length of the `first_proc` string.
    pub first_proc_len: u64,
    /// The argument for the first process.
    pub args: *const u8,
    /// The length of the arguments.
    pub args_len: u64,
}

/// Graphic informations for printing to the console.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GraphInfo {
    /// Framebuffer base physical address
    pub framebuffer: u64,
    /// Framebuffer size
    pub framebuffer_size: u64,
    /// The graph mode.
    pub mode: ModeInfo,
}
