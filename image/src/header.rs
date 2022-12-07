use crate::memmap::MemoryMap;

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
    /// The base address of the ramdisk. I.e., initrd load address (set by boot loader)
    pub ramdisk_image: u64,
    /// The size of the ramdisk. I.e., initrd size (set by boot loader)
    pub ramdisk_size: u64,
    /// The boot flags.
    pub cmdline: &'static str,
    /// The graphic mode. Must be false because we do not support it but we may add it in the future(?)
    pub graph_mode: bool,
    /// The address of the Root System Description Pointer used in the ACPI programming interface. 
    pub acpi2_rsdp_addr: u64,
    /// The physical address to the start of virtual address.
    pub virt_mem_start: u64,
    /// The address of the System Management BIOS.
    pub smbios_addr: u64,
    /// The memory mapping information after boolloader starts the kernel.
    pub memory_map: MemoryMap,
}

impl Header {
    // TODO.
}
