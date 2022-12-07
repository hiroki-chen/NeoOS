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
    version: u8,
    /// The base address of the ramdisk. I.e., initrd load address (set by boot loader)
    ramdisk_image: u16,
    /// The size of the ramdisk. I.e., initrd size (set by boot loader)
    ramdisk_size: u16,
    /// The boot flags.
    cmdline: &'static str,
    /// The graphic mode. Must be false because we do not support it but we may add it in the future(?)
    graph_mode: bool,
}

impl Header {
    // TODO.
}
