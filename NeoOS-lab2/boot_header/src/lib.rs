#![allow(non_snake_case)]
#![no_std]

// 引入内存分配相关的功能
extern crate alloc;

use uefi::proto::console::gop::ModeInfo;
// Export.
// 导出用于内存描述和内存类型的结构体
pub use uefi::table::boot::{MemoryDescriptor, MemoryType};

/// original address of boot-sector
// 原始的启动扇区地址
pub const BOOTSEG: u16 = 0x07C0;
/// historical load address >> 4
// 历史上的加载地址右移4位
pub const SYSSEG: u16 = 0x1000;
/// The current version.
// 当前的版本。
pub const KERN_VERSION: u8 = 0x01;

/// The boot header. See linux/arch/x86/boot/header.S
/// Will be linked against the assembly code.
///
/// This header is obtained by the bootloader and passed to the kernel.
/// 启动头部信息。参见 linux/arch/x86/boot/header.S
/// 这部分将与汇编代码进行链接。
///
/// 这个头部由引导程序获得，并传递给内核。
#[repr(C)]
#[derive(Debug)]
pub struct Header {
    /// The version of the boot protocol.
    // 启动协议的版本。
    pub version: u8,
    /// The boot flags.
    // 启动标志。
    pub cmdline: *const u8,
    /// The length of the cmdline string.
    // cmdline字符串的长度。
    pub cmdline_len: u64,
    /// The graphic mode. Must be false because we do not support it but we may add it in the future(?)
    // 图形模式。因为我们现在不支持它，所以必须是false，但我们可能会在未来添加它(?)
    pub enable_graph: bool,
    /// The address of the Root System Description Pointer used in the ACPI programming interface.
    // 用于ACPI编程接口的Root System Description Pointer的地址。
    pub acpi2_rsdp_addr: u64,
    /// The physical address to the start of virtual address.
    // 到虚拟地址开始的物理地址。
    pub mem_start: u64,
    /// The address of the System Management BIOS.
    // System Management BIOS的地址。
    pub smbios_addr: u64,
    /// The graphic information.
    // 图形信息。
    pub graph_info: GraphInfo,
    /// The address to the memory mapping provided by the UEFI.
    // UEFI提供的内存映射的地址。
    pub mmap: u64,
    /// The length of the mmap descriptors.
    // mmap描述符的长度。
    pub mmap_len: u64,
    /// The kernel entry.
    // 内核的入口点。
    pub kernel_entry: u64,
    /// The first process.
    // 第一个进程。
    pub first_proc: *const u8,
    /// The length of the `first_proc` string.
    // `first_proc`字符串的长度。
    pub first_proc_len: u64,
    /// The argument for the first process.
    // 第一个进程的参数。
    pub args: *const u8,
    /// The length of the arguments.
    // 参数的长度。
    pub args_len: u64,
}

/// Graphic informations for printing to the console.
// 用于向控制台打印的图形信息。
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GraphInfo {
    /// Framebuffer base physical address
    // Framebuffer的基础物理地址
    pub framebuffer: u64,
    /// Framebuffer size
    // Framebuffer的大小
    pub framebuffer_size: u64,
    /// The graph mode.
    // 图形模式。
    pub mode: ModeInfo,
}
