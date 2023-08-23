//! Contains a set of utility functions here.

// 引入必要的库和模块
use alloc::format;
use log::info;
use uefi::{
    prelude::BootServices,
    proto::media::{
        file::{File, FileAttribute, FileInfo, FileMode, FileType, RegularFile},
        fs::SimpleFileSystem,
    },
    table::boot::{AllocateType, MemoryType},
    CStr16,
};
use xmas_elf::{header::Type, ElfFile};

use crate::DEFAULT_FILE_BUF_SIZE;

// 解析配置字符串，从中获取U64类型的值
fn parse_u64(config: &str, key: &str) -> u64 {
    let pattern = format!("{} = ", key);
    let entry = match config.lines().find(|line| line.starts_with(&pattern)) {
        Some(e) => e,
        None => return 0,
    };
    let entry = entry.trim_start_matches(&pattern);

    match entry.parse::<u64>() {
        Ok(num) => num,
        Err(_) => u64::from_str_radix(&entry[2..], 16).unwrap(),
    }
}

// 从配置字符串中解析字符串值
fn parse_str<'a>(config: &'a str, key: &str) -> &'a str {
    let pattern = format!("{} = ", key);
    let entry = match config.lines().find(|line| line.starts_with(&pattern)) {
        Some(v) => v,
        None => return "",
    };

    entry.trim_start_matches(&pattern).trim_matches('"')
}

/// The Kernel ELF struct.
// 代表内核的ELF结构
#[derive(Debug)]
pub struct Kernel<'a> {
    /// The kernel ELF content.
    // 内核的ELF内容
    pub elf: ElfFile<'a>,
    /// The configuration parsed from `efi/boot/boot.cfg`.
    // 从`efi/boot/boot.cfg`解析的配置
    pub config: &'a BootLoaderConfig<'a>,
    /// The starting address of the start address.
    // 启动地址的开始地址
    pub start_address: *const u8,
    /// The size of the kernel.
    // 内核的大小
    pub size: u64,
}

// 根据BootServices和配置创建新的Kernel实例
impl<'a> Kernel<'a> {
    pub fn new(bs: &BootServices, config: &'a BootLoaderConfig<'a>) -> Self {
        let kernel_path = config.kernel_path;
        info!(
            "Kernel::new(): Now loading the kernel image from {}.",
            kernel_path
        );
        let mut kernel = open_file(bs, kernel_path);
        let kernel_content = read_buf(bs, &mut kernel);
        let kernel_elf = ElfFile::new(kernel_content).expect("Not a valid ELF file.");

        let ty = kernel_elf.header.pt2.type_().as_type();
        if ty != Type::Executable && ty != Type::SharedObject {
            panic!(
                "Kernel::new(): We only support executable or shared object! Got {:?}.",
                ty
            );
        }
        info!(
            "Kernel::new(): Kernel type: {:?}",
            kernel_elf.header.pt2.type_().as_type()
        );

        Self {
            elf: kernel_elf,
            config,
            start_address: kernel_content.as_ptr() as *const u8,
            size: kernel_content.len() as u64,
        }
    }
}

/// The configuration object for the bootloader.
#[derive(Debug)]
pub struct BootLoaderConfig<'a> {
    /// The size of the stack that the bootloader should allocate for the kernel (in bytes).
    ///
    /// The bootloader starts the kernel with a valid stack pointer. This setting defines
    /// the stack size that the bootloader should allocate and map. The stack is created
    /// with a guard page, so a stack overflow will lead to a page fault.

    // bootloader为内核分配的堆栈大小（以字节为单位）
    pub kernel_stack_size: u64,

    /// The starting address of the kernel stack.
    // 内核堆栈的开始地址
    pub kernel_stack_address: u64,

    /// The path to the kernel image.
    // 内核映像的路径
    pub kernel_path: &'a str,
    
    /// Command line arguments (similar to grub).
    // 命令行参数（类似于grub）
    pub cmdline: &'a str,

    /// The starting virtual address of the allocatable memory.
    // 可分配内存的开始虚拟地址
    pub physical_mem: u64,

    /// The starting address of the initramfs.
    // initramfs的开始地址
    pub initramfs: u64,

    /// The size of the initramfs.
    // initramfs的大小
    pub initramfs_size: u64,

    /// The first process's name.
    // 第一个进程的名称
    pub first_proc: &'a str,

    /// The arguments for the first process.
    // 第一个进程的参数
    pub args: &'a str,
}

// 从配置缓冲区解析BootLoaderConfig
impl<'a> BootLoaderConfig<'a> {
    pub fn parse(config_buf: &'a [u8]) -> Self {
        let config_str = core::str::from_utf8(config_buf).unwrap();

        let kernel_stack_size = parse_u64(config_str, "kernel_stack_size");
        let kernel_stack_address = parse_u64(config_str, "kernel_stack_address");
        let kernel_path = parse_str(config_str, "kernel_path");
        let cmdline = parse_str(config_str, "cmdline");
        let physical_mem = parse_u64(config_str, "physical_mem");
        let initramfs = parse_u64(config_str, "initramfs");
        let initramfs_size = parse_u64(config_str, "initramfs_size");
        let first_proc = parse_str(config_str, "first_proc");
        let args = parse_str(config_str, "args");

        Self {
            kernel_stack_size,
            kernel_stack_address,
            kernel_path,
            cmdline,
            physical_mem,
            initramfs,
            initramfs_size,
            first_proc,
            args,
        }
    }
}

impl<'a> Default for BootLoaderConfig<'a> {
    fn default() -> Self {
        Self {
            kernel_stack_size: 0x200,
            kernel_stack_address: 0xFFFFFF0100000000,
            kernel_path: "\\efi\\boot\\NeoOS.img",
            cmdline: "",
            physical_mem: 0xFFFF800000000000,
            initramfs: 0,
            initramfs_size: 0,
            first_proc: "",
            args: "",
        }
    }
}

/// Opens a file on the disk.
/// At this timepoint, the filesystem is not created, so we need to create a temporary one.
// 在磁盘上打开一个文件
pub fn open_file(bs: &BootServices, path: &str) -> RegularFile {
    // Create a temporary filesystem.
    let handle = bs.get_handle_for_protocol::<SimpleFileSystem>().unwrap();
    let mut file_system = bs
        .open_protocol_exclusive::<SimpleFileSystem>(handle)
        .unwrap();

    let mut root = file_system.open_volume().unwrap();
    let mut buf = [0u16; 0x40];
    let filename = CStr16::from_str_with_buf(path, &mut buf).unwrap();
    let handle = root
        .open(filename, FileMode::Read, FileAttribute::empty())
        .expect("Failed to open file");

    let file = match handle.into_type().unwrap() {
        FileType::Regular(f) => f,
        _ => panic!("This file does not exist!"),
    };
    info!("open_file(): File {} successfullly opened!", path);

    file
}

// 从文件中读取内容并返回缓冲区
pub fn read_buf(bs: &BootServices, file: &mut RegularFile) -> &'static mut [u8] {
    let mut file_info = [0u8; DEFAULT_FILE_BUF_SIZE];
    let info: &mut FileInfo = file.get_info(&mut file_info).unwrap();
    let size = usize::try_from(info.file_size()).unwrap();
    info!("read_buf(): File size is {}", size);

    // Allocate ramdisk pages in the memory.
    let file_mem_ptr = bs
        .allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            ((size - 1) / crate::PAGE_SIZE as usize) + 1,
        )
        .expect("Cannot allocate memory in the ramdisk!") as *mut u8;

    // Read from memory.
    let mem_file = unsafe {
        core::ptr::write_bytes(file_mem_ptr, 0, size);
        core::slice::from_raw_parts_mut(file_mem_ptr, size)
    };
    let file_len = file
        .read(mem_file)
        .expect("Cannot read file into the memory!");

    &mut mem_file[..file_len]
}
