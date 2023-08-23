//! This is based on the example at https://rust-osdev.github.io/uefi-rs
//这是一个在UEFI环境下的Rust代码示例，主要实现了引导加载器的功能，加载一个内核并将其执行。

#![no_std] // 不使用标准库。
#![no_main] // 不使用Rust默认的main入口。

mod page_table;
mod utils;

extern crate alloc; // 导入内存分配库。

use boot_header::KERN_VERSION;
use boot_header::{GraphInfo, Header};
use log::info; // 导入日志工具。
use uefi::{
    prelude::*,
    proto::console::gop::GraphicsOutput,
    table::{
        boot::{MemoryDescriptor, MemoryType},
        cfg::{ACPI2_GUID, SMBIOS_GUID},
    },
};

// Export.
pub use page_table::PAGE_SIZE;

const BOOT_CONFIG_PATH: &str = "\\efi\\boot\\boot.cfg"; // 引导配置文件的路径。
// 1KB
const DEFAULT_FILE_BUF_SIZE: usize = 0x400;// 默认文件缓冲区大小为1KB。

// 主入口函数。
#[entry]
fn _main(handle: uefi::Handle, mut st: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut st).expect("Failed to launch the system table!");

    // 初始化引导加载器。
    info!("_main(): Initializing the image");

    // 加载引导配置文件。
    // Load boot configurations.
    let bs = st.boot_services();
    let mut file = utils::open_file(bs, BOOT_CONFIG_PATH);
    let file_content = utils::read_buf(bs, &mut file);
    let config = utils::BootLoaderConfig::parse(file_content);
    info!("_main(): {:#x?}", config);

    let config_table = st.config_table();

    // 获取ACPI和SMBIOS的基地址。
    // Get the base address of the ACPI2 data structure.
    let acpi_address = config_table
        .iter()
        .find(|entry| entry.guid == ACPI2_GUID)
        .unwrap()
        .address;
    let smbios_address = config_table
        .iter()
        .find(|entry| entry.guid == SMBIOS_GUID)
        .unwrap()
        .address;

    // 打印ACPI和SMBIOS的基地址。
    info!(
        "_main(): Probed acpi: {:#x}; smbios: {:#x}.",
        acpi_address as u64, smbios_address as u64
    );
    info!("_main(): UEFI bootloader successfullly started. ");

    // 初始化并获取图形信息，尽管在这段代码中并未使用它。
    // Init framebuffer, although not used.
    let graph_info = get_graph_info(bs);
    info!(
        "_main(): Probed framebuffer: {:#x} with size {:#x}",
        graph_info.framebuffer, graph_info.framebuffer_size
    );

    // 从磁盘加载内核。
    // Load the kernel from the disk.
    let kernel = utils::Kernel::new(bs, &config);
    info!("_main(): Entry: {:#x}", kernel.elf.header.pt2.entry_point());
    info!(
        "_main(): Kernel loaded at {:#x}",
        kernel.start_address as u64
    );

    // 获取UEFI提供的内存映射信息。
    // In the context of UEFI (Unified Extensible Firmware Interface),
    // the memory_map_size parameter specifies the size of the memory
    // map that is provided by the UEFI firmware. The memory map is a
    // table that contains information about the memory regions that
    // are available to the operating system, such as the size and type
    // of each region. This information is important for the operating
    // system to properly allocate and manage memory resources.
    // 在UEFI（统一的可扩展固件接口）的上下文中，
    // memory_map_size参数指定了UEFI固件提供的内存映射的大小。
    // 内存映射是一个表，其中包含有关操作系统可用的内存区域的信息，
    // 如每个区域的大小和类型。这些信息对于操作系统正确分配和管理内存资源非常重要。

    let mmap_storage = {
        let max_mmap_size =
            bs.memory_map_size().map_size + 8 * core::mem::size_of::<MemoryDescriptor>();
        let ptr = bs
            .allocate_pool(MemoryType::LOADER_DATA, max_mmap_size)
            .unwrap();
        unsafe { core::slice::from_raw_parts_mut(ptr, max_mmap_size) }
    };
    mmap_storage.fill(0);
    let mmap_ptr = mmap_storage.as_mut_ptr();

    // 打印并退出UEFI的引导服务，为操作系统腾出资源。
    // Boot services are available only while the firmware owns the platform.
    // As we have obtained all the need information, they are no longer valid.
    // So we need to free them.
    let entry_size = core::mem::size_of::<MemoryDescriptor>();
    let mmap_size = bs.memory_map_size().map_size;
    info!("_main(): Invalidate boot services");
    info!(
        "_main():  cmdline addr: {:#x}, mmap_storage: {:#x}, mm_size: {:#x}, entry_size: {:#x}",
        config.cmdline.as_ptr() as u64,
        mmap_ptr as u64,
        mmap_size,
        entry_size,
    );

    let (_system_table, memory_map) = st
        .exit_boot_services(handle, mmap_storage)
        .expect("_main(): Failed to exit boot services");
    let mmap_len = memory_map.len();

    // 创建和构建页面表。
    // Construct mapping.
    let mut allocator = page_table::OsFrameAllocator::new(memory_map);
    let mut pt = page_table::create_page_tables(&mut allocator);

    // 准备内存空间并启用一些保护机制。
    // Prepare the memory spaces.
    // Enable protections.
    page_table::enable_nxe_efer();
    page_table::enable_write_protect();
    page_table::map_kernel(&kernel, &mut allocator, &mut pt);
    page_table::map_stack(&kernel, &mut allocator, &mut pt);
    page_table::map_context_switch(&kernel, &mut allocator, &mut pt);
    page_table::map_physical(&kernel, &mut allocator, &mut pt);

    // Before kernel is the boot header.
    let kernel_entry = kernel.elf.header.pt2.entry_point();

    // 构建加载所需的引导信息头。
    // Remember to map the header that loads the needed boot information.
    // This is because after we performed a context switch into the kernel,
    // previous pages are no longer accessible. You can check this fact by
    // gdb command `x [addr]`.
    let mut header = Header {
        version: KERN_VERSION,
        cmdline: config.cmdline.as_ptr(),
        cmdline_len: config.cmdline.len() as _,
        enable_graph: true,
        graph_info,
        acpi2_rsdp_addr: acpi_address as u64,
        smbios_addr: smbios_address as u64,
        mem_start: config.physical_mem,
        mmap: mmap_ptr as u64,
        mmap_len: mmap_len as u64,
        kernel_entry,
        first_proc: config.first_proc.as_ptr(),
        first_proc_len: config.first_proc.len() as _,
        args: config.args.as_ptr(),
        args_len: config.args.len() as _,
    };
    page_table::map_gdt(&kernel, &mut allocator, &mut pt);

    // Re-use `mmap_storage`.
    allocator.refactor_mmap_storage(mmap_ptr, entry_size);

    // 跳转到内核执行。
    // Jump to the kernel.
    let stack_top = config.kernel_stack_address + config.kernel_stack_size * PAGE_SIZE;

    // 执行上下文切换，转到内核执行。
    // The previous memory address is no longer available.
    unsafe {
        page_table::context_switch(
            &pt,
            kernel_entry,
            (&mut header as *mut Header as u64) + config.physical_mem,
            stack_top,
        )
    }
}

// 探测并获取图形信息。
// Probe the framebuffer and enable it.
pub fn get_graph_info(bs: &BootServices) -> GraphInfo {
    let gop_handle = bs
        .get_handle_for_protocol::<GraphicsOutput>()
        .expect("_main(): No such service!");
    let mut gop = bs
        .open_protocol_exclusive::<GraphicsOutput>(gop_handle)
        .expect("_main(): Cannot open GraphicsOutput!");

    GraphInfo {
        mode: gop.current_mode_info(),
        framebuffer: gop.frame_buffer().as_mut_ptr() as u64,
        framebuffer_size: gop.frame_buffer().size() as u64,
    }
}
