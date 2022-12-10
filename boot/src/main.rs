//! This is based on the example at https://rust-osdev.github.io/uefi-rs
#![no_std]
#![no_main]
#![feature(abi_efiapi)]

mod header;
mod page_table;
mod utils;

extern crate alloc;

use alloc::boxed::Box;
use header::Header;
use log::info;
use uefi::{
    prelude::*,
    table::{
        boot::{MemoryDescriptor, MemoryType},
        cfg::{ACPI2_GUID, SMBIOS_GUID},
    },
};
use uefi_services;
// Export.
pub use page_table::PAGE_SIZE;

const BOOT_CONFIG_PATH: &'static str = "\\efi\\boot\\boot.cfg";
// 1KB
const DEFAULT_FILE_BUF_SIZE: usize = 0x400;

#[entry]
fn _main(handle: uefi::Handle, mut st: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut st).expect("Failed to launch the system table!");

    info!("Initializing the image");
    // Load boot configurations.
    let bs = st.boot_services();
    let mut file = utils::open_file(bs, BOOT_CONFIG_PATH);
    let file_content = utils::read_buf(bs, &mut file);
    let config = utils::BootLoaderConfig::parse(file_content);
    info!("{:#?}", config);

    let boot_services = st.boot_services();
    let config_table = st.config_table();

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

    info!(
        "Probed acpi: {:#x}; smbios: {:#x}.",
        acpi_address as u64, smbios_address as u64
    );
    info!("UEFI bootloader successfullly started. ");

    // Load the kernel from the disk.
    let kernel = utils::Kernel::new(bs, &config);
    info!("Entry: {:#x}", kernel.elf.header.pt2.entry_point());
    info!("Kernel loaded at {:#x}", kernel.start_address as u64);
    // In the context of UEFI (Unified Extensible Firmware Interface),
    // the memory_map_size parameter specifies the size of the memory
    // map that is provided by the UEFI firmware. The memory map is a
    // table that contains information about the memory regions that
    // are available to the operating system, such as the size and type
    // of each region. This information is important for the operating
    // system to properly allocate and manage memory resources.
    let mmap_storage = {
        let max_mmap_size =
            bs.memory_map_size().map_size + 8 * core::mem::size_of::<MemoryDescriptor>();
        let ptr = bs
            .allocate_pool(MemoryType::LOADER_DATA, max_mmap_size)
            .unwrap();
        unsafe { core::slice::from_raw_parts_mut(ptr, max_mmap_size) }
    };

    // Boot services are available only while the firmware owns the platform.
    // As we have obtained all the need information, they are no longer valid.
    // So we need to free them.
    info!("Invalidate boot services");
    info!("cmdline addr: {:#x}", config.cmdline.as_ptr() as u64);
    let (system_table, memory_map) = st
        .exit_boot_services(handle, mmap_storage)
        .expect("Failed to exit boot services");

    // Construct mapping.
    let mut allocator = page_table::OsFrameAllocator::new(memory_map);
    let mut pt = page_table::create_page_tables(&mut allocator);

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

    // Remember to map the header that loads the needed boot information.
    // This is because after we performed a context switch into the kernel,
    // previous pages are no longer accessible. You can check this fact by
    // gdb command `x [addr]`.
    let mut header = Header {
        version: 1u8,
        cmdline: config.cmdline,
        graph_mode: false,
        acpi2_rsdp_addr: acpi_address as u64,
        smbios_addr: smbios_address as u64,
        mem_start: config.physical_mem,
    };
    page_table::map_header(&kernel, &mut allocator, &mut pt, &header);
    // Jump to the kernel.
    let stack_top = config.kernel_stack_address + config.kernel_stack_size * PAGE_SIZE;

    // The previous memory address is no longer available.
    unsafe {
        page_table::context_switch(
            &pt,
            kernel_entry,
            &mut header as *mut Header as u64,
            stack_top,
        )
    }
}
