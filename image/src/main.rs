//! This is based on the example at https://rust-osdev.github.io/uefi-rs
#![no_std]
#![no_main]
#![feature(abi_efiapi)]

mod header;
mod page_table;
mod utils;

extern crate alloc;

use core::arch::asm;
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
    info!("Boot config: {:?}", config);

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
        "Probed acpi: {:?}; smbios: {:?}.",
        acpi_address, smbios_address
    );
    info!("UEFI bootloader successfullly started. ");

    // Load the kernel from the disk.
    let kernel = utils::Kernel::new(bs, &config);

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
    let (system_table, memory_map) = st
        .exit_boot_services(handle, mmap_storage)
        .expect("Failed to exit boot services");
    
    // Construct mapping.
    let mut allocator = page_table::OsFrameAllocator::new(memory_map);
    let pt = page_table::create_page_tables(&mut allocator);

    // panic!("a"); for debugging because logger is no longer valid.
    Status::SUCCESS
}

/// Performs a long jump into the entry of the kernel so that bootloader no long works.
unsafe fn long_jump(entry: u64, header: *const Header, stack_top: u64) -> ! {
    // The boot header is passed by the address in the rdi register.
    asm!("mov rsp, {}", "call {}", in(reg) stack_top, in(reg) entry, in("rdi") header);
    // After the kernel finishes, do CPU idle.
    loop {
        asm!("nop");
    }
}
