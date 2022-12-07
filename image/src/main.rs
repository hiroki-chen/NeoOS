//! This is based on the example at https://rust-osdev.github.io/uefi-rs
#![no_std]
#![no_main]
#![feature(abi_efiapi)]

extern crate alloc;

use log::info;
use uefi::{
    prelude::*,
    proto::media::{
        file::{File, FileAttribute, FileInfo, FileMode, FileType},
        fs::SimpleFileSystem,
    },
    table::{
        boot::{AllocateType, MemoryType},
        cfg::{ACPI2_GUID, SMBIOS_GUID},
    },
    CStr16,
};
use uefi_services;

const BOOT_CONFIG_PATH: &'static str = "\\efi\\boot\\boot.cfg";
// 1KB
const DEFAULT_FILE_BUF_SIZE: usize = 0x400;

/// Opens a file on the disk.
/// At this timepoint, the filesystem is not created, so we need to create a temporary one.
fn read_file(bs: &BootServices, path: &str) -> &'static mut [u8] {
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

    let mut file = match handle.into_type().unwrap() {
        FileType::Regular(f) => f,
        _ => panic!("This file does not exist!"),
    };

    info!("File {} successfullly opened!", path);

    let mut file_info = [0u8; DEFAULT_FILE_BUF_SIZE];
    let info: &mut FileInfo = file.get_info(&mut file_info).unwrap();
    let size = usize::try_from(info.file_size()).unwrap();
    info!("File size is {}", size);

    // Allocate ramdisk pages in the memory.
    let file_mem_ptr = bs
        .allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            ((size - 1) / 0x1000) + 1,
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

#[entry]
fn _main(_handle: uefi::Handle, mut st: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut st).expect("Failed to launch the system table!");

    info!("Initializing the image");
    // Load boot configurations.
    let bs = st.boot_services();
    let file_content = read_file(bs, BOOT_CONFIG_PATH);
    // let toml_value = file_content.parse::<toml::Value>().unwrap();
    // info!("Boot config: {:?}", toml_value);

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

    // For debug.
    bs.stall(10_000_000);

    Status::SUCCESS
}
