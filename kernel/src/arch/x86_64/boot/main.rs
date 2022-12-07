use uefi::prelude::*;
use uefi_services;

#[entry]
fn main(handle: uefi::Handle, mut st: SystemTable<Boot>) -> Status {
  uefi_services::init(&mut st).expect("Failed to launch the system table!");

  Status::SUCCESS
}
