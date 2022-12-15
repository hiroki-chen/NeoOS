//! A library for parsing ACPI tables. This module can be used by bootloaders and kernels
//! for architectures that support ACPI. This module is designed to find and parse the
//! static tables ACPI provides.

use core::ptr::NonNull;

use acpi::{AcpiHandler, AcpiTables, HpetInfo, PhysicalMapping};
use boot_header::Header;
use log::{debug, error, info};

use crate::{
    arch::PHYSICAL_MEMORY_START,
    error::{Errno, KResult},
};

#[derive(Clone, Copy)]
struct AcpiHandlerImpl;

impl AcpiHandler for AcpiHandlerImpl {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<Self, T> {
        debug!(
            "map_physical_region(): map {:#x} into {:#x}",
            physical_address,
            PHYSICAL_MEMORY_START + physical_address as u64
        );

        PhysicalMapping::new(
            physical_address,
            NonNull::new(crate::memory::phys_to_virt(physical_address as u64) as *mut _)
                .expect("map_physical_region(): failed to initialize `NonNull`"),
            size,
            size,
            Self,
        )
    }

    fn unmap_physical_region<T>(_: &PhysicalMapping<Self, T>) {
        debug!("unmap_physical_region(): unmap");
    }
}

pub fn init_acpi(header: &Header) -> KResult<()> {
    let handler = AcpiHandlerImpl {};
    let table = match unsafe { AcpiTables::from_rsdp(handler, header.acpi2_rsdp_addr as usize) } {
        Ok(table) => table,
        Err(e) => {
            error!("init_acpi(): acpi parse error: {:?}", e);
            return Err(Errno::EINVAL);
        }
    };

    debug!("init_acpi(): revision: {:#x}", table.revision);

    // Get IA-PC High Precision Event Timer Table for `rdtsc` timer.
    if let Ok(hpet_table) = HpetInfo::new(&table) {
        info!("init_acpi(): detected hpet_table!");
        info!("init_acpi(): HPET information:\n{:#x?}", hpet_table);
    }

    Ok(())
}
