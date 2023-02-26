//! A library for parsing ACPI tables. This module can be used by bootloaders and kernels
//! for architectures that support ACPI. This module is designed to find and parse the
//! static tables ACPI provides.

use core::{ptr::NonNull, sync::atomic::Ordering};

use acpi::{
    platform::interrupt::Apic, AcpiHandler, AcpiTables, HpetInfo, InterruptModel, PhysicalMapping,
    PlatformInfo,
};
use boot_header::Header;
use log::{debug, error, info};

use crate::{
    arch::{
        hpet::init_hpet,
        interrupt::pic::disable_pic,
        timer::{init_apic_timer, TimerSource, TIMER_SOURCE},
        PHYSICAL_MEMORY_START,
    },
    error::{Errno, KResult},
    irq::{IrqType, IRQ_TYPE},
};

use super::interrupt::ISA_TO_GSI;

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

    // Check IoAPIC information.
    if let Ok(platform_info) = PlatformInfo::new(&table) {
        info!("init_acpi(): showing platform information!");
        info!("Interrupt model: {:#x?}", platform_info.interrupt_model);
        info!(
            "Processor information: {:#x?}",
            platform_info.processor_info.unwrap().boot_processor
        );

        if let InterruptModel::Apic(apic_information) = platform_info.interrupt_model {
            disable_pic();
            IRQ_TYPE.store(IrqType::Apic, Ordering::Release);

            // Collect mapping.
            collect_irq_mapping(&apic_information);
        }
    }

    // Get IA-PC High Precision Event Timer Table for `rdtsc` timer.
    if let Ok(hpet_table) = HpetInfo::new(&table) {
        // Initialize the HPET timer.
        if let Err(errno) = init_hpet(&hpet_table) {
            log::error!("init_acpi(): cannot initialize HPET due to {:?}.", errno);
            // Ignore this and fall back to `Acpi` timer.
            TIMER_SOURCE.store(TimerSource::Apic, Ordering::Release);
        }
    }

    Ok(())
}

fn collect_irq_mapping(apic_information: &Apic) {
    let mut mapping = ISA_TO_GSI.write();

    apic_information
        .interrupt_source_overrides
        .iter()
        .for_each(|iso| {
            mapping.insert(iso.isa_source, iso.global_system_interrupt);
        });
}
