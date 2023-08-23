//! A library for parsing ACPI tables. This module can be used by bootloaders and kernels
//! for architectures that support ACPI. This module is designed to find and parse the
//! static tables ACPI provides.

use core::{ptr::NonNull, sync::atomic::Ordering};

use acpi::{
    madt::Madt, platform::interrupt::Apic, sdt::Signature, AcpiHandler, AcpiTables, HpetInfo,
    InterruptModel, PhysicalMapping, PlatformInfo,
};

use boot_header::Header;
use x86_64::instructions::port::Port;

use crate::{
    arch::{
        apic::ap::init_aps,
        cpu::BSP_ID,
        hpet::init_hpet,
        interrupt::pic::disable_pic,
        timer::{TimerSource, TIMER_SOURCE},
        PHYSICAL_MEMORY_START,
    },
    error::{error_to_int, Errno, KResult},
    irq::{IrqType, IRQ_TYPE},
};

use super::interrupt::ISA_TO_GSI;

pub const AP_STARTUP: u64 = 0xf000;
// The trampoline code assembled by nasm.
pub const AP_TRAMPOLINE_CODE: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/ap_trampoline"));

#[derive(Clone, Copy)]
struct AcpiHandlerImpl;

impl AcpiHandler for AcpiHandlerImpl {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<Self, T> {
        kdebug!(
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
        kdebug!("unmap_physical_region(): unmap");
    }
}

pub fn init_acpi(header: &Header) -> KResult<()> {
    let handler = AcpiHandlerImpl {};
    let table = match unsafe { AcpiTables::from_rsdp(handler, header.acpi2_rsdp_addr as usize) } {
        Ok(table) => table,
        Err(e) => {
            kerror!("init_acpi(): acpi parse kerror: {:?}", e);
            return Err(Errno::EINVAL);
        }
    };

    kdebug!("init_acpi(): revision: {:#x}", table.revision);

    // Check IoAPIC information.
    if let Ok(platform_info) = PlatformInfo::new(&table) {
        kinfo!("init_acpi(): showing platform information!");
        kdebug!("Interrupt model: {:#x?}", platform_info.interrupt_model);

        // Set the BSP.
        BSP_ID.call_once(|| {
            platform_info
                .processor_info
                .unwrap()
                .boot_processor
                .local_apic_id
        });

        if let InterruptModel::Apic(apic_information) = platform_info.interrupt_model {
            if apic_information.also_has_legacy_pics {
                disable_pic();
            }
            IRQ_TYPE.store(IrqType::Apic, Ordering::Release);

            // Collect mapping.
            collect_irq_mapping(&apic_information);
        }
    }

    // Get IA-PC High Precision Event Timer Table for `rdtsc` timer.
    if let Ok(hpet_table) = HpetInfo::new(&table) {
        // Initialize the HPET timer.
        if let Err(errno) = init_hpet(&hpet_table) {
            kerror!("init_acpi(): cannot initialize HPET due to {:?}.", errno);
            // Ignore this and fall back to `Acpi` timer.
            TIMER_SOURCE.store(TimerSource::Apic, Ordering::Release);
        }
    }

    if cfg!(feature = "multiprocessor") {
        unsafe {
            let madt = table
                .get_sdt::<Madt>(Signature::MADT)
                .map_err(|_| Errno::ENOSPC)?
                .ok_or(Errno::EEXIST)?;
            init_aps(&madt)
        }
    } else {
        Ok(())
    }
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

/// In modern versions of qemu, in order to terminate the VM from inside, we have to run qemu with
/// `-device isa-kdebug-exit` and write a message (0x31) to a port (0x501). Port I/O is a weird kernel-y
/// thing, but just realize that:
/// * ioperm gives us permission to write to port 0x501
/// * outb writes a byte (0x31) to that port
///
/// The byte we pass is doubled and incremented to build an exit code.
///
/// # Safety
///
/// This function is marked as `unsafe` because writing to arbitrary port is dangerous.
pub unsafe fn shutdown<T>(res: KResult<T>) -> ! {
    kinfo!("shuwdown(): The system is about to shutdown...");
    match res {
        Ok(_) => {
            Port::new(0xb004).write(0x0u8);
        }
        Err(errno) => {
            // Qemu's exit code is double the value plus one.
            let num = error_to_int(&res) * 2 + 1;
            Port::new(0x501).write(num as u8);
        }
    }

    loop {}
}
