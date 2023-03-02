//! Some helper functions for hanlding x2APIC, xAPIC, as well as IOAPIC.

#[cfg(feature = "multiprocessor")]
use acpi::{madt::Madt, AcpiHandler, PhysicalMapping};

use apic::{IoApic, X2Apic, XApic, IOAPIC_ADDR};
use log::info;

use crate::{arch::interrupt::ISA_TO_GSI, error::KResult, memory::phys_to_virt};

use super::{cpu::cpu_feature_info, interrupt::IRQ_MIN};

pub trait AcpiSupport {
    /// Checks if CPU supports the target feature.
    fn does_cpu_support() -> bool;
}

impl AcpiSupport for X2Apic {
    fn does_cpu_support() -> bool {
        cpu_feature_info()
            .expect("does_cpu_support(): failed to fetch CPU feature information")
            .has_x2apic()
    }
}

impl AcpiSupport for XApic {
    fn does_cpu_support() -> bool {
        cpu_feature_info()
            .expect("does_cpu_support(): failed to fetch CPU feature information")
            .has_apic()
    }
}

pub fn get_gsi(irq: u64) -> u8 {
    let mapping = ISA_TO_GSI.read();

    match mapping.get(&(irq as u8)) {
        None => irq as u8,
        Some(&pin) => pin as u8,
    }
}

/// Registers the interrupt request into IOAPIC.
pub fn enable_irq(irq: u64) {
    info!("enable_irq(): enabling {irq}");

    let mut ioapic = unsafe { IoApic::new(phys_to_virt(IOAPIC_ADDR as u64) as usize) };
    let apic_pin = get_gsi(irq);
    ioapic.set_irq_vector(apic_pin, (IRQ_MIN + irq as usize) as u8);
    ioapic.enable(apic_pin, 0);
}

pub fn disable_irq(irq: u64) {
    let mut ioapic = unsafe { IoApic::new(phys_to_virt(IOAPIC_ADDR as u64) as usize) };
    let apic_pin = get_gsi(irq);
    ioapic.disable(apic_pin);
}

#[cfg(feature = "multiprocessor")]
#[allow(unused_variables)]
pub fn init_aps<H>(madt: &PhysicalMapping<H, Madt>) -> KResult<()>
where
    H: AcpiHandler,
{
    use core::{ffi::c_void, sync::atomic::Ordering};

    use acpi::madt::{EntryHeader, LocalApicEntry, MadtEntry};
    use log::debug;

    use crate::{
        arch::{
            acpi::{AP_STARTUP, AP_TRAMPOLINE_CODE},
            boot::_start_ap,
            cpu::{ApHeader, CPU_COUNT},
            interrupt::ipi::{send_init_ipi, send_startup_ipi},
            mm::paging::KernelPageTable,
            PAGE_SIZE,
        },
        memory::{allocate_frame_contiguous, read_at},
    };

    info!("init_aps(): initializing APs.");

    // Fill data into that address.
    unsafe {
        // AP believe that it is running in real mode (i.e., 0x0000 - 0xffff).
        let ap_trampoline_addr = phys_to_virt(AP_STARTUP);

        AP_TRAMPOLINE_CODE.iter().enumerate().for_each(|(idx, d)| {
            core::intrinsics::atomic_store_seqcst((ap_trampoline_addr as *mut u8).add(idx), *d);
        });

        // From now on, the ap trampoline code is at 0x10000.
        for item in madt.entries() {
            // First check if the APIC id is 0 (self).
            if let MadtEntry::LocalApic(lapic) = item {
                // LocalX2ApicEntry contains all private field and we want to break this constraint.
                // Becauset this struct is also borrowed (i.e., read from raw memory represented by the rsdt pointer),
                // it is 'safe' to cast it back to raw pointer and read something from it.
                let p_lapic = lapic as *const LocalApicEntry as *const c_void;
                let offset = core::mem::size_of::<EntryHeader>();
                let apic_id = read_at::<u8>(p_lapic, offset);
                info!("init_aps(): parsing CPU {:#x}", apic_id);

                if *apic_id == 0x0 {
                    info!("init_aps(): it is BSP; skip.");
                } else {
                    // Initialize the AP.
                    let ap_header_addr =
                        phys_to_virt(AP_STARTUP) + core::mem::size_of::<u64>() as u64;
                    let ap_header = &mut *(ap_header_addr as *mut u8 as *mut ApHeader);
                    debug!("init_aps(): read header {:#x?}", ap_header);
                    // Allocate stack frames for the AP.
                    let ap_stack_frame = allocate_frame_contiguous(0x40, 0)?;
                    let stack_bottom = phys_to_virt(ap_stack_frame.as_u64());
                    let stack_top = stack_bottom + 0x40 * PAGE_SIZE as u64;
                    let page_table = KernelPageTable::active()
                        .page_table_frame
                        .start_address()
                        .as_u64();

                    CPU_COUNT.fetch_add(0x1, Ordering::SeqCst);
                    core::intrinsics::atomic_store_seqcst(&mut ap_header.ready as *mut _, 0u64);
                    core::intrinsics::atomic_store_seqcst(
                        &mut ap_header.cpu_id as *mut _,
                        *apic_id as u64,
                    );
                    core::intrinsics::atomic_store_seqcst(
                        &mut ap_header.trampoline_code as *mut _,
                        _start_ap as u64,
                    );
                    core::intrinsics::atomic_store_seqcst(
                        &mut ap_header.stack_top as *mut _,
                        stack_top,
                    );
                    core::intrinsics::atomic_store_seqcst(
                        &mut ap_header.stack_bottom as *mut _,
                        stack_bottom,
                    );
                    core::intrinsics::atomic_store_seqcst(
                        &mut ap_header.page_table as *mut _,
                        page_table,
                    );

                    debug!("init_aps(): filled {:#x?}", ap_header);

                    // Send init IPI.
                    send_init_ipi(*apic_id as _);
                    // Send startup IPI.
                    send_startup_ipi(*apic_id as _);
                }
            }
        }
    }
    info!("init_aps(): successfully initialized APs.");

    Ok(())
}
