use acpi::{madt::Madt, AcpiHandler, PhysicalMapping};
use core::{ffi::c_void, sync::atomic::Ordering};

use acpi::madt::{EntryHeader, LocalApicEntry, MadtEntry};

use crate::{
    arch::{
        acpi::{AP_STARTUP, AP_TRAMPOLINE_CODE},
        boot::_start_ap,
        cpu::{ApHeader, CPU_NUM},
        interrupt::ipi::{send_init_ipi, send_startup_ipi},
        mm::paging::{KernelPageTable, PageTableBehaviors},
        PAGE_SIZE,
    },
    error::KResult,
    memory::{allocate_frame_contiguous, atomic_memset, phys_to_virt, read_at},
};

pub fn init_aps<H>(madt: &PhysicalMapping<H, Madt>) -> KResult<()>
where
    H: AcpiHandler,
{
    kinfo!("init_aps(): initializing APs.");

    // Fill data into that address.
    unsafe {
        // AP believe that it is running in real mode (i.e., 0x0000 - 0xffff).
        let ap_trampoline_addr = phys_to_virt(AP_STARTUP);

        AP_TRAMPOLINE_CODE.iter().enumerate().for_each(|(idx, d)| {
            core::intrinsics::atomic_store_seqcst((ap_trampoline_addr as *mut u8).add(idx), *d);
        });

        // Map the trampoline page.
        let ap_trampoline_frame = phys!(AP_STARTUP);
        let ap_trampoline_page = virt!(AP_STARTUP);
        KernelPageTable::active()
            .map(ap_trampoline_page, ap_trampoline_frame)
            .update();

        // Get CPU numbers.
        CPU_NUM.call_once(|| {
            madt.entries()
                .filter(|entry| matches!(entry, MadtEntry::LocalApic(_)))
                .count()
        });

        for item in madt.entries() {
            // First check if the APIC id is 0 (self).
            if let MadtEntry::LocalApic(lapic) = item {
                // LocalX2ApicEntry contains all private field and we want to break this constraint.
                // Becauset this struct is also borrowed (i.e., read from raw memory represented by the rsdt pointer),
                // it is 'safe' to cast it back to raw pointer and read something from it.
                let p_lapic = lapic as *const LocalApicEntry as *const c_void;
                let offset = core::mem::size_of::<EntryHeader>();
                let apic_id = read_at::<u8>(p_lapic, offset);
                kinfo!("init_aps(): parsing CPU {:#x}", apic_id);

                if *apic_id == 0x0 {
                    kinfo!("init_aps(): it is BSP; skip.");
                } else {
                    // Initialize the AP.
                    let ap_header_addr =
                        phys_to_virt(AP_STARTUP) + core::mem::size_of::<u64>() as u64;
                    // Make sure the header is cleared. This is done by writing zeros to that address.
                    let ap_header = &mut *(ap_header_addr as *mut u8 as *mut ApHeader);
                    atomic_memset::<ApHeader>(ap_header_addr as *mut _, 0u8, Ordering::SeqCst);

                    // Check header.
                    if !ap_header.sanity_check() {
                        kerror!("init_aps(): AP {:#x} contains corrupted header!", *apic_id);
                        continue;
                    }

                    // Allocate stack frames for the AP.
                    let ap_stack_frame = allocate_frame_contiguous(0x40, 0)?;
                    let stack_bottom = phys_to_virt(ap_stack_frame.as_u64());
                    let stack_top = stack_bottom + 0x40 * PAGE_SIZE as u64;
                    let page_table = KernelPageTable::active()
                        .page_table_frame
                        .start_address()
                        .as_u64();

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

                    kdebug!("init_aps(): filled {:#x?}", ap_header);

                    // Send init IPI.
                    send_init_ipi(*apic_id as _);
                    // Send startup IPI.
                    send_startup_ipi(*apic_id as _);
                    // Wait.
                    while core::intrinsics::atomic_load_seqcst(&mut ap_header.ready as *mut u64)
                        == 0
                    {
                        core::hint::spin_loop();
                    }
                }
            }
        }
    }
    kinfo!("init_aps(): successfully initialized APs.");

    Ok(())
}
