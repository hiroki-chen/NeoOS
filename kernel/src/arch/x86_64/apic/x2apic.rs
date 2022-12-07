use raw_cpuid::CpuId;
use x86::msr::{
    rdmsr, wrmsr, IA32_APIC_BASE, IA32_X2APIC_APICID, IA32_X2APIC_SIVR, IA32_X2APIC_VERSION,
};

use super::{LocalApic, IA32_APIC_BASE_MSR_ENABLE};

/// The second-generation extended Advanced Programmable Interrupt Controller.
pub struct X2Apic;

impl LocalApic for X2Apic {
    fn does_cpu_support() -> bool {
        CpuId::new().get_feature_info().unwrap().has_x2apic()
    }

    fn cpu_init(&mut self) {
        // Set the physical address for local APIC registers.
        // We first need to rdmsr for this information.
        // This register holds the APIC base address, permitting the relocation of the APIC memory map.
        let base_addr = unsafe { rdmsr(IA32_APIC_BASE) } as u32 | IA32_APIC_BASE_MSR_ENABLE as u32;
        // We need to write to the MSR. Note that `IA32_APIC_BASE` is set by the hardware, and we cannot modify it.
        unsafe {
            wrmsr(IA32_APIC_BASE, base_addr as u64);
            wrmsr(IA32_X2APIC_SIVR, 0x100);
        }
    }

    fn lapic_id(&self) -> u32 {
        unsafe { rdmsr(IA32_X2APIC_APICID) as u32 }
    }

    fn lapic_version(&self) -> u32 {
        unsafe { rdmsr(IA32_X2APIC_VERSION) as u32 }
    }
}
