use raw_cpuid::CpuId;
use x86::apic::xapic;

use super::LocalApic;

/// The extended Advanced Programmable Interrupt Controller.
/// Unlink X2APIC, this controller's base address must be manually provided.
pub struct XApic {
    base_addr: usize,
}

impl XApic {
    pub fn new(base_addr: usize) -> Self {
        Self { base_addr }
    }

    fn write(&mut self, reg: u32, val: u32) {
        unsafe { core::ptr::write_volatile((self.base_addr + reg as usize) as *mut u32, val) }
    }

    fn read(&self, reg: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.base_addr + reg as usize) as *const u32) }
    }
}

impl LocalApic for XApic {
    fn does_cpu_support() -> bool {
        CpuId::new().get_feature_info().unwrap().has_apic()
    }

    fn cpu_init(&mut self) {
        // Registers: https://wiki.osdev.org/APIC#:~:text=use%20the%20attack.-,Local%20APIC%20registers,-The%20local%20APIC
        // To enable the APIC, set bit 8 (or 0x100) of the Spurious Interrupt Vector Register.
        self.write(xapic::XAPIC_SVR, 0x100 | (0x20 + 0x1f));
    }

    fn lapic_id(&self) -> u32 {
        self.read(xapic::XAPIC_ID)
    }

    fn lapic_version(&self) -> u32 {
        self.read(xapic::XAPIC_VERSION)
    }
}
