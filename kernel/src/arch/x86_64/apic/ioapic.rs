//! There are two components in the Intel APIC system, the local APIC (LAPIC) and the I/O APIC.
//! There is one LAPIC in each CPU in the system. In the very first implementation.

pub const IOAPIC_DEFAULT_ADDR: usize = 0xFEC00000;

/// The IO APIC uses two registers for most of its operation - an address register at IOAPICBASE+0 and a data register at IOAPICBASE+0x10.
/// All accesses must be done on 4 byte boundaries. The address register uses the bottom 8 bits for register select.
pub struct IOApic {
    /// The last used register.
    reg: *mut u32,
    /// The last value stored in the register.
    val: *mut u32,
}

impl IOApic {
    /// Construct a new `IOApic` instance given its base address.
    ///
    /// The caller must ensure that `base_addr` is always valid.
    pub unsafe fn new(base_addr: u32) -> Self {
        Self {
            reg: base_addr as *mut u32,
            val: (base_addr + 0x10) as *mut u32,
        }
    }
}
