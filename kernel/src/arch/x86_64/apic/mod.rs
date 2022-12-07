//! Most (all) Intel-MP compliant SMP boards have the so-called ‘IO-APIC’, which is an enhanced interrupt controller.
//! It enables us to route hardware interrupts to multiple CPUs, or to CPU groups. Without an IO-APIC, interrupts from
//! hardware will be delivered only to the CPU which boots the operating system (usually CPU#0).

pub mod ioapic;
pub mod x2apic;
pub mod xapic;

pub const IA32_APIC_BASE_MSR_ENABLE: u16 = 1 << 10;

/// Configure the local APIC. From: https://www.naic.edu/~phil/software/intel/318148.pdf
/// ```C
///   #define IA32_APIC_BASE_MSR 0x1B
///   #define IA32_APIC_BASE_MSR_BSP 0x100 // Processor is a BSP
///   #define IA32_APIC_BASE_MSR_ENABLE 0x800
/// ```
/// Local APICs (LAPICs) manage all external interrupts for some specific processor in an SMP system.
pub trait LocalApic {
    /// Returns true if the CPU supports this specific type of APIC.
    fn does_cpu_support() -> bool;

    /// Initialize the APIC on the CPU.
    /// System software can place the local APIC in the x2APIC mode by setting the
    /// x2APIC mode enable bit (bit 10) in the IA32_APIC_BASE MSR at MSR address 01BH.
    fn cpu_init(&mut self);

    /// Get the id of the local apic because LAPIC is set for each core.
    fn lapic_id(&self) -> u32;

    /// Get the version.
    fn lapic_version(&self) -> u32;
}
