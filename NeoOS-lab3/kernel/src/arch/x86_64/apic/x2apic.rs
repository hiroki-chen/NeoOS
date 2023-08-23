//! The x2APIC (Extended xAPIC) is an advanced local Advanced Programmable Interrupt Controller (APIC) architecture
//! designed by Intel for modern processors. It is an extension of the original xAPIC architecture and provides enhanced
//! performance, scalability, and reliability for interrupt handling in multi-core processors.
//!
//! The x2APIC provides several improvements over the previous xAPIC architecture, including a larger interrupt vector
//! table, improved interrupt delivery mechanisms, and increased flexibility in interrupt routing. It also allows for the
//! distribution of interrupts among multiple processors, improving overall system performance and reducing latency.

use x86::msr::{
    rdmsr, wrmsr, IA32_APIC_BASE, IA32_X2APIC_APICID, IA32_X2APIC_EOI, IA32_X2APIC_ICR,
    IA32_X2APIC_SIVR, IA32_X2APIC_VERSION,
};

use crate::arch::cpu::cpu_feature_info;

use super::{AcpiSupport, ApicInfo};

pub struct X2Apic;

impl AcpiSupport for X2Apic {
    fn does_cpu_support() -> bool {
        cpu_feature_info()
            .expect("does_cpu_support(): failed to fetch CPU feature information")
            .has_x2apic()
    }
}

impl X2Apic {
    /// Initialize the X2Apic on the target CPU.
    pub fn init(&self) {
        unsafe {
            let x2apic_enable = rdmsr(IA32_APIC_BASE) | 1 << 10;
            wrmsr(IA32_APIC_BASE, x2apic_enable);
            wrmsr(IA32_X2APIC_SIVR, 0x100);
        }
    }

    pub fn get_info(&self) -> ApicInfo {
        unsafe {
            ApicInfo {
                id: rdmsr(IA32_X2APIC_APICID) as u32,
                version: rdmsr(IA32_X2APIC_VERSION) as u32,
            }
        }
    }

    pub fn eoi(&self) {
        unsafe {
            wrmsr(IA32_X2APIC_EOI, 0x0);
        }
    }

    pub fn send_ipi(&self, target: u8, val: u8) {
        unsafe {
            wrmsr(
                IA32_X2APIC_ICR,
                (target as u64) << 32 | val as u64 | 1 << 14,
            );
        }
    }

    pub fn set_icr(&self, icr: u64) {
        unsafe {
            wrmsr(IA32_X2APIC_ICR, icr);
        }
    }
}
