//! The x2APIC (Extended xAPIC) is an advanced local Advanced Programmable Interrupt Controller (APIC) architecture
//! designed by Intel for modern processors. It is an extension of the original xAPIC architecture and provides enhanced
//! performance, scalability, and reliability for interrupt handling in multi-core processors.
//!
//! The x2APIC provides several improvements over the previous xAPIC architecture, including a larger interrupt vector
//! table, improved interrupt delivery mechanisms, and increased flexibility in interrupt routing. It also allows for the
//! distribution of interrupts among multiple processors, improving overall system performance and reducing latency.

use core::sync::atomic::Ordering;

use x86::msr::{
    rdmsr, wrmsr, IA32_APIC_BASE, IA32_X2APIC_APICID, IA32_X2APIC_CUR_COUNT, IA32_X2APIC_DIV_CONF,
    IA32_X2APIC_EOI, IA32_X2APIC_ICR, IA32_X2APIC_INIT_COUNT, IA32_X2APIC_LVT_TIMER,
    IA32_X2APIC_SIVR, IA32_X2APIC_VERSION,
};

use crate::{
    arch::{apic::disable_irq, interrupt::timer::APIC_UP, pit::countdown},
    error::KResult,
};

use super::{ApicInfo, ApicSupport, ApicType};

pub struct X2Apic;

impl ApicSupport for X2Apic {
    /// Initialize the X2Apic on the target CPU.
    fn init(&self) {
        unsafe {
            let x2apic_enable = rdmsr(IA32_APIC_BASE) | 1 << 10;
            wrmsr(IA32_APIC_BASE, x2apic_enable);
            wrmsr(IA32_X2APIC_SIVR, 0x100);
        }
    }

    fn get_info(&self) -> ApicInfo {
        unsafe {
            ApicInfo {
                id: rdmsr(IA32_X2APIC_APICID) as u32,
                version: rdmsr(IA32_X2APIC_VERSION) as u32,
            }
        }
    }

    fn eoi(&self) {
        unsafe {
            wrmsr(IA32_X2APIC_EOI, 0x0);
        }
    }

    fn set_icr(&self, icr: u64) {
        unsafe {
            wrmsr(IA32_X2APIC_ICR, icr);
        }
    }

    fn send_ipi(&self, target: u8, val: u8) {
        self.set_icr((target as u64) << 32 | val as u64 | 1 << 14);
    }

    fn ty(&self) -> ApicType {
        ApicType::X2Apic
    }

    fn init_timer(&self) -> KResult<()> {
        unsafe {
            // Measure the bus frequency for a fixed time interval.
            // This time we use PIT temporarrily.
            x86_64::instructions::interrupts::without_interrupts(|| {
                // Tell APIC timer to use divider 16.
                wrmsr(IA32_X2APIC_DIV_CONF, 0x3);
                // Set the initial count to -1.
                wrmsr(IA32_X2APIC_INIT_COUNT, 0xFFFFFFFF);

                // wait for 10 ms.
                countdown(10000);

                APIC_UP.store(true, Ordering::Release);
                // Stop the timer so that we can read from it.
                wrmsr(IA32_X2APIC_LVT_TIMER, 0x10000);
                let apic_timer_current = 0xFFFFFFFF - rdmsr(IA32_X2APIC_CUR_COUNT);
                // Now we know how often the APIC timer has ticked in 10ms.

                // Start timer as periodic on IRQ 0, divider 16, with the number of ticks we counted
                wrmsr(IA32_X2APIC_LVT_TIMER, 0x20 | 0x20000);
                wrmsr(IA32_X2APIC_DIV_CONF, 0x3);
                wrmsr(IA32_X2APIC_INIT_COUNT, apic_timer_current);

                kinfo!("successfully initialized APIC timer.");

                // Disable the old PIT and switches to APIC timer.
                // This time, IRQ 0 is automatically reigstered for APIC timer.
                disable_irq(0x0);
            });
        }
        Ok(())
    }
}
