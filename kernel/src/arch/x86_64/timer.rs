use core::{sync::atomic::Ordering, time::Duration};

use atomic_enum::atomic_enum;
use lazy_static::lazy_static;
use x86::msr::{
    rdmsr, wrmsr, IA32_X2APIC_CUR_COUNT, IA32_X2APIC_DIV_CONF, IA32_X2APIC_INIT_COUNT,
    IA32_X2APIC_LVT_TIMER,
};

use crate::{
    arch::{apic::disable_irq, interrupt::timer::APIC_UP, pit::countdown},
    error::{Errno, KResult},
};

use super::cpu::CPU_FREQUENCY;

/// Local APIC timer modes.
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum TimerMode {
    /// Timer only fires once.
    OneShot = 0b00,
    /// Timer fires periodically.
    Periodic = 0b01,
    /// Timer fires at an absolute time.
    TscDeadline = 0b10,
}

/// Local APIC timer divide configurations.
///
/// Defines the APIC timer frequency as the processor frequency divided by a
/// specified value.
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum TimerDivide {
    /// Divide by 2.
    Div2 = 0b0000,
    /// Divide by 4.
    Div4 = 0b0001,
    /// Divide by 8.
    Div8 = 0b0010,
    /// Divide by 16.
    Div16 = 0b0011,
    /// Divide by 32.
    Div32 = 0b1000,
    /// Divide by 64.
    Div64 = 0b1001,
    /// Divide by 128.
    Div128 = 0b1010,
    /// Divide by 256.
    Div256 = 0b1011,
}

lazy_static! {
    pub static ref TIMER_SOURCE: AtomicTimerSource = AtomicTimerSource::new(TimerSource::Rdtsc);
}

#[repr(u8)]
#[derive(PartialEq, Eq, PartialOrd, Ord)]
#[atomic_enum]
pub enum TimerSource {
    Rdtsc = 0,
    Apic = 1,
    Hpet = 2,
}

/// The TSC is the preferred clocksource between the two counters, as it is the fastest one,
/// however it can only be used if it is stable.
pub fn rdtsc_timer() -> Duration {
    // Get the frequency of the CPU.
    let freq = *CPU_FREQUENCY.get().unwrap();
    let rdtsc = unsafe { core::arch::x86_64::_rdtsc() };

    Duration::from_nanos(((rdtsc * 1000) as f64 / freq).round() as u64)
}

pub fn init_apic_timer() -> KResult<()> {
    let timer_source = TIMER_SOURCE.load(Ordering::Acquire);

    match timer_source {
        TimerSource::Hpet => {
            kerror!("init_apic_timer(): The timer source is at higher priority!");
            Err(Errno::EINVAL)
        }
        _ => {
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

                    kinfo!("init_apic_timer(): successfully initialized APIC timer.");

                    // Disable the old PIT and switches to APIC timer.
                    // This time, IRQ 0 is automatically reigstered for APIC timer.
                    disable_irq(0x0);
                });
            }

            Ok(())
        }
    }
}
