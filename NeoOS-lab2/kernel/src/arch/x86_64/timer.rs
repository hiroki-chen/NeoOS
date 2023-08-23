use core::{sync::atomic::Ordering, time::Duration};

use atomic_enum::atomic_enum;
use lazy_static::lazy_static;

use crate::error::{Errno, KResult};

use super::{
    apic::LOCAL_APIC,
    cpu::{cpu_id, CPU_FREQUENCY},
};

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
        _ => LOCAL_APIC.read().get(&cpu_id()).unwrap().init_timer(),
    }
}
