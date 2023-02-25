use core::time::Duration;

use atomic_enum::atomic_enum;
use lazy_static::lazy_static;

use super::cpu::cpu_frequency;

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
pub fn timer() -> Duration {
    // Get the frequency of the CPU.
    let freq = cpu_frequency() as u64;
    let rdtsc = unsafe { core::arch::x86_64::_rdtsc() };

    Duration::from_nanos(rdtsc * 1000 / freq)
}
