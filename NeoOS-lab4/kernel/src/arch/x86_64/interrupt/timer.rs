//! Handles timer interrupt 0x00.

use core::{
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};

use lazy_static::lazy_static;

use crate::{
    arch::{
        cpu::{cpu_id, AP_UP_NUM, BSP_ID, CPU_NUM},
        timer::rdtsc_timer,
    },
    process::scheduler::FIFO_SCHEDULER,
    sync::mutex::SpinLockNoInterrupt as Mutex,
    trigger::Trigger,
};

use super::ipi::{send_ipi, IpiType};

/// This tick will continuously increment.
pub static MONOTONIC_TICK: AtomicUsize = AtomicUsize::new(0usize);
/// This tick is used to trigger some event.
pub static TICK: AtomicUsize = AtomicUsize::new(0usize);
pub static TICK_WALL: AtomicUsize = AtomicUsize::new(0usize);
pub static APIC_UP: AtomicBool = AtomicBool::new(false);

lazy_static! {
    /// A clock that will trigger the callback if the given time ends.
    pub static ref TRIGGER: Mutex<Trigger> = Mutex::new(Trigger::default());
}

/// Returns the tick after.
pub fn tick_microsecond() -> Duration {
    let tick = TICK_WALL.load(Ordering::Acquire);
    // Our timer interrupt ticks per 10,000 us.
    Duration::from_micros(10000 * tick as u64)
}

pub fn handle_timer() {
    if cpu_id() == *BSP_ID.get().unwrap_or(&0) as usize {
        MONOTONIC_TICK.fetch_add(0x1, Ordering::Relaxed);
        // Only the primary core can do tick.
        let prev = TICK.fetch_add(0x1, Ordering::Release);
        let ap_num = AP_UP_NUM.load(Ordering::Relaxed);
        let cpu_num = CPU_NUM.get().copied().unwrap_or(1);

        if ap_num == cpu_num - 1 && prev >= 0x2 {
            // Clear the tick.
            TICK.store(0x0, Ordering::SeqCst);
            // Try to do some balance on each core.
            FIFO_SCHEDULER.schedule_tick();
            // Wake up other cores via IPI.
            send_ipi(|| {}, None, false, IpiType::WakeUp);
        }
    }
    // Do tick.
    TICK_WALL.fetch_add(0x1, Ordering::Relaxed);

    if APIC_UP.load(Ordering::Relaxed) {
        TRIGGER.lock().expire(rdtsc_timer());
    }
}
