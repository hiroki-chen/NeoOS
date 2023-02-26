//! Handles timer interrupt 0x00.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use lazy_static::lazy_static;

use crate::{
    arch::{
        cpu::{cpu_id, MEASURE_DONE},
        timer::rdtsc_timer,
    },
    sync::mutex::SpinLockNoInterrupt as Mutex,
    trigger::Trigger,
};

pub static TICK: AtomicUsize = AtomicUsize::new(0usize);
pub static TICK_WALL: AtomicUsize = AtomicUsize::new(0usize);
pub static APIC_UP: AtomicBool = AtomicBool::new(false);

lazy_static! {
    /// A clock that will trigger the callback if the given time ends.
    pub static ref TRIGGER: Mutex<Trigger> = Mutex::new(Trigger::default());
}

pub fn handle_timer() {
    if cpu_id() == 0x0 {
        TICK.fetch_add(0x1, Ordering::Release);

        if !MEASURE_DONE.load(Ordering::Acquire) {
            MEASURE_DONE.store(true, Ordering::Release);
        }
    }
    // Do tick.
    TICK_WALL.fetch_add(0x1, Ordering::Relaxed);

    if APIC_UP.load(Ordering::Relaxed) {
        // FIXME: use apic timer?
        TRIGGER.lock().expire(rdtsc_timer());
    } else {
        if cpu_id() == 0x0 {
            TICK.fetch_add(0x1, Ordering::Release);
        }
    }
}
