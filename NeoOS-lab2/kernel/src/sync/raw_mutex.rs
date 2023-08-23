//! Raw mutex type backed by the parking lot.

use core::sync::atomic::{AtomicU8, Ordering};

pub struct RawMutex {
    /// This atomic integer holds the current state of the mutex instance. Only the two lowest bits
    /// are used. See `LOCKED_BIT` and `PARKED_BIT` for the bitmask for these bits.
    ///
    /// # State table:
    ///
    /// PARKED_BIT | LOCKED_BIT | Description
    ///     0      |     0      | The mutex is not locked, nor is anyone waiting for it.
    /// -----------+------------+------------------------------------------------------------------
    ///     0      |     1      | The mutex is locked by exactly one thread. No other thread is
    ///            |            | waiting for it.
    /// -----------+------------+------------------------------------------------------------------
    ///     1      |     0      | The mutex is not locked. One or more thread is parked or about to
    ///            |            | park. At least one of the parked threads are just about to be
    ///            |            | unparked, or a thread heading for parking might abort the park.
    /// -----------+------------+------------------------------------------------------------------
    ///     1      |     1      | The mutex is locked by exactly one thread. One or more thread is
    ///            |            | parked or about to park, waiting for the lock to become available.
    ///            |            | In this state, PARKED_BIT is only ever cleared when a bucket lock
    ///            |            | is held (i.e. in a parking_lot_core callback). This ensures that
    ///            |            | we never end up in a situation where there are parked threads but
    ///            |            | PARKED_BIT is not set (which would result in those threads
    ///            |            | potentially never getting woken up).
    state: AtomicU8,
}

impl RawMutex {
    #[inline]
    pub fn locked(&self) -> bool {
        self.state.load(Ordering::Relaxed) & 0x1 != 0
    }

    #[inline]
    pub fn parked(&self) -> bool {
        self.state.load(Ordering::Relaxed) & 0x2 != 0
    }

    #[inline]
    pub fn unpark(&mut self) {
        let state = self.state.load(Ordering::Relaxed);
        self.state.store(state & 0x1, Ordering::Relaxed)
    }

    #[inline]
    pub fn unlock(&mut self) {
        let state = self.state.load(Ordering::Relaxed);
        self.state.store(state & 0x2, Ordering::Relaxed)
    }
}
