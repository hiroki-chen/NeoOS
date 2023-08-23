//! This module implements high-level timing functions and structs, which mimicks a
//! subset of `std:time` module in Rust standard library.
//!
use core::fmt::Display;
pub use core::time::Duration;

use chrono::prelude::*;

use crate::{
    arch::timer::rdtsc_timer,
    drivers::rtc,
    error::{Errno, KResult},
};
pub const UNIX_EPOCH: SystemTime = SystemTime(Duration::from_secs(0));

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Instant(Duration);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct SystemTime(Duration);

/// A measurement of a monotonically nondecreasing clock. Opaque and useful only with Duration.
///
/// Note, however, that instants are not guaranteed to be steady. In other words, each tick of the
/// underlying clock might not be the same length (e.g. some seconds may be longer than others). An
/// instant may jump forwards or experience time dilation (slow down or speed up), but it will never go
/// *backwards*.
impl Instant {
    /// Constructs a tiempoint from now.
    pub fn now() -> Self {
        Instant(rdtsc_timer())
    }

    /// Calculate the elaped time.
    pub fn elapsed(&self) -> Duration {
        let now = rdtsc_timer();
        Duration::from_nanos(now.as_nanos() as u64 - self.0.as_nanos() as u64)
    }
}

impl SystemTime {
    /// System time( date command) is rtc time, but date application may not go to HW to get the time from RTC.
    pub fn now() -> Self {
        SystemTime(rtc::read_clock().unwrap_or(Duration::from_secs(0)))
    }

    pub fn duration_since(&self, earlier: SystemTime) -> KResult<Duration> {
        match self.0.checked_sub(earlier.0) {
            Some(d) => Ok(d),
            None => Err(Errno::EINVAL),
        }
    }
}

impl Display for SystemTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let seconds = self.0.as_secs();

        let dt = NaiveDateTime::from_timestamp_opt(seconds as i64, 0).unwrap();
        let datetime: DateTime<Utc> = DateTime::from_utc(dt, Utc);
        let newdate = datetime.format("%Y-%m-%dT%H:%M:%SZ");
        write!(f, "{}", newdate)
    }
}
