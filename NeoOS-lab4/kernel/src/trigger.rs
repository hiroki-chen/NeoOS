//! A trigger primitive that executes a callback upon timeout.

use core::{cmp::Ordering, time::Duration};

use alloc::{boxed::Box, collections::BinaryHeap};

struct CallbackWrapper {
    endtime: Duration,
    callback: Callback,
}

#[derive(Default)]
pub struct Trigger {
    callbacks: BinaryHeap<CallbackWrapper>,
}

pub type Callback = Box<dyn FnOnce(Duration) + Send + Sync + 'static>;

impl Trigger {
    /// Add a timer.
    ///
    /// The `callback` will be called on timer expired after `endtime`.
    pub fn add(
        &mut self,
        endtime: Duration,
        callback: impl FnOnce(Duration) + Send + Sync + 'static,
    ) {
        let cw = CallbackWrapper {
            endtime,
            callback: Box::new(callback),
        };
        self.callbacks.push(cw);
    }

    /// Expire timers.
    ///
    /// Given the current time `now`, trigger and remove all expired timers.
    pub fn expire(&mut self, now: Duration) {
        while let Some(t) = self.callbacks.peek() {
            if t.endtime > now {
                break;
            }
            let cw = self.callbacks.pop().unwrap();
            (cw.callback)(now);
        }
    }

    /// Get next timer.
    pub fn next(&self) -> Option<Duration> {
        self.callbacks.peek().map(|e| e.endtime)
    }
}

impl PartialEq for CallbackWrapper {
    fn eq(&self, other: &Self) -> bool {
        self.endtime.eq(&other.endtime)
    }
}

impl Eq for CallbackWrapper {}

// BinaryHeap is a max-heap. So we need to reverse the order.
impl PartialOrd for CallbackWrapper {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.endtime.partial_cmp(&self.endtime)
    }
}

impl Ord for CallbackWrapper {
    fn cmp(&self, other: &CallbackWrapper) -> Ordering {
        other.endtime.cmp(&self.endtime)
    }
}
