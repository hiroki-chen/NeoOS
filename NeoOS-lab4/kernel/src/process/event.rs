use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use bitflags::bitflags;

use crate::sync::mutex::SpinLockNoInterrupt as Mutex;

bitflags! {
    #[derive(Default)]
    pub struct Event: u32 {
        /// File
        const READABLE                      = 1 << 0;
        const WRITABLE                      = 1 << 1;
        const ERROR                         = 1 << 2;
        const CLOSED                        = 1 << 3;

        /// Process
        const PROCESS_QUIT                  = 1 << 10;
        const CHILD_PROCESS_QUIT            = 1 << 11;
        const RECEIVE_SIGNAL                = 1 << 12;

        /// Semaphore
        const SEMAPHORE_REMOVED             = 1 << 20;
        const SEMAPHORE_CAN_ACQUIRE         = 1 << 21;
    }
}

pub type EventCallback = Box<dyn Fn(Event) -> bool + Send>;

#[derive(Default)]
pub struct EventBus {
    event: Event,
    callbacks: Vec<EventCallback>,
}

impl EventBus {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::default()))
    }

    pub fn set(&mut self, set: Event) {
        self.change(Event::empty(), set);
    }

    pub fn clear(&mut self, set: Event) {
        self.change(set, Event::empty());
    }

    pub fn change(&mut self, reset: Event, set: Event) {
        let orig = self.event;
        let mut new = self.event;
        new.remove(reset);
        new.insert(set);
        self.event = new;
        if new != orig {
            self.callbacks.retain(|f| !f(new));
        }
    }

    pub fn subscribe(&mut self, callback: EventCallback) {
        self.callbacks.push(callback);
    }

    pub fn get_callback_len(&self) -> usize {
        self.callbacks.len()
    }
}

pub fn wait_for_event(bus: Arc<Mutex<EventBus>>, mask: Event) -> impl Future<Output = Event> {
    EventBusFuture { bus, mask }
}

struct EventBusFuture {
    bus: Arc<Mutex<EventBus>>,
    mask: Event,
}

impl Future for EventBusFuture {
    type Output = Event;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut lock = self.bus.lock();
        if !(lock.event & self.mask).is_empty() {
            return Poll::Ready(lock.event);
        }
        let waker = cx.waker().clone();
        let mask = self.mask;
        lock.subscribe(Box::new(move |s| {
            if (s & mask).is_empty() {
                return false;
            }
            waker.wake_by_ref();
            true
        }));
        Poll::Pending
    }
}
