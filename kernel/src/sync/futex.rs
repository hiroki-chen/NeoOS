//! A futex (short for "fast userspace mutex") is a kernel system call that programmers can use to implement basic
//! locking, or as a building block for higher-level locking abstractions such as semaphores and POSIX mutexes or
//! condition variables.
//!
//! A futex consists of a kernelspace wait queue that is attached to an atomic integer in userspace.

use core::task::Waker;

use alloc::{collections::VecDeque, sync::Arc};

use super::mutex::SpinLockNoInterrupt as Mutex;

pub struct Futex {
    pub futex_inner: Mutex<FutexInner>,
}

impl Futex {
    pub fn new() -> Self {
        Self {
            futex_inner: Mutex::new(FutexInner {
                wait_queue: VecDeque::new(),
            }),
        }
    }

    /// Wakes the queue and returns the number of tasks awaken.
    pub fn futex_wake(&self, num: usize) -> usize {
        for i in 0..num {
            let mut futex_inner = self.futex_inner.lock();

            if let Some(inner) = futex_inner.wait_queue.pop_front() {
                let mut inner = inner.lock();
                inner.awaken = true;

                if let Some(waker) = inner.waker.take() {
                    waker.wake();
                }
            } else {
                // No task, end.
                return i;
            }
        }

        num
    }

    // Waits until someone wakes it.
    // pub fn futex_wait(&self) -> impl Future<Output = KResult<usize>> {
    //     todo!();
    // }
}

pub struct FutexInner {
    // Wait queue.
    wait_queue: VecDeque<Arc<Mutex<WaitType>>>,
}

pub struct WaitType {
    /// A Waker is a handle for waking up a task by notifying its executor that it is ready to be run.
    waker: Option<Waker>,
    awaken: bool,
    futex: Arc<Futex>,
}
