//! A futex (short for "fast userspace mutex") is a kernel system call that programmers can use to implement basic
//! locking, or as a building block for higher-level locking abstractions such as semaphores and POSIX mutexes or
//! condition variables.
//!
//! See also: https://eli.thegreenplace.net/2018/basics-of-futexes/
//!
//! A futex consists of a kernelspace wait queue that is attached to an atomic integer in userspace.
//!
//! Before the introduction of futexes, system calls were required for locking and unlocking shared resources
//! (for example semop). System calls are relatively expensive, however, requiring a context switch from userspace
//! to kernel space; as programs became increasingly concurrent, locks started showing up on profiles as a significant
//! percentage of the run time. This is very unfortunate, given that locks accomplish no real work ("business logic")
//! but are only there to guarantee that access to shared resources is safe.
//!
//! The futex proposal is based on a clever observation: in most cases, locks are actually not contended. If a thread
//! comes upon a free lock, locking it can be cheap because most likely no other thread is trying to lock it at the exact
//! same time. So we can get by without a system call, attemping much cheaper atomic operations first. There's a very high
//! chance that the atomic instruction will succeed.
//!
//! However, in the unlikely event that another thread did try to take the lock at the same time, the atomic approach may
//! fail. In this case there are two options. We can busy-loop using the atomic until the lock is cleared; while this is
//! 100% userspace, it can also be extremely wasteful since looping can significantly occupy a core, and the lock can be
//! held for a long time. The alternative is to "sleep" until the lock is free (or at least there's a high chance that
//! it's free); we need the kernel to help with that, and this is where futexes come in (kernel wakes up the sleeper).
//!
//! The implementation is simple. Futex is just a deque holding a bunch of threads (either awake or sleeping) and a Mutex
//! protected counter, and this can be simplified into a Mutex-protected deque. Wake is to pop out each thread from the
//! deque in an FIFO way; wait is to put the current thread into a sleeping status and push it onto the deque. We do not
//! want to block the execution, so we can implement the wait method as a `Future` that returns something asynchronously.

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

use alloc::{collections::VecDeque, sync::Arc};
use log::warn;

use crate::{
    arch::{interrupt::timer::TRIGGER, timer::rdtsc_timer},
    error::{Errno, KResult},
    sync::mutex::SpinLock as Mutex,
};

pub type SimpleFutex = Futex<()>;

/// Basically, [`Futex`] is just a simple wrapper for [`Mutex`].
pub struct Futex<T>
where
    T: Send + Sync,
{
    /// The address.
    pub uaddr: u64,
    /// The inner protected area.
    pub futex_impl: Mutex<FutexImpl<T>>,
}

/// The operation type for [`Futex`] operations. We only support two basic ones.
#[derive(Clone, Copy, Debug)]
pub enum OpType {
    /// This operation wakes at most val of the waiters that are waiting.
    FutexWake,
    /// This operation tests that the value at the futex word pointed to by the address uaddr still contains the
    /// expected value val, and if so, then sleeps waiting for a [`FutexWake`] operation on the futex word.
    FutexWait,
}

/// The 'real' implementation of the Futex. We do a trick here: there is no need to actually guard some data `T`; in fact,
/// the only thing meaningful is an atomic counter that serves as a 'lock' that locks the address.
pub struct FutexImpl<T>
where
    T: Send + Sync,
{
    /// Wait queue.
    wait_queue: VecDeque<Arc<Mutex<Thread<T>>>>,
}

/// Other threads that try to enter/leave the region guarded by the [`Futex`].
pub struct Thread<T>
where
    T: Send + Sync,
{
    /// Whether or not the current one is sleeping?
    sleeping: bool,
    /// Possible self-referencing problem?
    futex: Arc<Futex<T>>,
    /// Who is reponsible to wake it up. If it is [`None`] and it is sleeping, then the thread may be dead.
    waker: Option<Waker>,
}

pub(crate) struct FutexFuture<T>
where
    T: Send + Sync,
{
    /// Each thread can only be accessed by one thread! So we wrap it with a [`Mutex`].
    thread: Arc<Mutex<Thread<T>>>,
    timeout: Option<Duration>,
}

impl<T> Future for FutexFuture<T>
where
    T: Send + Sync,
{
    /// This future always returns a system result indicating success or failure with an [`Errno`].
    type Output = KResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut current_thread = self.thread.lock();

        // Check if the thread is not sleeping.
        if !current_thread.sleeping {
            return Poll::Ready(Ok(0));
        }

        // Check duration.
        let now = rdtsc_timer();
        if let Some(timeout) = self.timeout {
            if timeout <= now {
                // Immediately return a `EWOULDBLOCK` status and wake it up.
                current_thread.sleeping = true;
                return Poll::Ready(Err(Errno::EAGAIN));
            }
        }

        // Otherwise let the waker take control of the thread.
        if current_thread.waker.is_none() {
            let mut futex = current_thread.futex.futex_impl.lock();
            futex.wait_queue.push_back(self.thread.clone());
            drop(futex);

            current_thread.waker = Some(cx.waker().clone());

            if let Some(timeout) = self.timeout {
                let waker = cx.waker().clone();
                TRIGGER.lock().add(timeout, move |_| waker.wake());
            }
        }

        Poll::Pending
    }
}

impl<T> Futex<T>
where
    T: Send + Sync,
{
    /// Creates a new [`FutexImpl`].
    pub fn new(uaddr: u64) -> Self {
        Self {
            uaddr,
            futex_impl: Mutex::new(FutexImpl {
                wait_queue: VecDeque::new(),
            }),
        }
    }

    /// Wake up the waiting threads. `val` means how many threads should be awaken. Returns the number of holders
    /// that are successfullly awaken.
    pub fn futex_wake(&self, val: usize) -> usize {
        let mut futex = self.futex_impl.lock();
        let mut waked = 0usize;

        // We pop out each thread in an FIFO way.
        while let Some(thread) = futex.wait_queue.pop_front() {
            let mut thread = thread.lock();
            if thread.sleeping {
                // Check if it has waker.
                if let Some(waker) = thread.waker.take() {
                    waker.wake();
                    thread.sleeping = false;
                    waked += 1;

                    if waked == val {
                        break;
                    }
                } else {
                    warn!(
                      "futext_wake(): thread at {:#p} is sleeping but has no waker?! This would unnecessarily consume resources.",
                      &thread
                  );
                }
            }
        }

        waked
    }

    /// Tell a `thread` to wait for `timeout` time. This function returns a [`core::future::Future`] carrying the
    /// result of the futex wait operation; since this is non-blocking, the only reasonable way is to use async.
    /// Thread which polls this future is the waker for the sleeping thread the future represents.
    fn futex_wait(
        futex: &Arc<Self>,
        timeout: Option<Duration>,
    ) -> impl Future<Output = KResult<usize>> {
        FutexFuture {
            thread: Arc::new(Mutex::new(Thread {
                sleeping: false,
                futex: futex.clone(),
                waker: None,
            })),
            timeout: timeout.map(|timeout| timeout + rdtsc_timer()),
        }
    }
}
