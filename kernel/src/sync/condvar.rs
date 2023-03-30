use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use crate::process::{thread::Thread, Process};

use super::mutex::{FlagsGuard, MutexGuard, MutexSupport, SpinLockNoInterrupt as Mutex};

pub struct EpollInfo {
    /// Parent.
    proc: Arc<Mutex<Process>>,
    id: u64,
    epfd: u64,
    fd: u64,
}

/// A Condition Variable
///
/// Condition variables represent the ability to block a thread such that it
/// consumes no CPU time while waiting for an event to occur. Condition
/// variables are typically associated with a boolean predicate (a condition)
/// and a mutex. The predicate is always verified inside of the mutex before
/// determining that thread must block.
///
/// Note that this module places one additional restriction over the system
/// condition variables: each condvar can be used with only one mutex at a
/// time. Any attempt to use multiple mutexes on the same condition variable
/// simultaneously will result in a runtime panic. However it is possible to
/// switch to a different mutex if there are no threads currently waiting on
/// the condition variable.
///
/// Also note that the state is shown in a [`RawMutex`] type. This type needs
/// to be guarded by a [`Mutex`].
pub struct CondVar {
    /// Currently, this raw mutex is just used to ensure sanity.
    // state: AtomicPtr<RawMutex>,
    /// The wait queue.
    queue: Mutex<VecDeque<Arc<Thread>>>,
    /// The epoll queue.
    epoll: Mutex<VecDeque<EpollInfo>>,
}

impl CondVar {
    /// Creates a new condition variable which is ready to be waited on and notified.
    #[inline]
    pub fn new() -> Self {
        Self {
            // state: AtomicPtr::new(core::ptr::null_mut()),
            queue: Mutex::new(VecDeque::new()),
            epoll: Mutex::new(VecDeque::new()),
        }
    }

    #[inline]
    pub fn queue_len(&self) -> usize {
        self.queue.lock().len()
    }

    /// Wakes up one blocked thread on this condvar.
    ///
    /// Returns whether a thread was woken up.
    ///
    /// If there is a blocked thread on this condition variable, then it will
    /// be woken up from its call to `wait` or `wait_timeout`. Calls to
    /// `notify_one` are not buffered in any way.
    ///
    /// To wake up all threads, see `notify_all()`.
    pub fn notify_one(&self) -> bool {
        let mut queue = self.queue.lock();
        if let Some(thread) = queue.pop_front() {
            // Call the callback.
            self.call(&thread);

            if queue.is_empty() {}

            true
        } else {
            false
        }
    }

    /// Wakes up all blocked threads on this condvar.
    ///
    /// Returns the number of threads woken up.
    ///
    /// This method will ensure that any current waiters on the condition
    /// variable are awoken. Calls to `notify_all()` are not buffered in any
    /// way.
    ///
    /// To wake up only one thread, see `notify_one()`.
    pub fn notify_all(&self) -> bool {
        kinfo!("notifying all!!!");
        let mut queue = self.queue.lock();
        while let Some(thread) = queue.pop_front() {
            self.call(&thread);
        }

        true
    }

    /// Park current thread and wait for this condvar to be notified.
    #[inline]
    pub fn wait<'a, T, S>(&self, guard: MutexGuard<'a, T, S>) -> MutexGuard<'a, T, S>
    where
        S: MutexSupport,
    {
        let mutex = guard.mutex;
        self.queue.lock();
        mutex.lock()
    }

    /// Parks current thread and wait for a condition to be true.
    pub fn wait_while<F, T>(condvar: &Self, predicate: F) -> T
    where
        F: FnMut() -> Option<T>,
    {
        Self::wait_while_sliced(&[condvar], predicate)
    }

    pub fn wait_while_sliced<F, T>(condvars: &[&Self], mut predicate: F) -> T
    where
        F: FnMut() -> Option<T>,
    {
        condvars.iter().for_each(|&cond| {
            cond.queue.lock();
        });

        let mut locks = Vec::with_capacity(condvars.len());
        loop {
            condvars.iter().for_each(|&condvar| {
                locks.push(condvar.queue.lock());
            });

            locks.clear();

            if let Some(res) = predicate() {
                let _ = FlagsGuard::no_irq_region();
                return res;
            } else {
                condvars.iter().for_each(|&condvar| {
                    condvar.queue.lock();
                });
            }
        }
    }

    pub fn register(&self, proc: Arc<Mutex<Process>>, id: u64, epfd: u64, fd: u64) {
        self.epoll
            .lock()
            .push_back(EpollInfo { proc, id, epfd, fd });
    }

    pub fn unregister(&self, id: u64, epfd: u64, fd: u64) -> bool {
        let mut epoll = self.epoll.lock();
        if let Some(idx) = epoll
            .iter()
            .position(|epoll| epoll.epfd == epfd && epoll.fd == fd && epoll.id == id)
        {
            epoll.remove(idx);
            true
        } else {
            false
        }
    }

    /// Mark as ready!
    fn call(&self, thread: &Arc<Thread>) {
        let q = self.epoll.lock();
        q.iter().for_each(|epoll| {
            let fd = epoll.fd;
            let mut proc = epoll.proc.lock();
            let epoll = proc.get_epoll(epoll.epfd).unwrap(); // `None` should panic here.
            epoll.add_ready(fd);
        });
    }
}
