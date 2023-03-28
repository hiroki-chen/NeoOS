//! Epoll instance related structs.

use alloc::collections::{BTreeMap, BTreeSet};

use crate::{sync::mutex::SpinLockNoInterrupt as Mutex, sys::EpollEvent};

///  An epoll instance is an object created by a process to manage its set of file descriptors for event notification.
/// The process can register multiple file descriptors with the epoll instance using the epoll_ctl system call, and
/// specify which events it is interested in monitoring (such as read, write, or error events).
pub struct EpollInstance {
    /// Process id -> event.
    events: BTreeMap<u64, EpollEvent>,
    /// Ready.
    ready: Mutex<BTreeSet<u64>>,
}

impl EpollInstance {
    pub fn new() -> Self {
        Self {
            events: BTreeMap::new(),
            ready: Mutex::new(BTreeSet::new()),
        }
    }

    #[inline]
    pub fn is_ready(&self, fd: u64) -> bool {
        self.ready.lock().contains(&fd)
    }

    #[inline]
    pub fn add_ready(&mut self, fd: u64) {
        self.ready.lock().insert(fd);
    }

    #[inline]
    pub fn ready_num(&self) -> usize {
        self.ready.lock().len()
    }
}
