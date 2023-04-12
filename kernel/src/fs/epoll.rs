//! Epoll instance related structs.

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};
use lazy_static::lazy_static;

use crate::{
    error::{Errno, KResult},
    process::thread::Thread,
    sync::mutex::SpinLockNoInterrupt as Mutex,
    sys::{EpollEvent, EpollOp},
};

lazy_static! {
    /// A queue used to store EPOLL requests.
    pub static ref EPOLL_QUEUE: EpollQueue = EpollQueue::new();
}

/// An epoll instance is an object created by a process to manage its set of file descriptors for event notification.
/// The process can register multiple file descriptors with the epoll instance using the epoll_ctl system call, and
/// specify which events it is interested in monitoring (such as read, write, or error events).
pub struct EpollInstance {
    /// fd -> events.
    pub(crate) events: Mutex<BTreeMap<u64, EpollEvent>>,
    /// Ready.
    pub(crate) ready: Mutex<BTreeSet<u64>>,
    /// Execute on close？
    pub(crate) epoll_cloexec: bool,
}

impl Clone for EpollInstance {
    fn clone(&self) -> Self {
        EpollInstance::new(false)
    }
}

impl EpollInstance {
    pub fn new(epoll_cloexec: bool) -> Self {
        Self {
            events: Mutex::new(BTreeMap::new()),
            ready: Mutex::new(BTreeSet::new()),
            epoll_cloexec,
        }
    }

    pub fn epoll_ctl(&mut self, fd: u64, op: EpollOp, event: EpollEvent) -> KResult<usize> {
        let mut events = self.events.lock();
        match op {
            EpollOp::EpollCtlAdd => {
                events.insert(fd, event);
            }
            EpollOp::EpollCtlDel => {
                events.remove(&fd);
            }
            EpollOp::EpollCtlMod => match events.get_mut(&fd) {
                Some(epoll_event) => {
                    *epoll_event = event;
                }
                None => return Err(Errno::EPERM),
            },
        }

        Ok(0)
    }

    #[inline]
    pub fn is_ready(&self, fd: u64) -> bool {
        self.ready.lock().contains(&fd)
    }

    #[inline]
    pub fn add_ready(&self, fd: u64) {
        self.ready.lock().insert(fd);
    }

    #[inline]
    pub fn ready_num(&self) -> usize {
        self.ready.lock().len()
    }

    #[inline]
    pub fn clear_ready(&self) {
        self.ready.lock().clear();
    }
}

/// A simple data structure that tracks the epoll status of a given thread.
pub struct EpollInfo {
    /// The waiting thread.
    pub(crate) thread: Arc<Thread>,
    /// The Epoll instance's file descriptor.
    pub(crate) epfd: u64,
    /// The target file descriptor of interest.
    pub(crate) fd: u64,
}

pub struct EpollQueue(Mutex<VecDeque<EpollInfo>>);

impl EpollQueue {
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Mutex::new(VecDeque::with_capacity(capacity)))
    }

    #[inline]
    pub const fn new() -> Self {
        Self(Mutex::new(VecDeque::new()))
    }

    #[inline]
    pub fn register_epoll_event(&self, thread: Arc<Thread>, epfd: u64, fd: u64) {
        self.0.lock().push_back(EpollInfo { thread, epfd, fd })
    }

    pub fn remove_epoll_event(&self, thread_id: u64, epfd: u64, fd: u64) -> Option<EpollInfo> {
        let mut queue = self.0.lock();
        match queue
            .iter()
            .position(|ei| ei.thread.id == thread_id && ei.epfd == epfd && ei.fd == fd)
        {
            Some(idx) => queue.remove(idx),
            None => None,
        }
    }
}
