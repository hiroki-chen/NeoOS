//!  An executing program consists of a collection of native OS threads, each with their
//! own stack and local state. Threads can be named, and provide some built-in support for
//! low-level synchronization.
//!
//! Communication between threads can be done through signals, shared memory, along with
//! other forms of thread synchronization and shared-memory data structures. In particular,
//! types that are guaranteed to be threadsafe are easily shared between threads using the
//! atomically-reference-counted container, Arc.

use alloc::sync::Arc;

use crate::{
    arch::mm::paging::KernelPageTable, mm::MemoryManager, sync::mutex::SpinLockNoInterrupt as Mutex,
};

use super::Process;

/// Describes a thread.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreadState {
    /// The thread is currently being executed by the processor.
    RUNNING,
    /// The thread is waiting for a resource or event to become available.
    WAITING,
    /// The thread is sleeping for a specified amount of time.
    SLEEPING,
    /// The thread has been stopped by a signal or other external event.
    STOPPED,
    /// The thread has terminated but its parent process has not yet waited on it.
    ZOMBIE,
}

pub struct Thread {
    /// The thread id.
    pub id: u64,
    /// The parent process.
    pub parent: Arc<Mutex<Process>>,
    /// The inner thread context.
    pub inner: Arc<Mutex<ThreadInner>>,
    /// Proc.vm
    pub vm: Arc<Mutex<MemoryManager<KernelPageTable>>>,
}

pub struct ThreadInner {
    state: ThreadState,
}
