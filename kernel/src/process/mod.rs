use crate::sync::mutex::SpinLockNoInterrupt as Mutex;
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use lazy_static::lazy_static;
use spin::RwLock;

pub mod thread;

pub type Pid = usize;

lazy_static! {
    pub static ref KERNEL_PROCESS_LIST: RwLock<BTreeMap<usize, Arc<Mutex<Process>>>> =
        RwLock::new(BTreeMap::new());
}

/// Implementation of the OS-level processes. Each process consists of several threads. See
/// kernel/process/thread.rs
pub struct Process {
    /// The process id.
    process_id: Pid,
    /// The thread lists.
    threads: Vec<usize>,
    // struct mm_struct		*mm;
    // struct mm_struct		*active_mm;
}
