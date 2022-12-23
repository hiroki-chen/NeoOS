use crate::{
    arch::mm::paging::KernelPageTable, fs::file::FileObject, mm::MemoryManager,
    sync::mutex::SpinLockNoInterrupt as Mutex,
};
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use lazy_static::lazy_static;
use spin::RwLock;

pub mod thread;

lazy_static! {
    pub static ref KERNEL_PROCESS_LIST: RwLock<BTreeMap<usize, Arc<Mutex<Process>>>> =
        RwLock::new(BTreeMap::new());
}

/// Implementation of the OS-level processes. Each process consists of several threads. See
/// kernel/process/thread.rs
pub struct Process {
    /// The process id.
    pub process_id: u64,
    /// The thread lists.
    pub threads: Vec<u64>,
    /// struct mm_struct		*mm; shared with threads.
    pub vm: Arc<Mutex<MemoryManager<KernelPageTable>>>,
    /// Current exeuction path.
    pub exec_path: String,
    /// Wording directory.
    pub pwd: String,
    /// Opened files.
    pub opened_files: BTreeMap<usize, FileObject>,
}
