use crate::{
    arch::mm::paging::KernelPageTable,
    error::{Errno, KResult},
    fs::file::FileObject,
    mm::MemoryManager,
    process::event::Event,
    sync::{futex::SimpleFutex, mutex::SpinLockNoInterrupt as Mutex},
};
use alloc::{
    collections::BTreeMap,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use lazy_static::lazy_static;
use log::info;
use spin::RwLock;

use event::EventBus;

use self::thread::THREAD_TABLE;

pub mod event;
pub mod ld;
pub mod scheduler;
pub mod thread;

lazy_static! {
    pub static ref KERNEL_PROCESS_LIST: RwLock<BTreeMap<u64, Arc<Mutex<Process>>>> =
        RwLock::new(BTreeMap::new());
}

/// Implementation of the OS-level processes. Each process consists of several threads. See
/// kernel/process/thread.rs
pub struct Process {
    /// The process id.
    pub process_id: u64,
    /// Process group id.
    pub process_group_id: u64,
    /// The thread lists.
    pub threads: Vec<u64>,
    /// struct mm_struct *mm; shared with threads.
    pub vm: Arc<Mutex<MemoryManager<KernelPageTable>>>,
    /// Current exeuction path.
    pub exec_path: String,
    /// Wording directory.
    pub pwd: String,
    /// Opened files.
    pub opened_files: BTreeMap<u64, FileObject>,
    /// Exit code.
    pub exit_code: u64,
    /// Events like exiting
    pub event_bus: Arc<Mutex<EventBus>>,
    pub futexes: BTreeMap<u64, Arc<SimpleFutex>>,
    /// Avoid deadlock, put pid out
    /// can be self-referenced.
    pub parent: (u64, Weak<Mutex<Process>>),
    /// Children process
    pub children: Vec<(u64, Weak<Mutex<Process>>)>,
}

impl Process {
    pub fn exited(&self) -> bool {
        self.threads.is_empty()
    }

    fn get_free_fd(&self) -> KResult<u64> {
        (0..)
            .find(|i| !self.opened_files.contains_key(i))
            .ok_or(Errno::EEXIST)
    }

    fn add_file(&mut self, file: FileObject) -> KResult<u64> {
        let fd = self.get_free_fd()?;
        self.opened_files.insert(fd, file);
        Ok(fd)
    }

    pub fn exit(&mut self, exit_code: u64) {
        // TODO:make the process exit
        // First, get all file descriptors for the process and release them
        // Second, set event bus to PROCESS_QUIT
        // Third, remove all threads

        info!("process {} exit with {}", self.process_id, self.exit_code);
    }
}

pub fn register(process: Arc<Mutex<Process>>, id: u64) {
    let mut table = KERNEL_PROCESS_LIST.write();
    process.lock().process_id = id;
    table.insert(id, process);
}

pub fn search_by_id(id: u64) -> KResult<Arc<Mutex<Process>>> {
    let table = KERNEL_PROCESS_LIST.read();
    table
        .iter()
        .find(|item| item.1.lock().process_id == id)
        .map(|(_, item)| item.clone())
        .ok_or(Errno::EEXIST)
}

pub fn search_by_group_id(id: u64) -> Vec<Arc<Mutex<Process>>> {
    let table = KERNEL_PROCESS_LIST.read();
    table
        .iter()
        .filter(|item| item.1.lock().process_group_id == id)
        .map(|(_, item)| item.clone())
        .collect::<Vec<_>>()
}

pub fn search_by_thread(id: u64) -> KResult<Arc<Mutex<Process>>> {
    let mut table = KERNEL_PROCESS_LIST.read();
    table
        .iter()
        .find(|(_, item)| item.lock().threads.contains(&id))
        .map(|(_, item)| item.clone())
        .ok_or(Errno::EEXIST)
}
