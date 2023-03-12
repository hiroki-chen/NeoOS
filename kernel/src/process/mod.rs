use core::{future::Future, task::Poll};

use crate::{
    arch::mm::paging::KernelPageTable,
    error::{Errno, KResult},
    fs::file::FileObject,
    mm::MemoryManager,
    process::event::Event,
    signal::{SigAction, SigInfo, SigSet},
    sync::{futex::SimpleFutex, mutex::SpinLockNoInterrupt as Mutex},
};
use alloc::{
    collections::{BTreeMap, VecDeque},
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

#[derive(Default)]
pub struct Yield(bool);

impl Future for Yield {
    type Output = ();

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        match self.0 {
            true => Poll::Ready(()),
            false => {
                self.0 = true;
                // Wake me.
                cx.waker().clone().wake();
                Poll::Pending
            }
        }
    }
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
    pub exit_code: u8,
    /// Events like exiting
    pub event_bus: Arc<Mutex<EventBus>>,
    pub futexes: BTreeMap<u64, Arc<SimpleFutex>>,
    /// Avoid deadlock, put pid out
    /// can be self-referenced.
    pub parent: (u64, Weak<Mutex<Process>>),
    /// Children process
    pub children: Vec<(u64, Weak<Mutex<Process>>)>,
    /// Pending signals.
    pub pending_sigset: SigSet,
    /// Signal queue.
    pub sig_queue: VecDeque<(SigInfo, i64)>,
    /// Signal actions.
    pub actions: [SigAction; 0x41],
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

    pub fn exit(&mut self, exit_code: u8) {
        let all_fd = self.opened_files.keys().copied().collect::<Vec<u64>>();
        for fd in all_fd.iter() {
            let file = self.opened_files.remove(fd).unwrap();
            drop(file);
        }

        self.event_bus.lock().set(Event::PROCESS_QUIT);
        if let Some(parent) = self.parent.1.upgrade() {
            parent
                .lock()
                .event_bus
                .lock()
                .set(Event::CHILD_PROCESS_QUIT);
        }
        self.exit_code = exit_code;

        let mut table = THREAD_TABLE.write();
        for thread in self.threads.iter() {
            table.remove(thread);
        }
        self.threads.clear();

        info!("process {} exit with {}", self.process_id, self.exit_code);
    }
}

pub fn register(process: &Arc<Mutex<Process>>, id: u64) {
    let mut table = KERNEL_PROCESS_LIST.write();
    process.lock().process_id = id;
    table.insert(id, process.clone());
}

pub fn search_by_id(id: u64) -> KResult<Arc<Mutex<Process>>> {
    KERNEL_PROCESS_LIST
        .read()
        .iter()
        .find(|item| item.1.lock().process_id == id)
        .map(|(_, item)| item.clone())
        .ok_or(Errno::EEXIST)
}

pub fn search_by_group_id(id: u64) -> Vec<Arc<Mutex<Process>>> {
    KERNEL_PROCESS_LIST
        .read()
        .iter()
        .filter(|item| item.1.lock().process_group_id == id)
        .map(|(_, item)| item.clone())
        .collect::<Vec<_>>()
}

pub fn search_by_thread(id: u64) -> KResult<Arc<Mutex<Process>>> {
    KERNEL_PROCESS_LIST
        .read()
        .iter()
        .find(|(_, item)| item.lock().threads.contains(&id))
        .map(|(_, item)| item.clone())
        .ok_or(Errno::EEXIST)
}
